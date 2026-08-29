package com.cyberscope;

import com.cyberscope.model.Host;
import com.cyberscope.model.Port;
import com.cyberscope.model.ScanType;
import com.cyberscope.model.VulnAssessment;
import com.cyberscope.repository.CveFeedLoader;
import com.cyberscope.repository.CveIndexManager;
import com.cyberscope.repository.CveRepository;
import com.cyberscope.repository.DatabaseManager;
import com.cyberscope.repository.IndexMetadata;
import com.cyberscope.repository.RepositoryException;
import com.cyberscope.repository.ScanRepository;
import com.cyberscope.repository.ScanSummary;
import com.cyberscope.service.compare.ScanComparator;
import com.cyberscope.service.report.ScanDiffFormatter;
import com.cyberscope.service.report.ScanReportFormatter;
import com.cyberscope.service.report.VulnReportFormatter;
import com.cyberscope.service.scanner.NmapDetector;
import com.cyberscope.service.scanner.NmapExecutionException;
import com.cyberscope.service.scanner.NmapExecutor;
import com.cyberscope.service.scanner.NmapNotFoundException;
import com.cyberscope.service.scanner.NmapRunResult;
import com.cyberscope.service.scanner.NmapXmlParser;
import com.cyberscope.service.scanner.ScanOutcome;
import com.cyberscope.service.scanner.XmlParseException;
import com.cyberscope.service.vuln.VulnerabilityService;
import com.cyberscope.util.InvalidTargetException;
import com.cyberscope.util.TargetValidator;
import com.cyberscope.util.ValidatedTarget;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;


/** Command-line entry point for CyberScope. */
public final class App {

    /**
     * Read from the build, not typed here.
     *
     * <p>Kept as a field so every existing reference still compiles, but it is
     * now derived rather than declared -- see {@link BuildInfo} for why.
     */
    public static final String VERSION = BuildInfo.version();

    private static final ScanType DEFAULT_SCAN = ScanType.QUICK;
    private static final int DEFAULT_HISTORY_LIMIT = 20;

    private static final DateTimeFormatter HISTORY_TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    static final int EXIT_OK = 0;
    static final int EXIT_DEPENDENCY_MISSING = 2;
    static final int EXIT_INVALID_TARGET = 3;
    static final int EXIT_SCAN_FAILED = 4;
    static final int EXIT_DATABASE_ERROR = 5;

    /** What the invocation asked for. Exactly one applies. */
    private enum Mode {
        SCAN,
        HISTORY,
        SHOW,
        DELETE,
        DIFF,
        COMPARE,
        UPDATE_CVE_INDEX,
        CVE_INDEX_STATUS
    }

    private App() {
    }

    public static void main(String[] args) {
        System.exit(run(args));
    }

    static int run(String[] args) {
        boolean assumeAuthorised = false;
        boolean endOfOptions = false;
        boolean save = true;
        Mode mode = Mode.SCAN;
        ScanType scanType = DEFAULT_SCAN;
        int limit = DEFAULT_HISTORY_LIMIT;
        long targetId = -1;
        long secondId = -1;
        String compareTarget = null;

        Path cveIndexPath = CveIndexManager.defaultLocation();
        boolean verboseVulns = false;

        Path databasePath = DatabaseManager.defaultLocation();
        List<String> targets = new ArrayList<>();

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];

            if (endOfOptions) {
                targets.add(arg);
                continue;
            }

            switch (arg) {
                case "--" -> endOfOptions = true;

                case "--yes", "-y" -> assumeAuthorised = true;

                case "--no-save" -> save = false;

                case "--history" -> mode = Mode.HISTORY;

                case "--vulns" -> verboseVulns = true;

                case "--update-cve-index" -> mode = Mode.UPDATE_CVE_INDEX;

                case "--cve-index-status" -> mode = Mode.CVE_INDEX_STATUS;

                case "--cve-index" -> {
                    if (i + 1 >= args.length) {
                        System.err.println("[!!] --cve-index requires a path");
                        return EXIT_INVALID_TARGET;
                    }
                    cveIndexPath = Path.of(args[++i]);
                }

                case "--help", "-h" -> {
                    printUsage();
                    return EXIT_OK;
                }

                case "--version", "-V" -> {
                    System.out.println("CyberScope " + VERSION);
                    return EXIT_OK;
                }

                case "--scan-type", "-s" -> {
                    if (i + 1 >= args.length) {
                        System.err.println("[!!] --scan-type requires a value ("
                                + ScanType.cliNames() + ")");
                        return EXIT_INVALID_TARGET;
                    }

                    String value = args[++i];
                    scanType = ScanType.fromCliName(value);

                    if (scanType == null) {
                        System.err.println("[!!] Unknown scan type '" + value
                                + "'. Choose one of: " + ScanType.cliNames());
                        return EXIT_INVALID_TARGET;
                    }
                }

                case "--show" -> {
                    if (i + 1 >= args.length) {
                        System.err.println("[!!] --show requires a scan id");
                        return EXIT_INVALID_TARGET;
                    }

                    targetId = parseId(args[++i]);

                    if (targetId < 0) {
                        return EXIT_INVALID_TARGET;
                    }

                    mode = Mode.SHOW;
                }

                case "--delete" -> {
                    if (i + 1 >= args.length) {
                        System.err.println("[!!] --delete requires a scan id");
                        return EXIT_INVALID_TARGET;
                    }

                    targetId = parseId(args[++i]);

                    if (targetId < 0) {
                        return EXIT_INVALID_TARGET;
                    }

                    mode = Mode.DELETE;
                }

                case "--limit", "-n" -> {
                    if (i + 1 >= args.length) {
                        System.err.println("[!!] --limit requires a number");
                        return EXIT_INVALID_TARGET;
                    }

                    long parsed = parseId(args[++i]);

                    if (parsed < 1 || parsed > 1000) {
                        System.err.println("[!!] --limit must be between 1 and 1000");
                        return EXIT_INVALID_TARGET;
                    }

                    limit = (int) parsed;
                }

                case "--diff" -> {
                    if (i + 2 >= args.length) {
                        System.err.println("[!!] --diff requires two scan ids,"
                                + " e.g. --diff 3 7");
                        return EXIT_INVALID_TARGET;
                    }

                    targetId = parseId(args[++i]);
                    secondId = parseId(args[++i]);

                    if (targetId < 0 || secondId < 0) {
                        return EXIT_INVALID_TARGET;
                    }

                    mode = Mode.DIFF;
                }

                case "--compare" -> {
                    if (i + 1 >= args.length) {
                        System.err.println("[!!] --compare requires a target");
                        return EXIT_INVALID_TARGET;
                    }

                    compareTarget = args[++i];
                    mode = Mode.COMPARE;
                }

                case "--db" -> {
                    if (i + 1 >= args.length) {
                        System.err.println("[!!] --db requires a path");
                        return EXIT_INVALID_TARGET;
                    }

                    databasePath = Path.of(args[++i]);
                }

                default -> {
                    if (arg.startsWith("-")) {
                        System.err.println("[!!] Unknown option: " + arg);
                        printUsage();
                        return EXIT_INVALID_TARGET;
                    }

                    targets.add(arg);
                }
            }
        }

        banner();

        return switch (mode) {
            case HISTORY ->
                    listHistory(databasePath, limit);

            case SHOW ->
                    showScan(databasePath, targetId);

            case DELETE ->
                    deleteScan(databasePath, targetId);

            case DIFF ->
                    diffScans(databasePath, targetId, secondId);

            case COMPARE ->
                    compareTarget(databasePath, compareTarget);

            case UPDATE_CVE_INDEX ->
                    updateCveIndex(cveIndexPath);

            case CVE_INDEX_STATUS ->
                    cveIndexStatus(cveIndexPath);

            case SCAN ->
                    scan(
                            targets,
                            scanType,
                            assumeAuthorised,
                            save,
                            databasePath,
                            cveIndexPath,
                            verboseVulns
                    );
        };
    }

    // -------------------------------------------------------------------- scan

    private static int scan(
            List<String> targets,
            ScanType scanType,
            boolean assumeAuthorised,
            boolean save,
            Path databasePath,
            Path cveIndexPath,
            boolean verboseVulns) {

        if (targets.isEmpty()) {
            printUsage();
            return EXIT_OK;
        }

        if (targets.size() > 1) {
            System.err.println("[!!] Exactly one target expected; got " + targets.size()
                    + ": " + targets);
            return EXIT_INVALID_TARGET;
        }

        ValidatedTarget target;

        try {
            target = TargetValidator.validate(targets.get(0));
        } catch (InvalidTargetException e) {
            System.err.println("[!!] " + e.getMessage());
            return EXIT_INVALID_TARGET;
        }

        try {
            System.out.println("[ok] Nmap " + NmapDetector.detectVersion() + " detected");
        } catch (NmapNotFoundException e) {
            System.err.println("[!!] " + e.getMessage());
            return EXIT_DEPENDENCY_MISSING;
        }

        if (!assumeAuthorised && !confirmAuthorisation(target)) {
            System.out.println("Scan cancelled.");
            return EXIT_OK;
        }

        System.out.println("[..] Scanning " + target.value()
                + " (" + scanType.displayName() + ") ...");

        if (target.isRange()) {
            System.out.printf(
                    "     Timeout budget: %d s for %d addresses%n",
                    scanType.timeoutFor(target.addressCount()).toSeconds(),
                    target.addressCount()
            );
        }

        System.out.println();

        ScanOutcome outcome;

        try {
            NmapRunResult run = NmapExecutor.execute(scanType, target);
            List<Host> hosts = NmapXmlParser.parse(run.xml());

            outcome = new ScanOutcome(run, hosts);

            System.out.print(
                    ScanReportFormatter.format(
                            run,
                            hosts,
                            ZoneId.systemDefault()
                    )
            );

            /*
             * Vulnerability assessment is deliberately performed after the
             * normal scan report. The scan itself has already succeeded, so
             * CVE-index problems do not turn a successful scan into a failed
             * scan.
             */
            System.out.print(
                    assessVulnerabilities(
                            hosts,
                            cveIndexPath,
                            verboseVulns
                    )
            );

        } catch (NmapExecutionException | XmlParseException e) {
            System.err.println("[!!] " + e.getMessage());
            return EXIT_SCAN_FAILED;
        }

        // The scan already succeeded and its report is already on screen.
        // A storage failure after that point is worth reporting, but it is
        // not worth turning a successful scan into a non-zero exit.
        if (save) {
            try {
                long id = openRepository(databasePath).save(outcome);

                System.out.println();
                System.out.println(
                        "[ok] Saved as scan #" + id
                                + "   (cyberscope --show " + id + ")"
                );

            } catch (RepositoryException e) {
                System.err.println();
                System.err.println(
                        "[!] Results were NOT saved: " + e.getMessage()
                );
            }
        }

        return EXIT_OK;
    }

    /**
     * Assesses every host and renders the vulnerability section.
     *
     * <p>Never throws and never returns an empty string. If the index is missing
     * or unreadable the section says so -- because the alternative is printing
     * nothing, and a scan report that silently omits the vulnerability section
     * reads exactly like a scan report with no vulnerabilities.
     */
    private static String assessVulnerabilities(
            List<Host> hosts,
            Path cveIndexPath,
            boolean verbose) {

        CveRepository repository = null;
        IndexMetadata metadata = null;

        try {
            CveIndexManager manager = new CveIndexManager(cveIndexPath);
            repository = new CveRepository(manager);
            metadata = repository.metadata().orElse(null);

        } catch (RepositoryException e) {
            System.err.println(
                    "[!] CVE index unavailable: " + e.getMessage()
            );
        }

        VulnerabilityService service =
                new VulnerabilityService(repository);

        StringBuilder out = new StringBuilder();

        for (Host host : hosts) {
            Map<Port, VulnAssessment> assessed =
                    service.assess(host);

            if (assessed.isEmpty() && hosts.size() > 1) {
                continue;
            }

            if (hosts.size() > 1) {
                out.append('\n')
                        .append(" ")
                        .append(host.ipAddress())
                        .append('\n');
            }

            out.append(
                    VulnReportFormatter.format(
                            assessed,
                            metadata,
                            Instant.now(),
                            ZoneId.systemDefault(),
                            verbose
                    )
            );
        }

        return out.toString();
    }

    /** Builds or refreshes the local CVE index. */
    private static int updateCveIndex(Path cveIndexPath) {

        System.out.println(
                "[..] Refreshing the CVE index at " + cveIndexPath
        );

        System.out.println(
                "     About 100 MB of downloads and roughly a minute."
        );

        System.out.println();

        try {
            CveIndexManager manager =
                    new CveIndexManager(cveIndexPath);

            long started = System.nanoTime();

            CveFeedLoader.Result result =
                    new CveFeedLoader(manager).refresh(
                            (stage, done, total) ->
                                    System.out.printf(
                                            "\r     %-34s %2d/%d",
                                            stage,
                                            done,
                                            total
                                    )
                    );

            System.out.println();
            System.out.println();

            System.out.printf(
                    "[ok] %,d CVEs and %,d applicability statements, %d-%d%n",
                    result.cveCount(),
                    result.matchCount(),
                    result.firstYear(),
                    result.lastYear()
            );

            System.out.printf(
                    "     %.1f MB downloaded, %.1f MB on disk, %.0f s%n",
                    result.bytesDownloaded() / 1048576.0,
                    manager.sizeOnDisk() / 1048576.0,
                    (System.nanoTime() - started) / 1e9
            );

            return EXIT_OK;

        } catch (InterruptedException e) {

            Thread.currentThread().interrupt();

            System.err.println();
            System.err.println(
                    "[!] Cancelled. The previous index is untouched."
            );

            return EXIT_OK;

        } catch (RepositoryException e) {

            System.err.println();
            System.err.println("[!!] " + e.getMessage());

            return EXIT_DATABASE_ERROR;
        }
    }

    /** Prints what the index holds and how old it is. */
    private static int cveIndexStatus(Path cveIndexPath) {

        try {
            CveIndexManager manager =
                    new CveIndexManager(cveIndexPath);

            CveRepository repository =
                    new CveRepository(manager);

            IndexMetadata metadata =
                    repository.metadata().orElse(null);

            System.out.println("CVE index: " + cveIndexPath);

            if (metadata == null) {
                System.out.println(
                        "  Not built yet. Run --update-cve-index."
                );
                return EXIT_OK;
            }

            System.out.println(
                    "  " + metadata.describe(
                            Instant.now(),
                            ZoneId.systemDefault()
                    )
            );

            System.out.printf(
                    "  %,d applicability statements across %,d products%n",
                    metadata.matchCount(),
                    repository.productCount()
            );

            System.out.printf(
                    "  %.1f MB on disk%n",
                    manager.sizeOnDisk() / 1048576.0
            );

            System.out.println(
                    "  Source: " + metadata.source()
            );

            return EXIT_OK;

        } catch (RepositoryException e) {

            System.err.println("[!!] " + e.getMessage());
            return EXIT_DATABASE_ERROR;
        }
    }

    // ----------------------------------------------------------------- history

    private static int listHistory(
            Path databasePath,
            int limit) {

        try {
            List<ScanSummary> recent =
                    openRepository(databasePath).listRecent(limit);

            if (recent.isEmpty()) {
                System.out.println("No scans saved yet.");
                return EXIT_OK;
            }

            System.out.printf(
                    "%-5s  %-16s  %-20s  %-9s  %8s  %s%n",
                    "ID",
                    "STARTED",
                    "TARGET",
                    "TYPE",
                    "DURATION",
                    "RESULT"
            );

            System.out.println("-".repeat(90));

            for (ScanSummary s : recent) {
                System.out.printf(
                        "%-5d  %-16s  %-20s  %-9s  %7.1fs  %d %s, %d open%n",
                        s.id(),
                        HISTORY_TIME.format(
                                s.startedAt().atZone(
                                        ZoneId.systemDefault()
                                )
                        ),
                        s.target(),
                        s.scanType().displayName(),
                        s.elapsed().toMillis() / 1000.0,
                        s.hostCount(),
                        s.hostCount() == 1 ? "host" : "hosts",
                        s.openPortCount()
                );
            }

            System.out.println();

            System.out.println(
                    recent.size()
                            + " scan(s) shown.  Use --show <id> for the full report."
            );

            return EXIT_OK;

        } catch (RepositoryException e) {

            System.err.println("[!!] " + e.getMessage());
            return EXIT_DATABASE_ERROR;
        }
    }

    private static int showScan(
            Path databasePath,
            long id) {

        try {
            Optional<ScanOutcome> found =
                    openRepository(databasePath).load(id);

            if (found.isEmpty()) {
                System.err.println(
                        "[!!] No scan with id " + id
                                + ". Run --history to list what is stored."
                );

                return EXIT_INVALID_TARGET;
            }

            ScanOutcome outcome = found.get();

            System.out.print(
                    ScanReportFormatter.format(
                            outcome.run(),
                            outcome.hosts(),
                            ZoneId.systemDefault()
                    )
            );

            return EXIT_OK;

        } catch (RepositoryException e) {

            System.err.println("[!!] " + e.getMessage());
            return EXIT_DATABASE_ERROR;
        }
    }

    private static int deleteScan(
            Path databasePath,
            long id) {

        try {
            if (openRepository(databasePath).delete(id)) {

                System.out.println(
                        "[ok] Deleted scan #" + id
                                + " and every host and port recorded under it."
                );

                return EXIT_OK;
            }

            System.err.println(
                    "[!!] No scan with id " + id + "."
            );

            return EXIT_INVALID_TARGET;

        } catch (RepositoryException e) {

            System.err.println("[!!] " + e.getMessage());
            return EXIT_DATABASE_ERROR;
        }
    }

    // -------------------------------------------------------------------- diff

    /** Compares two scans named by id, in either order. */
    private static int diffScans(
            Path databasePath,
            long firstId,
            long secondId) {

        try {
            ScanRepository repository =
                    openRepository(databasePath);

            Optional<ScanOutcome> first =
                    repository.load(firstId);

            Optional<ScanOutcome> second =
                    repository.load(secondId);

            if (first.isEmpty() || second.isEmpty()) {

                System.err.println(
                        "[!!] No scan with id "
                                + (first.isEmpty() ? firstId : secondId)
                                + ". Run --history to list what is stored."
                );

                return EXIT_INVALID_TARGET;
            }

            if (firstId == secondId) {

                System.err.println(
                        "[!!] Both ids are " + firstId
                                + "; a scan cannot be compared with itself."
                );

                return EXIT_INVALID_TARGET;
            }

            System.out.print(
                    ScanDiffFormatter.format(
                            ScanComparator.compare(
                                    first.get(),
                                    second.get()
                            ),
                            ZoneId.systemDefault()
                    )
            );

            return EXIT_OK;

        } catch (RepositoryException e) {

            System.err.println("[!!] " + e.getMessage());
            return EXIT_DATABASE_ERROR;
        }
    }

    /**
     * Compares the two most recent scans of one target.
     *
     * <p>The common case by a distance -- "what changed since last time?" -- and
     * the reason {@code findByTarget} and its index exist. Matches on the target
     * string exactly as it was stored, because that is as far as the database
     * can go; whether the two scans reached the same machine is the comparator's
     * question, not this one's.
     */
    private static int compareTarget(
            Path databasePath,
            String target) {

        try {
            ScanRepository repository =
                    openRepository(databasePath);

            List<ScanSummary> recent =
                    repository.findByTarget(target, 2);

            if (recent.size() < 2) {

                System.err.println(
                        "[!!] Need two scans of " + target
                                + " to compare; found "
                                + recent.size()
                                + ". Scan it again, or use --history to see"
                                + " what is stored."
                );

                return EXIT_INVALID_TARGET;
            }

            // findByTarget returns newest first.
            ScanOutcome newer =
                    repository.load(recent.get(0).id()).orElseThrow();

            ScanOutcome older =
                    repository.load(recent.get(1).id()).orElseThrow();

            System.out.println(
                    "[..] Comparing scan #" + recent.get(1).id()
                            + " with scan #" + recent.get(0).id()
            );

            System.out.println();

            System.out.print(
                    ScanDiffFormatter.format(
                            ScanComparator.compare(
                                    older,
                                    newer
                            ),
                            ZoneId.systemDefault()
                    )
            );

            return EXIT_OK;

        } catch (RepositoryException e) {

            System.err.println("[!!] " + e.getMessage());
            return EXIT_DATABASE_ERROR;
        }
    }

    // ---------------------------------------------------------------- repository

    private static ScanRepository openRepository(
            Path databasePath) throws RepositoryException {

        return new ScanRepository(
                new DatabaseManager(databasePath)
        );
    }

    /** Returns -1 and prints a message rather than throwing on bad input. */
    private static long parseId(String raw) {

        try {
            return Long.parseLong(raw.trim());

        } catch (NumberFormatException e) {

            System.err.println(
                    "[!!] '" + raw + "' is not a number"
            );

            return -1;
        }
    }

    // ------------------------------------------------------------------- text

    private static void banner() {

        System.out.println(
                "CyberScope v" + VERSION
                        + " - authorised targets only, see SCOPE.md"
        );

        System.out.println();
    }

    private static void printUsage() {

        System.out.println("""
                Usage: cyberscope [options] <target>
                       cyberscope --history [--limit n]
                       cyberscope --show <id>
                       cyberscope --delete <id>
                       cyberscope --diff <id> <id>
                       cyberscope --compare <target>
                       cyberscope --update-cve-index
                       cyberscope --cve-index-status

                  <target>          an IPv4 address, a hostname, or a CIDR range
                                    (up to /24) you are authorised to scan

                Scan options:
                  -s, --scan-type   quick (default) or standard
                  -y, --yes         skip the interactive authorisation prompt
                      --no-save     do not record this scan in the history

                Vulnerability mapping:
                      --vulns       list every CVE rather than the top few per port
                      --update-cve-index   download and rebuild the local CVE index
                                         (~100 MB, about a minute)
                      --cve-index-status   show what the index holds and how old it is
                      --cve-index <path>   use a different index file
                                         (default ~/.cyberscope/cve-index.db)

                Comparison:
                      --diff        compare two stored scans by id
                      --compare     compare the two most recent scans of a target

                History options:
                  -n, --limit       how many rows --history shows (default 20)
                      --db <path>   use a different database file
                                    (default ~/.cyberscope/cyberscope.db)

                Other:
                  -h, --help        show this help
                  -V, --version     show the version

                Exit codes:
                  0  success
                  2  Nmap not installed
                  3  invalid target, argument, or unknown scan id
                  4  scan or parse failed
                  5  database error

                Saved scans record target addresses, service versions, and CPEs.
                The database is created mode 0600 inside a 0700 directory. Remove one
                scan with --delete <id>, or all of them by deleting the file at
                ~/.cyberscope/cyberscope.db.

                The CVE index is a local copy of public NVD data. It contains nothing
                about your network, can be deleted at any time, and is rebuilt by
                --update-cve-index. A service CyberScope could not look up is reported
                as such -- it is never reported as having no vulnerabilities.
                """);
    }

    private static boolean confirmAuthorisation(
            ValidatedTarget target) {

        System.out.println();

        System.out.println(
                "  Active scanning is lawful only against systems you own or"
        );

        System.out.println(
                "  have explicit written permission to test."
        );

        if (target.isRange()) {
            System.out.println(
                    "  This will scan "
                            + target.addressCount()
                            + " addresses."
            );
        }

        System.out.print(
                "  Type 'yes' to confirm you are authorised to scan "
                        + target.value()
                        + ": "
        );

        try {
            BufferedReader in =
                    new BufferedReader(
                            new InputStreamReader(System.in)
                    );

            String answer = in.readLine();

            System.out.println();

            return answer != null
                    && answer.trim().equalsIgnoreCase("yes");

        } catch (IOException e) {
            return false;
        }
    }
}