package com.cyberscope;

import com.cyberscope.model.Host;
import com.cyberscope.model.ScanType;
import com.cyberscope.repository.DatabaseManager;
import com.cyberscope.repository.RepositoryException;
import com.cyberscope.repository.ScanRepository;
import com.cyberscope.repository.ScanSummary;
import com.cyberscope.service.report.ScanReportFormatter;
import com.cyberscope.service.scanner.NmapDetector;
import com.cyberscope.service.scanner.NmapExecutionException;
import com.cyberscope.service.scanner.NmapExecutor;
import com.cyberscope.service.scanner.NmapNotFoundException;
import com.cyberscope.service.scanner.NmapRunResult;
import com.cyberscope.service.scanner.NmapXmlParser;
import com.cyberscope.service.scanner.ScanOutcome;
import com.cyberscope.service.scanner.XmlParseException;
import com.cyberscope.util.InvalidTargetException;
import com.cyberscope.util.TargetValidator;
import com.cyberscope.util.ValidatedTarget;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Command-line entry point for CyberScope. */
public final class App {

    public static final String VERSION = "0.3.0";

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
    private enum Mode { SCAN, HISTORY, SHOW, DELETE }

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
            case HISTORY -> listHistory(databasePath, limit);
            case SHOW    -> showScan(databasePath, targetId);
            case DELETE  -> deleteScan(databasePath, targetId);
            case SCAN    -> scan(targets, scanType, assumeAuthorised, save, databasePath);
        };
    }

    // -------------------------------------------------------------------- scan

    private static int scan(List<String> targets, ScanType scanType,
                            boolean assumeAuthorised, boolean save, Path databasePath) {
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
            System.out.printf("     Timeout budget: %d s for %d addresses%n",
                    scanType.timeoutFor(target.addressCount()).toSeconds(),
                    target.addressCount());
        }
        System.out.println();

        ScanOutcome outcome;
        try {
            NmapRunResult run = NmapExecutor.execute(scanType, target);
            List<Host> hosts = NmapXmlParser.parse(run.xml());
            outcome = new ScanOutcome(run, hosts);
            System.out.print(ScanReportFormatter.format(run, hosts, ZoneId.systemDefault()));
        } catch (NmapExecutionException | XmlParseException e) {
            System.err.println("[!!] " + e.getMessage());
            return EXIT_SCAN_FAILED;
        }

        // The scan already succeeded and its report is already on screen. A storage
        // failure after that point is worth reporting, but it is not worth turning a
        // successful scan into a non-zero exit: a script checking $? should not be
        // told the scan failed when it did not.
        if (save) {
            try {
                long id = openRepository(databasePath).save(outcome);
                System.out.println();
                System.out.println("[ok] Saved as scan #" + id
                                 + "   (cyberscope --show " + id + ")");
            } catch (RepositoryException e) {
                System.err.println();
                System.err.println("[!] Results were NOT saved: " + e.getMessage());
            }
        }
        return EXIT_OK;
    }

    // ----------------------------------------------------------------- history

    private static int listHistory(Path databasePath, int limit) {
        try {
            List<ScanSummary> recent = openRepository(databasePath).listRecent(limit);
            if (recent.isEmpty()) {
                System.out.println("No scans saved yet.");
                return EXIT_OK;
            }
            System.out.printf("%-5s  %-16s  %-20s  %-9s  %8s  %s%n",
                    "ID", "STARTED", "TARGET", "TYPE", "DURATION", "RESULT");
            System.out.println("-".repeat(90));
            for (ScanSummary s : recent) {
                System.out.printf("%-5d  %-16s  %-20s  %-9s  %7.1fs  %d %s, %d open%n",
                        s.id(),
                        HISTORY_TIME.format(s.startedAt().atZone(ZoneId.systemDefault())),
                        s.target(),
                        s.scanType().displayName(),
                        s.elapsed().toMillis() / 1000.0,
                        s.hostCount(), s.hostCount() == 1 ? "host" : "hosts",
                        s.openPortCount());
            }
            System.out.println();
            System.out.println(recent.size()
                    + " scan(s) shown.  Use --show <id> for the full report.");
            return EXIT_OK;
        } catch (RepositoryException e) {
            System.err.println("[!!] " + e.getMessage());
            return EXIT_DATABASE_ERROR;
        }
    }

    private static int showScan(Path databasePath, long id) {
        try {
            Optional<ScanOutcome> found = openRepository(databasePath).load(id);
            if (found.isEmpty()) {
                System.err.println("[!!] No scan with id " + id
                                 + ". Run --history to list what is stored.");
                return EXIT_INVALID_TARGET;
            }
            ScanOutcome outcome = found.get();
            System.out.print(ScanReportFormatter.format(
                    outcome.run(), outcome.hosts(), ZoneId.systemDefault()));
            return EXIT_OK;
        } catch (RepositoryException e) {
            System.err.println("[!!] " + e.getMessage());
            return EXIT_DATABASE_ERROR;
        }
    }

    private static int deleteScan(Path databasePath, long id) {
        try {
            if (openRepository(databasePath).delete(id)) {
                System.out.println("[ok] Deleted scan #" + id
                                 + " and every host and port recorded under it.");
                return EXIT_OK;
            }
            System.err.println("[!!] No scan with id " + id + ".");
            return EXIT_INVALID_TARGET;
        } catch (RepositoryException e) {
            System.err.println("[!!] " + e.getMessage());
            return EXIT_DATABASE_ERROR;
        }
    }

    private static ScanRepository openRepository(Path databasePath) throws RepositoryException {
        return new ScanRepository(new DatabaseManager(databasePath));
    }

    /** Returns -1 and prints a message rather than throwing on bad input. */
    private static long parseId(String raw) {
        try {
            return Long.parseLong(raw.trim());
        } catch (NumberFormatException e) {
            System.err.println("[!!] '" + raw + "' is not a number");
            return -1;
        }
    }

    // ------------------------------------------------------------------- text

    private static void banner() {
        System.out.println("CyberScope v" + VERSION + " - authorised targets only, see SCOPE.md");
        System.out.println();
    }

    private static void printUsage() {
        System.out.println("""
                Usage: cyberscope [options] <target>
                       cyberscope --history [--limit n]
                       cyberscope --show <id>
                       cyberscope --delete <id>

                  <target>          an IPv4 address, a hostname, or a CIDR range
                                    (up to /24) you are authorised to scan

                Scan options:
                  -s, --scan-type   quick (default) or standard
                  -y, --yes         skip the interactive authorisation prompt
                      --no-save     do not record this scan in the history

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
                """);
    }

    private static boolean confirmAuthorisation(ValidatedTarget target) {
        System.out.println();
        System.out.println("  Active scanning is lawful only against systems you own or");
        System.out.println("  have explicit written permission to test.");
        if (target.isRange()) {
            System.out.println("  This will scan " + target.addressCount() + " addresses.");
        }
        System.out.print("  Type 'yes' to confirm you are authorised to scan "
                       + target.value() + ": ");
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            String answer = in.readLine();
            System.out.println();
            return answer != null && answer.trim().equalsIgnoreCase("yes");
        } catch (IOException e) {
            return false;
        }
    }
}