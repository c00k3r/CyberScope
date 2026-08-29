package com.cyberscope.repository;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.StreamReadConstraints;
import org.tukaani.xz.MemoryLimitException;
import org.tukaani.xz.XZInputStream;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Builds the CVE index from the offline NVD feed.
 *
 * <h2>Why this is streamed rather than parsed</h2>
 *
 * The corpus is 100.8 MB compressed and about <b>2.9 GB uncompressed</b>
 * (CVE-2024 alone is 317 MB). Reading a year into memory as a string or a tree
 * is not an option. Everything below is a single pass: xz decompression feeds a
 * pull parser, which feeds JDBC batches, and nothing larger than one CVE is ever
 * held. Measured peak heap for the whole 28-year build: <b>95 MB</b>, and it does
 * not grow with the number of years.
 *
 * <p>Almost all of that 95 MB is not ours. The feed is compressed with
 * {@code --lzma2=dict=64MiB}, so decompression allocates a 64 MiB dictionary
 * regardless of file size or how carefully we stream. That allocation happens on
 * the <em>first read</em>, not at construction, which is why
 * {@link MemoryLimitException} has to be caught around the read loop rather than
 * around the constructor.
 *
 * <h2>Why it builds into a temporary file</h2>
 *
 * A refresh interrupted halfway would otherwise leave an index containing some
 * products and not others -- and a missing product does not look like an error,
 * it looks like "no known vulnerabilities". That is precisely the failure this
 * whole version exists to prevent, so the build happens beside the real index and
 * replaces it only once every year has loaded.
 */
public final class CveFeedLoader {

    /** Where the feed lives. Recorded in the index so a source change is visible. */
    public static final String FEED_BASE =
            "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download";

    public static final int FIRST_YEAR = 1999;

    /**
     * The dictionary this feed needs, plus headroom.
     *
     * <p>Measured: {@code xz --list -vv} reports {@code --lzma2=dict=64MiB} and
     * the decoder asks for exactly 65,640 KB. The limit exists so that a feed
     * recompressed upstream with a larger dictionary produces a clear message
     * instead of an {@code OutOfMemoryError} from somewhere unrelated.
     */
    private static final int XZ_MEMORY_LIMIT_KB = 128 * 1024;

    private static final JsonFactory FACTORY = JsonFactory.builder()
            .streamReadConstraints(StreamReadConstraints.builder()
                    .maxStringLength(2_000_000)
                    .maxNestingDepth(64)
                    .build())
            .build();

    /** Progress for a long operation. Called from the calling thread. */
    @FunctionalInterface
    public interface Progress {
        void update(String stage, int done, int total);
    }

    /** What a completed refresh produced. */
    public record Result(int cveCount, int matchCount, int firstYear, int lastYear,
                         Instant feedTimestamp, Duration elapsed, long bytesDownloaded) { }

    private final CveIndexManager target;
    private final String feedBase;
    private final int lastYear;
    private final HttpClient http;

    public CveFeedLoader(CveIndexManager target) {
        this(target, FEED_BASE, Instant.now().atZone(java.time.ZoneOffset.UTC).getYear());
    }

    /** Test seam: a local base URL and a narrow year range keep tests offline and fast. */
    public CveFeedLoader(CveIndexManager target, String feedBase, int lastYear) {
        this.target = target;
        this.feedBase = feedBase;
        this.lastYear = lastYear;
        this.http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(30))
                .build();
    }

    /**
     * Downloads every year file and rebuilds the index from scratch.
     *
     * <p>Rebuild rather than merge: the feed is regenerated daily and CVEs are
     * revised in place, so a merge would have to reconcile changed applicability
     * statements row by row. A full rebuild takes about 50 seconds and is
     * obviously correct. If that ever stops being an acceptable trade, the
     * {@code lastModified} column is already stored to support an incremental path.
     *
     * @throws InterruptedException if the calling thread is interrupted; the
     *         existing index is left untouched
     */
    public Result refresh(Progress progress) throws RepositoryException, InterruptedException {
        Instant started = Instant.now();
        Path staging = target.indexFile().resolveSibling(
                target.indexFile().getFileName() + ".building");
        try {
            Files.deleteIfExists(staging);
        } catch (IOException e) {
            throw new RepositoryException("Could not clear the staging index: " + e.getMessage(), e);
        }

        CveIndexManager stagingManager = new CveIndexManager(staging);
        int totalYears = lastYear - FIRST_YEAR + 1;
        int cves = 0, matches = 0;
        long bytes = 0;
        Instant oldestFeedTimestamp = null;

        try (Connection connection = stagingManager.connect()) {
            tuneForBulkLoad(connection);
            dropLookupIndex(connection);

            for (int year = FIRST_YEAR; year <= lastYear; year++) {
                checkCancelled();
                int done = year - FIRST_YEAR;
                progress.update("Downloading CVE-" + year, done, totalYears);

                Path download = staging.resolveSibling("CVE-" + year + ".json.xz");
                try {
                    bytes += fetch(feedBase + "/CVE-" + year + ".json.xz", download);
                    checkCancelled();
                    progress.update("Indexing CVE-" + year, done, totalYears);

                    connection.setAutoCommit(false);
                    YearStats stats = loadYear(connection, download);
                    connection.commit();
                    connection.setAutoCommit(true);

                    cves += stats.cves;
                    matches += stats.matches;
                    // The index is only as fresh as its stalest year file.
                    if (stats.feedTimestamp != null
                        && (oldestFeedTimestamp == null
                            || stats.feedTimestamp.isBefore(oldestFeedTimestamp))) {
                        oldestFeedTimestamp = stats.feedTimestamp;
                    }
                } finally {
                    deleteQuietly(download);
                }
            }

            progress.update("Building the lookup index", totalYears, totalYears);
            createLookupIndex(connection);
            writeMetadata(connection, oldestFeedTimestamp, started,
                          cves, matches, FIRST_YEAR, lastYear);
            try (Statement statement = connection.createStatement()) {
                statement.execute("VACUUM");
            }
        } catch (SQLException e) {
            deleteQuietly(staging);
            throw new RepositoryException("Could not build the CVE index: " + e.getMessage(), e);
        } catch (RepositoryException | InterruptedException e) {
            deleteQuietly(staging);
            throw e;
        }

        // The swap. Everything before this point is reversible; nothing after it
        // can leave a partially built index in place.
        try {
            Files.move(staging, target.indexFile(),
                       StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException atomicUnsupported) {
            try {
                Files.move(staging, target.indexFile(), StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                deleteQuietly(staging);
                throw new RepositoryException(
                        "Built the index but could not put it in place: " + e.getMessage(), e);
            }
        }

        return new Result(cves, matches, FIRST_YEAR, lastYear, oldestFeedTimestamp,
                          Duration.between(started, Instant.now()), bytes);
    }

    // ------------------------------------------------------------- download

    private long fetch(String url, Path to) throws RepositoryException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofMinutes(10))
                .header("User-Agent", "CyberScope")
                .GET().build();
        try {
            HttpResponse<Path> response =
                    http.send(request, HttpResponse.BodyHandlers.ofFile(to));
            if (response.statusCode() != 200) {
                throw new RepositoryException(
                        "The CVE feed returned HTTP " + response.statusCode() + " for " + url);
            }
            return Files.size(to);
        } catch (IOException e) {
            throw new RepositoryException(
                    "Could not download " + url + ": " + e.getMessage()
                    + ". The CVE index needs one download; scanning still works without it.", e);
        }
    }

    // ------------------------------------------------------------- parse

    private record YearStats(int cves, int matches, Instant feedTimestamp) { }

    private YearStats loadYear(Connection connection, Path xzFile)
            throws RepositoryException, InterruptedException {
        int cveCount = 0, matchCount = 0;
        Instant feedTimestamp = null;

        try (InputStream raw = Files.newInputStream(xzFile);
             InputStream decompressed = new XZInputStream(
                     new BufferedInputStream(raw, 1 << 16), XZ_MEMORY_LIMIT_KB);
             JsonParser parser = FACTORY.createParser(
                     new BufferedInputStream(decompressed, 1 << 16));
             PreparedStatement insertCve = connection.prepareStatement(
                     "INSERT OR REPLACE INTO cve VALUES(?,?,?,?,?,?,?,?)");
             PreparedStatement insertMatch = connection.prepareStatement(
                     "INSERT INTO cve_match VALUES(?,?,?,?,?,?,?,?)")) {

            if (parser.nextToken() != JsonToken.START_OBJECT) {
                throw new RepositoryException("CVE feed " + xzFile.getFileName()
                                              + " is not a JSON object");
            }
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                String field = parser.currentName();
                parser.nextToken();
                if ("timestamp".equals(field)) {
                    feedTimestamp = parseOffset(parser.getText());
                    continue;
                }
                if (!"cve_items".equals(field)) {
                    parser.skipChildren();
                    continue;
                }
                while (parser.nextToken() == JsonToken.START_OBJECT) {
                    List<RawMatch> matches = new ArrayList<>();
                    RawCve cve = readCve(parser, matches);
                    if (cve == null) {
                        continue;
                    }
                    bindCve(insertCve, cve);
                    insertCve.addBatch();
                    for (RawMatch m : matches) {
                        bindMatch(insertMatch, cve.id, m);
                        insertMatch.addBatch();
                        matchCount++;
                    }
                    if (++cveCount % 2000 == 0) {
                        insertCve.executeBatch();
                        insertMatch.executeBatch();
                        checkCancelled();
                    }
                }
            }
            insertCve.executeBatch();
            insertMatch.executeBatch();

        } catch (MemoryLimitException e) {
            throw new RepositoryException(
                    "The CVE feed needs " + (e.getMemoryNeeded() / 1024)
                    + " MB to decompress, more than the " + (XZ_MEMORY_LIMIT_KB / 1024)
                    + " MB CyberScope allows. The feed was probably recompressed with a"
                    + " larger dictionary upstream.", e);
        } catch (IOException e) {
            throw new RepositoryException("Could not read " + xzFile.getFileName()
                                          + ": " + e.getMessage(), e);
        } catch (SQLException e) {
            throw new RepositoryException("Could not store " + xzFile.getFileName()
                                          + ": " + e.getMessage(), e);
        }
        return new YearStats(cveCount, matchCount, feedTimestamp);
    }

    /**
     * Field separator for the deduplication key.
     *
     * <p>A unit separator rather than a space or a comma, because both of those
     * occur inside real product names -- {@code office_app-edit_word,_pdf_file}
     * and {@code call_of_duty:_ghosts} are genuine NVD products. A separator that
     * can appear in the data turns two different keys into one and silently drops
     * a row.
     */
    private static final String SEP = "\u001f";

    private record RawCve(String id, String published, String lastModified, String description,
                          Double score, String severity, String vector, String cvssVersion) { }

    private record RawMatch(String vendor, String product, String version,
                            String startIncl, String startExcl,
                            String endIncl, String endExcl) { }

    private static RawCve readCve(JsonParser p, List<RawMatch> out) throws IOException {
        String id = null, published = null, lastModified = null, description = null;
        String[] metric = null;
        List<RawMatch> pending = new ArrayList<>();

        while (p.nextToken() != JsonToken.END_OBJECT) {
            String field = p.currentName();
            p.nextToken();
            switch (field) {
                case "id" -> id = p.getText();
                case "published" -> published = p.getText();
                case "lastModified" -> lastModified = p.getText();
                case "descriptions" -> description = readEnglishDescription(p);
                case "metrics" -> metric = readBestMetric(p);
                case "configurations" -> readConfigurations(p, pending);
                default -> p.skipChildren();
            }
        }
        if (id == null) {
            return null;
        }
        // One CVE can state the same (product, range) through several nodes.
        // Deduplicating here rather than in SQL keeps 2.09 million rows instead
        // of 3.4 million, at the cost of one HashSet per CVE.
        Set<String> seen = new HashSet<>();
        for (RawMatch m : pending) {
            if (seen.add(String.join(SEP, m.vendor, m.product, m.version,
                                     String.valueOf(m.startIncl), String.valueOf(m.startExcl),
                                     String.valueOf(m.endIncl), String.valueOf(m.endExcl)))) {
                out.add(m);
            }
        }
        Double score = metric != null && metric[0] != null ? Double.valueOf(metric[0]) : null;
        return new RawCve(id, published, lastModified, description,
                          score,
                          metric == null ? null : metric[1],
                          metric == null ? null : metric[2],
                          metric == null ? null : metric[3]);
    }

    /** The English description. NVD ships Spanish alongside it for most entries. */
    private static String readEnglishDescription(JsonParser p) throws IOException {
        String found = null;
        while (p.nextToken() == JsonToken.START_OBJECT) {
            String lang = null, value = null;
            while (p.nextToken() != JsonToken.END_OBJECT) {
                String field = p.currentName();
                p.nextToken();
                switch (field) {
                    case "lang" -> lang = p.getText();
                    case "value" -> value = p.getText();
                    default -> p.skipChildren();
                }
            }
            if ("en".equals(lang) && found == null) {
                found = value;
            }
        }
        return found;
    }

    /**
     * The authoritative CVSS score.
     *
     * <p>A CVE can carry several. CVE-2024-0001 carries two v3.1 base scores:
     * 10.0 from the vendor's own PSIRT and 9.8 from {@code nvd@nist.gov}. NVD's
     * convention is that the entry typed {@code Primary} is authoritative, so the
     * preference order is newest CVSS version first, and within a version
     * {@code Primary} before {@code Secondary}. Taking the first element of the
     * array -- the obvious implementation -- would pick whichever the feed
     * happened to serialise first.
     *
     * @return {@code {score, severity, vector, cvssVersion}}, or null if none
     */
    private static String[] readBestMetric(JsonParser p) throws IOException {
        String[][] candidates = new String[8][];        // rank*2 + (primary ? 0 : 1)
        while (p.nextToken() != JsonToken.END_OBJECT) {
            String key = p.currentName();
            p.nextToken();
            int rank = switch (key) {
                case "cvssMetricV40" -> 0;
                case "cvssMetricV31" -> 1;
                case "cvssMetricV30" -> 2;
                case "cvssMetricV2"  -> 3;
                default -> -1;
            };
            if (rank < 0) {
                p.skipChildren();
                continue;
            }
            String version = switch (rank) {
                case 0 -> "4.0"; case 1 -> "3.1"; case 2 -> "3.0"; default -> "2.0";
            };
            while (p.nextToken() == JsonToken.START_OBJECT) {
                String type = null, score = null, severity = null, vector = null;
                while (p.nextToken() != JsonToken.END_OBJECT) {
                    String field = p.currentName();
                    p.nextToken();
                    switch (field) {
                        case "type" -> type = p.getText();
                        // CVSS v2 puts baseSeverity beside cvssData, not inside it.
                        case "baseSeverity" -> { if (severity == null) severity = p.getText(); }
                        case "cvssData" -> {
                            while (p.nextToken() != JsonToken.END_OBJECT) {
                                String inner = p.currentName();
                                p.nextToken();
                                switch (inner) {
                                    case "baseScore" -> score = p.getText();
                                    case "baseSeverity" -> severity = p.getText();
                                    case "vectorString" -> vector = p.getText();
                                    default -> p.skipChildren();
                                }
                            }
                        }
                        default -> p.skipChildren();
                    }
                }
                int slot = rank * 2 + ("Primary".equals(type) ? 0 : 1);
                if (candidates[slot] == null) {
                    candidates[slot] = new String[]{score, severity, vector, version};
                }
            }
        }
        for (String[] candidate : candidates) {
            if (candidate != null) {
                return candidate;
            }
        }
        return null;
    }

    private static void readConfigurations(JsonParser p, List<RawMatch> out) throws IOException {
        while (p.nextToken() == JsonToken.START_OBJECT) {
            while (p.nextToken() != JsonToken.END_OBJECT) {
                String field = p.currentName();
                p.nextToken();
                if (!"nodes".equals(field)) {
                    p.skipChildren();
                    continue;
                }
                while (p.nextToken() == JsonToken.START_OBJECT) {
                    while (p.nextToken() != JsonToken.END_OBJECT) {
                        String inner = p.currentName();
                        p.nextToken();
                        if (!"cpeMatch".equals(inner)) {
                            p.skipChildren();
                            continue;
                        }
                        while (p.nextToken() == JsonToken.START_OBJECT) {
                            readCpeMatch(p, out);
                        }
                    }
                }
            }
        }
    }

    private static void readCpeMatch(JsonParser p, List<RawMatch> out) throws IOException {
        boolean vulnerable = false;
        String criteria = null, si = null, se = null, ei = null, ee = null;
        while (p.nextToken() != JsonToken.END_OBJECT) {
            String field = p.currentName();
            p.nextToken();
            switch (field) {
                case "vulnerable" -> vulnerable = p.getBooleanValue();
                case "criteria" -> criteria = p.getText();
                case "versionStartIncluding" -> si = p.getText();
                case "versionStartExcluding" -> se = p.getText();
                case "versionEndIncluding" -> ei = p.getText();
                case "versionEndExcluding" -> ee = p.getText();
                default -> p.skipChildren();
            }
        }
        // vulnerable=false means "this platform is required for the attack but is
        // not itself the flawed component" -- an operating system listed beside a
        // vulnerable application. Storing those would report the OS as vulnerable.
        if (!vulnerable || criteria == null) {
            return;
        }
        String[] fields = criteria.split("(?<!\\\\):", -1);
        if (fields.length < 6 || !"2.3".equals(fields[1])) {
            return;
        }
        out.add(new RawMatch(unescape(fields[3]), unescape(fields[4]), unescape(fields[5]),
                             si, se, ei, ee));
    }

    /**
     * Removes CPE backslash escapes, matching what {@code model.Cpe} does on the
     * other side of the lookup.
     *
     * <p>Both sides must agree. If the index stored {@code 1c\:enterprise} while
     * {@code Cpe} produced {@code 1c:enterprise}, every lookup for that product
     * would return nothing -- and an empty result is indistinguishable from "no
     * vulnerabilities". 229 products in the corpus contain an escaped colon.
     */
    static String unescape(String value) {
        if (value == null) {
            return "*";
        }
        if (value.indexOf('\\') < 0) {
            return value.toLowerCase(java.util.Locale.ROOT);
        }
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' && i + 1 < value.length()) {
                out.append(value.charAt(++i));
            } else {
                out.append(c);
            }
        }
        return out.toString().toLowerCase(java.util.Locale.ROOT);
    }

    // ------------------------------------------------------------- SQL

    /**
     * Trades durability for speed, which is safe only because this database is
     * disposable and is built into a staging file that is discarded on any error.
     * Never set these on {@code cyberscope.db}.
     */
    private static void tuneForBulkLoad(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA journal_mode = OFF");
            statement.execute("PRAGMA synchronous = OFF");
            statement.execute("PRAGMA temp_store = MEMORY");
        }
    }

    /**
     * Drops the lookup index for the duration of the bulk load.
     *
     * <p>Worth about 5% on a full build (49.6 s against 52.0 s, measured), which
     * is much less than the usual advice suggests. With journal_mode=OFF and
     * synchronous=OFF the bottleneck is parsing 2.9 GB of JSON, not maintaining
     * one two-column index. Kept because it is one statement and points the right
     * way; not kept because it matters much.
     */
    private static void dropLookupIndex(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP INDEX IF EXISTS idx_cve_match_product");
        }
    }

    private static void createLookupIndex(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute(
                    "CREATE INDEX IF NOT EXISTS idx_cve_match_product ON cve_match(vendor, product)");
        }
    }

    private void writeMetadata(Connection connection, Instant feedTimestamp, Instant builtAt,
                               int cves, int matches, int firstYear, int lastYear)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT OR REPLACE INTO index_metadata VALUES(1,?,?,?,?,?,?,?)")) {
            statement.setString(1, feedTimestamp == null ? null : feedTimestamp.toString());
            statement.setString(2, builtAt.toString());
            statement.setString(3, feedBase);
            statement.setInt(4, cves);
            statement.setInt(5, matches);
            statement.setInt(6, firstYear);
            statement.setInt(7, lastYear);
            statement.executeUpdate();
        }
    }

    private static void bindCve(PreparedStatement ps, RawCve cve) throws SQLException {
        ps.setString(1, cve.id);
        ps.setString(2, cve.published);
        ps.setString(3, cve.lastModified);
        if (cve.score == null) {
            ps.setNull(4, java.sql.Types.REAL);
        } else {
            ps.setDouble(4, cve.score);
        }
        ps.setString(5, cve.severity);
        ps.setString(6, cve.vector);
        ps.setString(7, cve.cvssVersion);
        // Truncated on purpose. The report shows one line and links to NVD for the
        // rest; keeping full text costs 126 MB across the corpus and buys nothing
        // a click cannot.
        String description = cve.description == null ? "" : cve.description;
        ps.setString(8, description.length() > 300 ? description.substring(0, 300) : description);
    }

    private static void bindMatch(PreparedStatement ps, String cveId, RawMatch m)
            throws SQLException {
        ps.setString(1, cveId);
        ps.setString(2, m.vendor);
        ps.setString(3, m.product);
        ps.setString(4, m.version);
        ps.setString(5, m.startIncl);
        ps.setString(6, m.startExcl);
        ps.setString(7, m.endIncl);
        ps.setString(8, m.endExcl);
    }

    // ------------------------------------------------------------- plumbing

    /**
     * Cooperative cancellation, the same discipline as {@code ProcessRunner}.
     *
     * <p>A 50-second build the user cannot stop is a hang as far as they are
     * concerned. Checking the interrupt flag between years and between batches
     * bounds the wait to one batch.
     */
    private static void checkCancelled() throws InterruptedException {
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedException("CVE index refresh cancelled");
        }
    }

    private static Instant parseOffset(String text) {
        try {
            return java.time.OffsetDateTime.parse(text).toInstant();
        } catch (DateTimeParseException e) {
            try {
                return Instant.parse(text);
            } catch (DateTimeParseException ignored) {
                return null;
            }
        }
    }

    private static void deleteQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // A leftover temp file is untidy, not a failure worth reporting over
            // whatever real error is already propagating.
        }
    }
}