package com.cyberscope.repository;

import com.cyberscope.model.MatchPrecision;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.tukaani.xz.LZMA2Options;
import org.tukaani.xz.XZOutputStream;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CveIndexTest {

    @TempDir
    Path dir;

    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    // ------------------------------------------------------------- fixtures

    /**
     * One year file, compressed exactly the way the real feed is structured but
     * with LZMA2 preset 0.
     *
     * <p>Preset choice is not cosmetic. Measured on a 520-byte payload:
     * <pre>
     *   preset 0 -> readable with a   1 MB dictionary
     *   preset 1 -> readable with an  8 MB dictionary
     *   preset 6 -> readable with a  64 MB dictionary   (the library default)
     * </pre>
     * The memory a reader needs is chosen by the writer and has nothing to do
     * with how much data there is. Compressing a half-kilobyte fixture at the
     * default preset would make every test allocate 64 MB.
     */
    private static byte[] xz(String json) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (XZOutputStream out = new XZOutputStream(bytes, new LZMA2Options(0))) {
            out.write(json.getBytes(StandardCharsets.UTF_8));
        }
        return bytes.toByteArray();
    }

    private static String feed(String timestamp, String... items) {
        return "{\"timestamp\":\"" + timestamp + "\",\"cve_count\":" + items.length
               + ",\"feed_name\":\"test\",\"cve_items\":[" + String.join(",", items) + "]}";
    }

    /** regreSSHion, reduced to the fields the loader reads. */
    private static final String REGRESSHION = """
            {"id":"CVE-2024-6387",
             "published":"2024-07-01T00:00:00.000",
             "lastModified":"2025-01-01T00:00:00.000",
             "descriptions":[{"lang":"es","value":"NO DEBE APARECER"},
                             {"lang":"en","value":"A security regression in OpenSSH sshd."}],
             "metrics":{"cvssMetricV31":[
                {"source":"vendor","type":"Secondary","cvssData":{"baseScore":10.0,
                  "baseSeverity":"CRITICAL","vectorString":"SECONDARY-VECTOR"}},
                {"source":"nvd@nist.gov","type":"Primary","cvssData":{"baseScore":8.1,
                  "baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N/AC:H"}}]},
             "configurations":[{"nodes":[{"cpeMatch":[
                {"vulnerable":true,"criteria":"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                 "versionStartIncluding":"8.6","versionEndIncluding":"9.8"},
                {"vulnerable":true,"criteria":"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                 "versionEndExcluding":"4.4"},
                {"vulnerable":false,
                 "criteria":"cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*"}
             ]}]},
             {"nodes":[{"cpeMatch":[
                {"vulnerable":true,"criteria":"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                 "versionStartIncluding":"8.6","versionEndIncluding":"9.8"}
             ]}]}]}
            """;

    /** A product whose name contains an escaped colon. 229 of these exist in NVD. */
    private static final String ESCAPED = """
            {"id":"CVE-2020-0001",
             "published":"2020-01-01T00:00:00.000","lastModified":"2020-01-01T00:00:00.000",
             "descriptions":[{"lang":"en","value":"Escaped separator test."}],
             "metrics":{"cvssMetricV2":[{"type":"Primary","baseSeverity":"MEDIUM",
                "cvssData":{"baseScore":5.0,"vectorString":"AV:N/AC:L"}}]},
             "configurations":[{"nodes":[{"cpeMatch":[
                {"vulnerable":true,"criteria":"cpe:2.3:a:1c:1c\\\\:enterprise:8.3:*:*:*:*:*:*:*"}
             ]}]}]}
            """;

    /** A CVE with no CVSS metrics at all -- 71,464 of these exist in the corpus. */
    private static final String NO_METRICS = """
            {"id":"CVE-2026-9999",
             "published":"2026-01-01T00:00:00.000","lastModified":"2026-01-01T00:00:00.000",
             "descriptions":[{"lang":"en","value":"Awaiting analysis."}],
             "configurations":[{"nodes":[{"cpeMatch":[
                {"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}
             ]}]}]}
            """;

    /**
     * Serves the fixture years over loopback so the loader's real HTTP path is
     * exercised. A mock HttpClient would test the parser but not the download,
     * the 404 handling, or the temp-file lifecycle.
     */
    private String serveFeed() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        byte[] y1 = xz(feed("2026-08-29T00:00:09+00:00", REGRESSHION, ESCAPED));
        byte[] y2 = xz(feed("2026-08-20T00:00:09+00:00", NO_METRICS));
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            byte[] body = path.endsWith("CVE-1999.json.xz") ? y1
                        : path.endsWith("CVE-2000.json.xz") ? y2
                        : null;
            if (body == null) {
                exchange.sendResponseHeaders(404, -1);
                exchange.close();
                return;
            }
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private CveIndexManager manager() throws Exception {
        return new CveIndexManager(dir.resolve("cve-index.db"));
    }

    private static void silently(String stage, int done, int total) {
        // progress is exercised by the callback below; nothing to assert here
    }

    // ------------------------------------------------------------- schema

    @Nested
    @DisplayName("the index file")
    class Schema {

        @Test
        @DisplayName("a fresh index is migrated, not stamped as current")
        void migrationsRunOnNewDatabases() throws Exception {
            CveIndexManager m = manager();
            assertEquals(1, m.schemaVersion(),
                    "a new index must walk 0 -> 1 like every other index");
            assertTrue(Files.exists(m.indexFile()));
        }

        @Test
        @DisplayName("reopening does not re-run migrations or lose data")
        void reopenIsIdempotent() throws Exception {
            CveIndexManager first = manager();
            assertEquals(1, first.schemaVersion());
            CveIndexManager second = manager();
            assertEquals(1, second.schemaVersion());
        }

        /**
         * The policy that differs from DatabaseManager. The scan database must
         * never be silently deleted; this one must, because it is a cache and the
         * alternative is a permanently unusable feature.
         */
        @Test
        @DisplayName("a corrupt index is discarded and rebuilt rather than reported")
        void corruptFileIsRecovered() throws Exception {
            Path file = dir.resolve("cve-index.db");
            Files.write(file, "this is not a SQLite database".getBytes(StandardCharsets.UTF_8));

            CveIndexManager m = new CveIndexManager(file);

            assertEquals(1, m.schemaVersion());
            assertTrue(Files.size(file) > 0);
        }

        @Test
        void discardRemovesTheFile() throws Exception {
            CveIndexManager m = manager();
            assertTrue(Files.exists(m.indexFile()));
            m.discard();
            assertFalse(Files.exists(m.indexFile()));
        }

        /**
         * The bug this project shipped once already: splitting on ';' before
         * stripping comments turns a semicolon inside a comment into a statement
         * boundary.
         */
        @Test
        @DisplayName("a semicolon inside a comment is not a statement boundary")
        void commentsAreStrippedBeforeSplitting() {
            List<String> statements = CveIndexManager.splitStatements("""
                    -- a comment; with a semicolon in it
                    CREATE TABLE a (x TEXT);
                    -- another; one
                    CREATE TABLE b (y TEXT);
                    """);
            assertEquals(2, statements.size(), statements.toString());
            assertTrue(statements.get(0).startsWith("CREATE TABLE a"));
            assertTrue(statements.get(1).startsWith("CREATE TABLE b"));
        }

        @Test
        void defaultLocationSitsBesideTheScanDatabase() {
            assertEquals(DatabaseManager.defaultLocation().getParent(),
                    CveIndexManager.defaultLocation().getParent(),
                    "both live in ~/.cyberscope so a user has one directory to find");
            assertTrue(CveIndexManager.defaultLocation().toString().endsWith("cve-index.db"));
        }
    }

    // ------------------------------------------------------------- loading

    @Nested
    @DisplayName("building the index from the feed")
    class Loading {

        @Test
        @DisplayName("downloads, decompresses, parses and stores")
        void endToEnd() throws Exception {
            String base = serveFeed();
            CveIndexManager m = manager();
            StringBuilder stages = new StringBuilder();

            CveFeedLoader.Result result = new CveFeedLoader(m, base, 2000)
                    .refresh((stage, done, total) -> stages.append(stage).append('\n'));

            assertEquals(3, result.cveCount());
            assertEquals(1999, result.firstYear());
            assertEquals(2000, result.lastYear());
            assertTrue(stages.toString().contains("Downloading CVE-1999"), stages.toString());
            assertTrue(stages.toString().contains("Indexing CVE-2000"), stages.toString());

            CveRepository repo = new CveRepository(m);
            assertTrue(repo.isPopulated());
            assertEquals(3, repo.productCount(),
                    "openbsd:openssh, 1c:1c:enterprise and acme:widget");
        }

        /**
         * CVE-2024-6387 states its applicability through two configurations and
         * three cpeMatch entries, one of which repeats. Storing the duplicate
         * would make the same vulnerability appear twice in a report.
         */
        @Test
        @DisplayName("identical applicability statements are stored once")
        void duplicatesAreCollapsed() throws Exception {
            String base = serveFeed();
            CveIndexManager m = manager();
            new CveFeedLoader(m, base, 1999).refresh(CveIndexTest::silently);

            List<CveMatchRow> rows =
                    new CveRepository(m).findByProduct("openbsd", "openssh");

            assertEquals(2, rows.size(),
                    "the >=8.6 <=9.8 statement appears twice in the feed and once here");
        }

        @Test
        @DisplayName("both of regreSSHion's ranges survive with their precision")
        void rangesAreStoredNotFlattened() throws Exception {
            String base = serveFeed();
            CveIndexManager m = manager();
            new CveFeedLoader(m, base, 1999).refresh(CveIndexTest::silently);

            List<CveMatchRow> rows =
                    new CveRepository(m).findByProduct("openbsd", "openssh");

            assertTrue(rows.stream().allMatch(
                    r -> r.range().precision() == MatchPrecision.VERSION_RANGE));
            assertTrue(rows.stream().anyMatch(r -> ">= 8.6, <= 9.8".equals(r.range().describe())),
                    rows.toString());
            assertTrue(rows.stream().anyMatch(r -> "< 4.4".equals(r.range().describe())),
                    rows.toString());
        }

        /**
         * A cpeMatch with vulnerable=false names a platform the attack needs, not
         * the flawed component. Storing it would report Ubuntu as vulnerable
         * every time an application running on it was.
         */
        @Test
        @DisplayName("vulnerable=false entries are not stored")
        void nonVulnerablePlatformsAreSkipped() throws Exception {
            String base = serveFeed();
            CveIndexManager m = manager();
            new CveFeedLoader(m, base, 1999).refresh(CveIndexTest::silently);

            assertTrue(new CveRepository(m).findByProduct("canonical", "ubuntu_linux").isEmpty());
        }

        @Test
        @DisplayName("the Primary CVSS score wins over the vendor's own")
        void primaryMetricIsAuthoritative() throws Exception {
            String base = serveFeed();
            CveIndexManager m = manager();
            new CveFeedLoader(m, base, 1999).refresh(CveIndexTest::silently);

            CveMatchRow row = new CveRepository(m).findByProduct("openbsd", "openssh").get(0);

            assertEquals(8.1, row.cvssScore(), 0.001,
                    "10.0 is the vendor's Secondary score and must not be preferred");
            assertEquals("HIGH", row.cvssSeverity());
            assertEquals("CVSS:3.1/AV:N/AC:H", row.cvssVector());
            assertEquals("3.1", row.cvssVersion());
        }

        @Test
        @DisplayName("the English description is kept and the Spanish one is not")
        void englishDescriptionOnly() throws Exception {
            String base = serveFeed();
            CveIndexManager m = manager();
            new CveFeedLoader(m, base, 1999).refresh(CveIndexTest::silently);

            CveMatchRow row = new CveRepository(m).findByProduct("openbsd", "openssh").get(0);

            assertTrue(row.description().startsWith("A security regression"), row.description());
            assertFalse(row.description().contains("NO DEBE"), row.description());
        }

        /**
         * Both sides of the lookup must unescape identically. If the index stored
         * {@code 1c\:enterprise} and Cpe produced {@code 1c:enterprise}, the
         * lookup would return nothing -- and nothing looks like safety.
         */
        @Test
        @DisplayName("an escaped colon is unescaped the same way Cpe unescapes it")
        void escapedProductNamesAreFindable() throws Exception {
            String base = serveFeed();
            CveIndexManager m = manager();
            new CveFeedLoader(m, base, 1999).refresh(CveIndexTest::silently);

            List<CveMatchRow> rows =
                    new CveRepository(m).findByProduct("1c", "1c:enterprise");

            assertEquals(1, rows.size(), "stored as 1c:enterprise, not 1c\\:enterprise");
            assertEquals(MatchPrecision.VERSION_EXACT, rows.get(0).range().precision());
        }

        @Test
        @DisplayName("a CVE with no CVSS data is stored with a null score, not a zero")
        void missingMetricsAreNull() throws Exception {
            String base = serveFeed();
            CveIndexManager m = manager();
            new CveFeedLoader(m, base, 2000).refresh(CveIndexTest::silently);

            CveMatchRow row = new CveRepository(m).findByProduct("acme", "widget").get(0);

            assertEquals(null, row.cvssScore(),
                    "0.0 would render as 'no severity' rather than 'not scored'");
            assertEquals(null, row.cvssSeverity());
        }

        @Test
        @DisplayName("NVD's offset-less timestamps are read as UTC, not rejected")
        void publishedDateIsParsed() throws Exception {
            String base = serveFeed();
            CveIndexManager m = manager();
            new CveFeedLoader(m, base, 1999).refresh(CveIndexTest::silently);

            CveMatchRow row = new CveRepository(m).findByProduct("openbsd", "openssh").get(0);

            assertNotNull(row.published(), "2024-07-01T00:00:00.000 has no offset");
            assertEquals(Instant.parse("2024-07-01T00:00:00Z"), row.published());
        }

        @Test
        void theNvdLinkIsBuiltFromTheId() throws Exception {
            String base = serveFeed();
            CveIndexManager m = manager();
            new CveFeedLoader(m, base, 1999).refresh(CveIndexTest::silently);

            assertEquals("https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
                    new CveRepository(m).findByProduct("openbsd", "openssh").get(0).nvdUrl());
        }
    }

    // ------------------------------------------------------------- failure

    @Nested
    @DisplayName("when a refresh does not finish")
    class Failure {

        /**
         * The property that matters most. A half-built index reports "no known
         * vulnerabilities" for every product it did not reach yet -- the exact
         * false negative this version exists to eliminate.
         */
        @Test
        @DisplayName("a failed refresh leaves the previous index untouched")
        void failureDoesNotDamageTheExistingIndex() throws Exception {
            String base = serveFeed();
            CveIndexManager m = manager();
            new CveFeedLoader(m, base, 1999).refresh(CveIndexTest::silently);
            long goodSize = Files.size(m.indexFile());
            assertTrue(new CveRepository(m).isPopulated());

            // 2001 is not served: the second refresh must fail partway.
            assertThrows(RepositoryException.class,
                    () -> new CveFeedLoader(m, base, 2001).refresh(CveIndexTest::silently));

            assertEquals(goodSize, Files.size(m.indexFile()),
                    "the working index must be byte-for-byte unchanged");
            assertTrue(new CveRepository(m).isPopulated());
            assertEquals(2, new CveRepository(m).findByProduct("openbsd", "openssh").size());
        }

        @Test
        @DisplayName("no staging file is left behind")
        void stagingIsCleanedUp() throws Exception {
            String base = serveFeed();
            CveIndexManager m = manager();
            assertThrows(RepositoryException.class,
                    () -> new CveFeedLoader(m, base, 2001).refresh(CveIndexTest::silently));

            try (var entries = Files.list(dir)) {
                assertTrue(entries.noneMatch(p -> p.getFileName().toString().contains(".building")),
                        "a leftover .building file would be silently reused");
            }
        }

        @Test
        @DisplayName("an interrupted refresh throws rather than half-finishing")
        void cancellationIsCooperative() throws Exception {
            String base = serveFeed();
            CveIndexManager m = manager();
            Thread.currentThread().interrupt();
            try {
                assertThrows(InterruptedException.class,
                        () -> new CveFeedLoader(m, base, 1999).refresh(CveIndexTest::silently));
            } finally {
                Thread.interrupted();       // clear the flag for the next test
            }
        }

        @Test
        @DisplayName("an empty index is not populated, and says so without throwing")
        void freshIndexIsEmptyNotBroken() throws Exception {
            CveIndexManager m = manager();
            CveRepository repo = new CveRepository(m);

            assertFalse(repo.isPopulated());
            assertEquals(Optional.empty(), repo.metadata());
            assertTrue(repo.findByProduct("openbsd", "openssh").isEmpty());
        }
    }

    // ------------------------------------------------------------- staleness

    @Nested
    @DisplayName("staleness")
    class Staleness {

        @Test
        @DisplayName("metadata records the OLDEST feed timestamp, not the newest")
        void freshnessIsThatOfTheStalestYear() throws Exception {
            String base = serveFeed();
            CveIndexManager m = manager();
            new CveFeedLoader(m, base, 2000).refresh(CveIndexTest::silently);

            IndexMetadata meta = new CveRepository(m).metadata().orElseThrow();

            assertEquals(Instant.parse("2026-08-20T00:00:09Z"), meta.feedTimestamp(),
                    "1999 is dated the 29th and 2000 the 20th; the index is as old as the 20th");
            assertEquals(3, meta.cveCount());
            assertEquals(1999, meta.firstYear());
            assertEquals(2000, meta.lastYear());
            assertTrue(meta.source().contains("127.0.0.1"));
        }

        @Test
        @DisplayName("age is measured from the feed, not from our download")
        void aFreshDownloadOfOldDataIsStillOld() {
            Instant now = Instant.parse("2026-08-29T00:00:00Z");
            IndexMetadata meta = new IndexMetadata(
                    Instant.parse("2026-07-01T00:00:00Z"),   // feed is 59 days old
                    now,                                     // but we downloaded it just now
                    "test", 1, 1, 1999, 2026);

            assertEquals(59, meta.age(now).toDays());
            assertTrue(meta.isStale(now),
                    "downloading a stale mirror today must not present as up to date");
        }

        @Test
        void theThresholdIsSevenDays() {
            Instant now = Instant.parse("2026-08-29T00:00:00Z");
            assertEquals(Duration.ofDays(7), IndexMetadata.STALE_AFTER);
            assertFalse(new IndexMetadata(now.minus(Duration.ofDays(7)), now, "t", 1, 1, 1999, 2026)
                    .isStale(now));
            assertTrue(new IndexMetadata(now.minus(Duration.ofDays(8)), now, "t", 1, 1, 1999, 2026)
                    .isStale(now));
        }

        @Test
        @DisplayName("a clock skew does not produce a negative age")
        void futureTimestampsClampToZero() {
            Instant now = Instant.parse("2026-08-29T00:00:00Z");
            IndexMetadata meta = new IndexMetadata(
                    now.plus(Duration.ofHours(6)), now, "t", 1, 1, 1999, 2026);

            assertEquals(Duration.ZERO, meta.age(now));
            assertFalse(meta.isStale(now));
        }

        @Test
        @DisplayName("the one-line summary states the count, the span and the age")
        void describesItselfForAReportHeader() {
            Instant now = Instant.parse("2026-08-29T00:00:00Z");
            String text = new IndexMetadata(Instant.parse("2026-08-20T00:00:00Z"), now,
                    CveFeedLoader.FEED_BASE, 384513, 2093452, 1999, 2026)
                    .describe(now, ZoneOffset.UTC);

            assertTrue(text.contains("384,513 CVEs"), text);
            assertTrue(text.contains("1999-2026"), text);
            assertTrue(text.contains("9 days old"), text);
            assertTrue(text.contains("STALE"), text);
        }

        @Test
        void aFreshIndexIsNotLabelledStale() {
            Instant now = Instant.parse("2026-08-29T00:00:00Z");
            String text = new IndexMetadata(now, now, "t", 10, 20, 1999, 2026)
                    .describe(now, ZoneOffset.UTC);

            assertTrue(text.contains("today"), text);
            assertFalse(text.contains("STALE"), text);
        }
    }
}