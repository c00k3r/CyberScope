package com.cyberscope.repository;

import com.cyberscope.model.DetectionMethod;
import com.cyberscope.model.Host;
import com.cyberscope.model.HostState;
import com.cyberscope.model.Port;
import com.cyberscope.model.PortState;
import com.cyberscope.model.Protocol;
import com.cyberscope.model.ScanType;
import com.cyberscope.model.Service;
import com.cyberscope.service.scanner.NmapRunResult;
import com.cyberscope.service.scanner.ScanOutcome;
import com.cyberscope.util.TargetKind;
import com.cyberscope.util.ValidatedTarget;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanRepositoryTest {

    @TempDir
    Path directory;

    private Path databaseFile;
    private ScanRepository repository;

    @BeforeEach
    void setUp() throws Exception {
        databaseFile = directory.resolve("test.db");
        repository = new ScanRepository(new DatabaseManager(databaseFile));
    }

    // ------------------------------------------------------------- fixtures

    private static Service service() {
        return new Service("http", "nginx", "1.24.0", "Ubuntu",
                List.of("cpe:/a:nginx:nginx:1.24.0", "cpe:/o:canonical:ubuntu_linux"),
                DetectionMethod.PROBED, 10);
    }

    private static Port openPort(int number) {
        return new Port(number, Protocol.TCP, PortState.OPEN, "syn-ack", service());
    }

    private static ScanOutcome outcome(String target, TargetKind kind, int addresses,
                                       List<Host> hosts) {
        NmapRunResult run = new NmapRunResult(
                new ValidatedTarget(target, kind, addresses),
                ScanType.QUICK,
                List.of("nmap", "-sV", "-T4", "-F", "-oX", "/tmp/scan.xml", target),
                "<nmaprun/>",
                Instant.parse("2026-08-20T10:15:30.123456789Z"),
                Duration.ofMillis(6789),
                "");
        return new ScanOutcome(run, hosts);
    }

    private static ScanOutcome singleHost() {
        return outcome("127.0.0.1", TargetKind.IPV4, 1, List.of(
                new Host("127.0.0.1", "localhost", HostState.UP,
                        List.of(openPort(80),
                                new Port(22, Protocol.TCP, PortState.CLOSED, "reset",
                                         Service.UNKNOWN)))));
    }

    // -------------------------------------------------------------- round trip

    @Nested
    @DisplayName("what goes in comes back out")
    class RoundTrip {

        @Test
        void savesAndReloadsAScanUnchanged() throws Exception {
            ScanOutcome original = singleHost();
            long id = repository.save(original);

            ScanOutcome loaded = repository.load(id).orElseThrow();

            assertEquals(original.hosts(), loaded.hosts());
            assertEquals(original.run().target(), loaded.run().target());
            assertEquals(original.run().scanType(), loaded.run().scanType());
            assertEquals(original.run().startedAt(), loaded.run().startedAt());
            assertEquals(original.run().command(), loaded.run().command());
        }

        /**
         * Regression, v0.3.0. Duration.between(Instant, Instant) carries nanoseconds
         * but elapsed_ms stores milliseconds, so a saved scan did not equal the scan
         * it was saved from. NmapRunResult now truncates on construction; if that is
         * ever removed, this fails.
         */
        @Test
        void elapsedSurvivesTheRoundTrip() throws Exception {
            NmapRunResult nanos = new NmapRunResult(
                    new ValidatedTarget("127.0.0.1", TargetKind.IPV4, 1),
                    ScanType.QUICK, List.of("nmap", "127.0.0.1"), "",
                    Instant.now(),
                    Duration.ofSeconds(6).plusNanos(789_123_456),
                    "");
            long id = repository.save(new ScanOutcome(nanos, List.of()));

            Duration loaded = repository.load(id).orElseThrow().run().elapsed();

            assertEquals(nanos.elapsed(), loaded);
            assertEquals(0, loaded.toNanosPart() % 1_000_000,
                    "a stored duration must be whole milliseconds");
        }

        /**
         * Regression, v0.3.0. The command was stored space-joined and split back on
         * spaces, so any argument containing a space came back as two arguments.
         * A temp directory with a space in its name is enough to trigger it.
         */
        @Test
        void argumentsContainingSpacesSurviveTheRoundTrip() throws Exception {
            List<String> command = List.of(
                    "nmap", "-sV", "-oX", "/home/moksh guleria/scan.xml", "127.0.0.1");
            NmapRunResult run = new NmapRunResult(
                    new ValidatedTarget("127.0.0.1", TargetKind.IPV4, 1),
                    ScanType.QUICK, command, "", Instant.now(), Duration.ofSeconds(1), "");

            long id = repository.save(new ScanOutcome(run, List.of()));

            assertEquals(command, repository.load(id).orElseThrow().run().command());
        }

        @Test
        void cpesRoundTripAsAList() throws Exception {
            long id = repository.save(singleHost());
            Service loaded = repository.load(id).orElseThrow()
                    .hosts().get(0).openPorts().get(0).service();

            assertEquals(List.of("cpe:/a:nginx:nginx:1.24.0", "cpe:/o:canonical:ubuntu_linux"),
                    loaded.cpes());
        }

        /**
         * "".split("\n") returns {""}, not {} -- so the naive read produced a
         * one-element list holding an empty string, which prints as [] and would
         * have shown a blank CPE in the UI.
         */
        @Test
        void aServiceWithNoCpesLoadsAsAnEmptyList() throws Exception {
            Host host = new Host("127.0.0.1", "", HostState.UP,
                    List.of(new Port(9999, Protocol.TCP, PortState.OPEN, "syn-ack",
                            new Service("unknown", "", "", "", List.of(),
                                        DetectionMethod.TABLE, 3))));
            long id = repository.save(outcome("127.0.0.1", TargetKind.IPV4, 1, List.of(host)));

            List<String> cpes = repository.load(id).orElseThrow()
                    .hosts().get(0).ports().get(0).service().cpes();

            assertTrue(cpes.isEmpty(), "expected no CPEs, got " + cpes.size() + ": " + cpes);
        }

        @Test
        void aCidrTargetKeepsItsKindAndAddressCount() throws Exception {
            long id = repository.save(
                    outcome("192.0.2.0/29", TargetKind.CIDR, 8, List.of()));

            ValidatedTarget loaded = repository.load(id).orElseThrow().run().target();

            assertEquals(TargetKind.CIDR, loaded.kind());
            assertEquals(8, loaded.addressCount());
            assertTrue(loaded.isRange());
        }

        /**
         * Regression, v0.3.0. loadPorts used ORDER BY number, which reordered
         * anything not already ascending. Nmap happens to emit ports in ascending
         * order, so real scans hid it -- exactly why the fixture here does not.
         */
        @Test
        void portsComeBackInTheOrderTheyWereSaved() throws Exception {
            List<Port> saved = List.of(openPort(443), openPort(22), openPort(80));
            long id = repository.save(outcome("127.0.0.1", TargetKind.IPV4, 1,
                    List.of(new Host("127.0.0.1", "", HostState.UP, saved))));

            List<Integer> order = repository.load(id).orElseThrow()
                    .hosts().get(0).ports().stream().map(Port::number).toList();

            assertEquals(List.of(443, 22, 80), order);
        }

        @Test
        void hostsComeBackInTheOrderTheyWereSaved() throws Exception {
            long id = repository.save(outcome("192.0.2.0/29", TargetKind.CIDR, 8, List.of(
                    new Host("192.0.2.7", "", HostState.UP, List.of()),
                    new Host("192.0.2.1", "", HostState.UP, List.of()),
                    new Host("192.0.2.4", "", HostState.DOWN, List.of()))));

            List<String> order = repository.load(id).orElseThrow()
                    .hosts().stream().map(Host::ipAddress).toList();

            assertEquals(List.of("192.0.2.7", "192.0.2.1", "192.0.2.4"), order);
        }

        @Test
        void closedPortsArePersistedTooNotJustOpenOnes() throws Exception {
            long id = repository.save(singleHost());
            List<Port> ports = repository.load(id).orElseThrow().hosts().get(0).ports();

            assertEquals(2, ports.size());
            assertEquals(1, ports.stream().filter(Port::isOpen).count());
        }
    }

    // ------------------------------------------------------------ transactions

    @Nested
    @DisplayName("a failed save leaves nothing behind")
    class Transactions {

        /**
         * Dropping the ports table makes the session and host inserts succeed and
         * the port insert fail -- exactly the half-written state a transaction
         * exists to prevent. Without the rollback, the session and host rows would
         * survive as a scan that claims a host with no ports.
         */
        @Test
        void aFailurePartWayThroughRollsBackEverything() throws Exception {
            dropTable("ports");

            assertThrows(RepositoryException.class, () -> repository.save(singleHost()));

            assertEquals(0, repository.count(), "the session row should have been rolled back");
            assertEquals(0, rowCount("hosts"), "the host row should have been rolled back");
        }

        @Test
        void aSuccessfulSaveAfterAFailedOneStillWorks() throws Exception {
            dropTable("ports");
            assertThrows(RepositoryException.class, () -> repository.save(singleHost()));

            // Recreate the table; the connection must not be left in a bad state.
            execute("""
                    CREATE TABLE ports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                        number INTEGER NOT NULL, protocol TEXT NOT NULL, state TEXT NOT NULL,
                        reason TEXT NOT NULL DEFAULT '', service_name TEXT NOT NULL DEFAULT '',
                        product TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '',
                        extra_info TEXT NOT NULL DEFAULT '', cpes TEXT NOT NULL DEFAULT '',
                        method TEXT NOT NULL, confidence INTEGER NOT NULL)
                    """);

            assertTrue(repository.save(singleHost()) > 0);
            assertEquals(1, repository.count());
        }
    }

    // ----------------------------------------------------------------- listing

    @Nested
    @DisplayName("history listing")
    class Listing {

        @Test
        void countsHostsAndOpenPortsWithoutLoadingThem() throws Exception {
            repository.save(singleHost());
            ScanSummary summary = repository.listRecent(10).get(0);

            assertEquals(1, summary.hostCount());
            assertEquals(1, summary.openPortCount(), "the closed port must not be counted");
        }

        @Test
        void returnsNewestFirst() throws Exception {
            saveAt("2026-08-01T00:00:00Z", "10.0.0.1");
            saveAt("2026-08-20T00:00:00Z", "10.0.0.2");
            saveAt("2026-08-10T00:00:00Z", "10.0.0.3");

            List<String> order = repository.listRecent(10).stream()
                    .map(ScanSummary::target).toList();

            assertEquals(List.of("10.0.0.2", "10.0.0.3", "10.0.0.1"), order);
        }

        @Test
        void honoursTheLimit() throws Exception {
            for (int i = 1; i <= 5; i++) {
                saveAt("2026-08-0" + i + "T00:00:00Z", "10.0.0." + i);
            }
            assertEquals(2, repository.listRecent(2).size());
        }

        @Test
        void anEmptyDatabaseListsNothingRatherThanFailing() throws Exception {
            assertTrue(repository.listRecent(10).isEmpty());
            assertEquals(0, repository.count());
        }

        private void saveAt(String when, String target) throws Exception {
            NmapRunResult run = new NmapRunResult(
                    new ValidatedTarget(target, TargetKind.IPV4, 1), ScanType.QUICK,
                    List.of("nmap", target), "", Instant.parse(when),
                    Duration.ofSeconds(1), "");
            repository.save(new ScanOutcome(run, List.of()));
        }
    }

    // ------------------------------------------------------------------ delete

    @Nested
    @DisplayName("delete")
    class Delete {

        @Test
        void removesTheHostsAndPortsWithTheSession() throws Exception {
            long id = repository.save(singleHost());
            assertEquals(1, rowCount("hosts"));
            assertEquals(2, rowCount("ports"));

            assertTrue(repository.delete(id));

            assertEquals(0, rowCount("hosts"), "ON DELETE CASCADE did not reach hosts");
            assertEquals(0, rowCount("ports"), "ON DELETE CASCADE did not reach ports");
            assertEquals(Optional.empty(), repository.load(id));
        }

        @Test
        void deletingSomethingThatIsNotThereReportsFalseRatherThanThrowing()
                throws Exception {
            assertFalse(repository.delete(4242));
        }

        @Test
        void onlyTheChosenScanGoes() throws Exception {
            long keep = repository.save(singleHost());
            long drop = repository.save(singleHost());
            assertNotEquals(keep, drop);

            repository.delete(drop);

            assertEquals(1, repository.count());
            assertTrue(repository.load(keep).isPresent());
        }
    }

    // ------------------------------------------------------------------ helpers

    private void dropTable(String table) throws SQLException {
        execute("DROP TABLE " + table);
    }

    private void execute(String sql) throws SQLException {
        try (Connection connection = raw(); Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    private int rowCount(String table) throws SQLException {
        try (Connection connection = raw();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery("SELECT COUNT(*) FROM " + table)) {
            return rs.next() ? rs.getInt(1) : -1;
        }
    }

    private Connection raw() throws SQLException {
        return DriverManager.getConnection("jdbc:sqlite:" + databaseFile.toAbsolutePath());
    }
}