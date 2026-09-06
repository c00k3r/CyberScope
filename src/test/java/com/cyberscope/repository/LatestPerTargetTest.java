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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code latestPerTarget} -- the dashboard's spine.
 *
 * <p>The interesting test here is {@link #onlyTheNewestRowSurvives}. The obvious
 * way to write this query is {@code GROUP BY target HAVING MAX(started_at)},
 * which SQLite accepts and most other engines reject: it permits a bare column
 * reference outside the aggregate and returns that column from an
 * <b>arbitrary</b> row of the group. The result is a query that usually looks
 * right, and occasionally returns one scan's id beside another scan's timestamp
 * -- loading the wrong scan while displaying the right date. Nothing errors.
 */
class LatestPerTargetTest {

    @TempDir
    Path directory;

    private ScanRepository repository;

    @BeforeEach
    void setUp() throws Exception {
        repository = new ScanRepository(new DatabaseManager(directory.resolve("test.db")));
    }

    // ------------------------------------------------------------- fixtures

    private static ScanOutcome scan(String target, Instant when, int... openPorts) {
        List<Port> ports = java.util.Arrays.stream(openPorts)
                .mapToObj(number -> new Port(number, Protocol.TCP, PortState.OPEN, "syn-ack",
                        new Service("http", "nginx", "1.24.0", "", List.of(),
                                    DetectionMethod.PROBED, 10)))
                .toList();
        NmapRunResult run = new NmapRunResult(
                new ValidatedTarget(target, TargetKind.IPV4, 1), ScanType.QUICK,
                List.of("nmap", "-sV", target), "<nmaprun/>", when,
                Duration.ofMillis(6000), "");
        return new ScanOutcome(run,
                List.of(new Host(target, "", HostState.UP, ports, List.of())));
    }

    // ----------------------------------------------------------------- tests

    @Test
    @DisplayName("one row per target, however many times it was scanned")
    void oneRowPerTarget() throws Exception {
        Instant base = Instant.parse("2026-09-01T09:00:00Z");
        for (int i = 0; i < 9; i++) {
            repository.save(scan("127.0.0.1", base.plus(Duration.ofHours(i)), 80));
        }
        repository.save(scan("10.0.0.5", base, 22));

        List<ScanSummary> latest = repository.latestPerTarget(40);
        assertAll(
                () -> assertEquals(2, latest.size(),
                        "a target scanned nine times must contribute one row, or the "
                      + "host you have been working on dominates the whole dashboard"),
                () -> assertEquals(10, repository.count(), "all nine are still stored"));
    }

    @Test
    @DisplayName("the row returned is the newest scan, with ITS id")
    void onlyTheNewestRowSurvives() throws Exception {
        Instant old = Instant.parse("2026-09-01T09:00:00Z");
        Instant recent = Instant.parse("2026-09-05T09:00:00Z");

        long oldId = repository.save(scan("127.0.0.1", old, 80));
        long newId = repository.save(scan("127.0.0.1", recent, 80, 443, 8080));

        ScanSummary row = repository.latestPerTarget(40).get(0);
        assertAll(
                () -> assertEquals(newId, row.id(), "wrong scan id for the newest row"),
                () -> assertEquals(recent, row.startedAt(), "wrong timestamp"),
                () -> assertEquals(3, row.openPortCount(),
                        "the port count came from a different row than the id -- "
                      + "this is exactly what a bare-column GROUP BY produces"),
                () -> assertTrue(oldId != newId));
    }

    @Test
    @DisplayName("two scans in the same second still resolve to one, deterministically")
    void identicalTimestampsAreBrokenById() throws Exception {
        Instant sameMoment = Instant.parse("2026-09-05T09:00:00Z");
        repository.save(scan("127.0.0.1", sameMoment, 80));
        long second = repository.save(scan("127.0.0.1", sameMoment, 80, 443));

        List<ScanSummary> latest = repository.latestPerTarget(40);
        assertAll(
                () -> assertEquals(1, latest.size()),
                () -> assertEquals(second, latest.get(0).id(),
                        "with equal timestamps the higher id wins, so a script that "
                      + "saves twice inside a second gets a stable answer"));
    }

    @Test
    @DisplayName("targets are ordered newest first")
    void newestTargetFirst() throws Exception {
        repository.save(scan("oldest", Instant.parse("2026-09-01T09:00:00Z"), 80));
        repository.save(scan("newest", Instant.parse("2026-09-05T09:00:00Z"), 80));
        repository.save(scan("middle", Instant.parse("2026-09-03T09:00:00Z"), 80));

        assertEquals(List.of("newest", "middle", "oldest"),
                repository.latestPerTarget(40).stream().map(ScanSummary::target).toList());
    }

    @Test
    @DisplayName("the limit caps targets, not scans")
    void limitAppliesToTargets() throws Exception {
        Instant base = Instant.parse("2026-09-01T09:00:00Z");
        for (int target = 0; target < 6; target++) {
            for (int repeat = 0; repeat < 3; repeat++) {
                repository.save(scan("10.0.0." + target,
                        base.plus(Duration.ofHours(target * 3L + repeat)), 80));
            }
        }
        assertAll(
                () -> assertEquals(18, repository.count()),
                () -> assertEquals(6, repository.latestPerTarget(40).size()),
                () -> assertEquals(2, repository.latestPerTarget(2).size(),
                        "the limit must cut distinct targets, not rows scanned"));
    }

    @Test
    @DisplayName("an empty database returns an empty list, not an error")
    void emptyDatabaseIsFine() throws Exception {
        assertTrue(repository.latestPerTarget(40).isEmpty());
    }
}
