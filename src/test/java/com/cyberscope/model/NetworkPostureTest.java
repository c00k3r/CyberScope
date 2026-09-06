package com.cyberscope.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("rolling every target's latest scan into one view")
class NetworkPostureTest {

    private static final Instant WHEN = Instant.parse("2026-09-01T10:00:00Z");

    // ------------------------------------------------------------- fixtures

    private static Port port(int number) {
        return new Port(number, Protocol.TCP, PortState.OPEN, "syn-ack",
                new Service("http", "nginx", "1.24.0", "", List.of(),
                            DetectionMethod.PROBED, 10));
    }

    private static ExploitSignal kev() {
        return new ExploitSignal(0.9, 0.99, KevStatus.LISTED, null, null);
    }

    private static ExploitSignal quiet() {
        return new ExploitSignal(0.001, 0.1, KevStatus.NOT_LISTED, null, null);
    }

    private static Vulnerability finding(String id, Severity severity, ExploitSignal signal) {
        return new Vulnerability(id, severity, 7.5, "AV:N/AC:L", "3.1", WHEN,
                "desc", MatchPrecision.VERSION_EXACT, "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*",
                signal);
    }

    /** A target with an explicit band, coverage and finding list. */
    private static TargetPosture target(String name, ExposureBand band, int checked,
                                        int examined, PostureTrend trend,
                                        Vulnerability... found) {
        Map<Severity, Integer> bySeverity = new EnumMap<>(Severity.class);
        List<RankedFinding> ranked = new ArrayList<>();
        int exploited = 0;
        for (Vulnerability v : found) {
            bySeverity.merge(v.severity(), 1, Integer::sum);
            if (v.isKnownExploited()) {
                exploited++;
            }
            ranked.add(new RankedFinding(port(443), "nginx 1.24.0", v));
        }
        ranked.sort(RankedFinding.ACTION_ORDER);
        PostureAssessment assessment = new PostureAssessment(band,
                new Coverage(checked, examined), examined, found.length, exploited,
                bySeverity, List.copyOf(ranked));
        return new TargetPosture(name, 1L, WHEN, assessment, trend);
    }

    // ----------------------------------------------------------------- tests

    @Test
    @DisplayName("no scans at all is INDETERMINATE, not CLEAR")
    void emptyIsNotClean() {
        NetworkPosture empty = NetworkPosture.empty();
        assertAll(
                () -> assertTrue(empty.isEmpty()),
                () -> assertEquals(ExposureBand.INDETERMINATE, empty.band(),
                        "an empty dashboard must not report a clean network"),
                () -> assertEquals(0, empty.findingCount()),
                () -> assertEquals(List.of(), empty.topActions(5)));
        assertEquals(empty.band(), NetworkPosture.of(List.of()).band());
    }

    @Nested
    @DisplayName("the network band is the worst target, never an average")
    class WorstWins {

        @Test
        void oneBadHostAmongManyGoodOnesSetsTheBand() {
            NetworkPosture posture = NetworkPosture.of(List.of(
                    target("a", ExposureBand.CLEAR, 5, 5, PostureTrend.UNCHANGED),
                    target("b", ExposureBand.CLEAR, 5, 5, PostureTrend.UNCHANGED),
                    target("c", ExposureBand.CLEAR, 5, 5, PostureTrend.UNCHANGED),
                    target("d", ExposureBand.CRITICAL, 5, 5, PostureTrend.WORSENED,
                            finding("CVE-BAD", Severity.HIGH, kev()))));

            assertEquals(ExposureBand.CRITICAL, posture.band(),
                    "three clean hosts must not dilute one that is being exploited "
                  + "-- an attacker needs one");
        }

        @Test
        @DisplayName("every target indeterminate means the network is too")
        void nothingAssessedIsNotClear() {
            NetworkPosture posture = NetworkPosture.of(List.of(
                    target("a", ExposureBand.INDETERMINATE, 0, 4, PostureTrend.FIRST_SCAN),
                    target("b", ExposureBand.INDETERMINATE, 1, 9, PostureTrend.FIRST_SCAN)));

            assertEquals(ExposureBand.INDETERMINATE, posture.band());
        }

        @Test
        @DisplayName("the worst target is listed first")
        void orderingPutsTheWorstOnTop() {
            NetworkPosture posture = NetworkPosture.of(List.of(
                    target("quiet", ExposureBand.LOW, 5, 5, PostureTrend.UNCHANGED),
                    target("exploited", ExposureBand.CRITICAL, 5, 5, PostureTrend.WORSENED,
                            finding("CVE-BAD", Severity.MEDIUM, kev())),
                    target("clean", ExposureBand.CLEAR, 5, 5, PostureTrend.UNCHANGED)));

            assertEquals(List.of("exploited", "quiet", "clean"),
                    posture.targets().stream().map(TargetPosture::target).toList());
        }

        @Test
        @DisplayName("a big pile of quiet findings does not outrank one exploited service")
        void countDoesNotDecideTheOrder() {
            // The shape measured in Part 1: mysql 73 findings / max EPSS 0.0111,
            // nginx 2 findings / EPSS 1.0000 and one KEV entry.
            Vulnerability[] many = new Vulnerability[73];
            for (int i = 0; i < many.length; i++) {
                many[i] = finding("CVE-QUIET-" + i, Severity.HIGH, quiet());
            }
            NetworkPosture posture = NetworkPosture.of(List.of(
                    target("mysql-box", ExposureBand.LOW, 5, 5, PostureTrend.UNCHANGED, many),
                    target("nginx-box", ExposureBand.HIGH, 5, 5, PostureTrend.UNCHANGED,
                            finding("CVE-HOT", Severity.MEDIUM, kev()))));

            assertEquals("nginx-box", posture.targets().get(0).target(),
                    "73 quiet findings must not outrank 1 that is being exploited");
            assertEquals(74, posture.findingCount(), "both still counted");
        }
    }

    @Nested
    @DisplayName("aggregation")
    class Aggregation {

        @Test
        void coverageSumsAcrossTargets() {
            NetworkPosture posture = NetworkPosture.of(List.of(
                    target("a", ExposureBand.CLEAR, 4, 4, PostureTrend.UNCHANGED),
                    target("b", ExposureBand.INDETERMINATE, 1, 5, PostureTrend.FIRST_SCAN),
                    target("c", ExposureBand.CLEAR, 3, 5, PostureTrend.UNCHANGED)));

            assertAll(
                    () -> assertEquals(8, posture.coverage().checked()),
                    () -> assertEquals(14, posture.coverage().examined()),
                    () -> assertEquals(57, posture.coverage().percent()),
                    () -> assertEquals(6, posture.unchecked(),
                            "the 'not checked' bar is the total, not a per-host figure"));
        }

        @Test
        void severityHistogramSumsAcrossTargets() {
            NetworkPosture posture = NetworkPosture.of(List.of(
                    target("a", ExposureBand.HIGH, 2, 2, PostureTrend.UNCHANGED,
                            finding("CVE-1", Severity.CRITICAL, kev()),
                            finding("CVE-2", Severity.HIGH, quiet())),
                    target("b", ExposureBand.LOW, 2, 2, PostureTrend.UNCHANGED,
                            finding("CVE-3", Severity.CRITICAL, quiet()))));

            assertAll(
                    () -> assertEquals(2, posture.count(Severity.CRITICAL)),
                    () -> assertEquals(1, posture.count(Severity.HIGH)),
                    () -> assertEquals(0, posture.count(Severity.LOW)),
                    () -> assertEquals(3, posture.findingCount()));
        }

        @Test
        @DisplayName("only bands that call for action are counted as needing attention")
        void attentionCountUsesTheBand() {
            NetworkPosture posture = NetworkPosture.of(List.of(
                    target("a", ExposureBand.CRITICAL, 2, 2, PostureTrend.WORSENED),
                    target("b", ExposureBand.HIGH, 2, 2, PostureTrend.UNCHANGED),
                    target("c", ExposureBand.CLEAR, 2, 2, PostureTrend.UNCHANGED),
                    target("d", ExposureBand.INDETERMINATE, 0, 2, PostureTrend.FIRST_SCAN)));

            assertEquals(2, posture.targetsNeedingAction());
        }
    }

    @Nested
    @DisplayName("recommended actions")
    class Actions {

        @Test
        @DisplayName("an action names the target it was found on")
        void actionsCarryTheirTarget() {
            NetworkPosture posture = NetworkPosture.of(List.of(
                    target("192.168.1.14", ExposureBand.HIGH, 1, 1, PostureTrend.UNCHANGED,
                            finding("CVE-2024-6387", Severity.HIGH, kev()))));

            NetworkPosture.Action action = posture.topActions(1).get(0);
            assertAll(
                    () -> assertEquals("192.168.1.14", action.target()),
                    () -> assertTrue(action.describe().contains("192.168.1.14"),
                            "a CVE id without a machine name is not an action: "
                          + action.describe()),
                    () -> assertTrue(action.describe().contains("CVE-2024-6387")));
        }

        @Test
        @DisplayName("actions are ranked across targets, not grouped by target")
        void rankingIsGlobal() {
            // The names matter. An earlier version of this test called them
            // "quiet-host" and "hot-host", and a mutation that sorted by target
            // BEFORE rank survived it -- "hot-host" sorts before "quiet-host"
            // alphabetically, so the grouped order and the ranked order happened
            // to agree and the test proved nothing. Here the alphabet and the
            // ranking disagree deliberately.
            NetworkPosture posture = NetworkPosture.of(List.of(
                    target("aaa-quiet-host", ExposureBand.LOW, 1, 1, PostureTrend.UNCHANGED,
                            finding("CVE-QUIET-A", Severity.CRITICAL, quiet()),
                            finding("CVE-QUIET-B", Severity.CRITICAL, quiet())),
                    target("zzz-hot-host", ExposureBand.HIGH, 1, 1, PostureTrend.UNCHANGED,
                            finding("CVE-HOT", Severity.LOW, kev()))));

            assertAll(
                    () -> assertEquals("CVE-HOT",
                            posture.topActions(1).get(0).finding().vulnerability().cveId(),
                            "the exploited LOW on one host outranks two quiet CRITICALs "
                          + "on another, whatever the hosts are called"),
                    () -> assertEquals("zzz-hot-host", posture.topActions(1).get(0).target(),
                            "the action list is one ranked queue, not a per-host grouping"));
        }

        @Test
        void topActionsIsBoundedAndNeverThrows() {
            NetworkPosture posture = NetworkPosture.of(List.of(
                    target("a", ExposureBand.HIGH, 1, 1, PostureTrend.UNCHANGED,
                            finding("CVE-1", Severity.HIGH, kev()),
                            finding("CVE-2", Severity.HIGH, quiet()))));
            assertAll(
                    () -> assertEquals(1, posture.topActions(1).size()),
                    () -> assertEquals(2, posture.topActions(2).size()),
                    () -> assertEquals(2, posture.topActions(500).size()),
                    () -> assertTrue(posture.topActions(0).isEmpty()));
        }

        @Test
        @DisplayName("a target with no findings contributes no actions")
        void cleanTargetsAddNothing() {
            NetworkPosture posture = NetworkPosture.of(List.of(
                    target("clean", ExposureBand.CLEAR, 3, 3, PostureTrend.UNCHANGED)));
            assertAll(
                    () -> assertTrue(posture.actions().isEmpty()),
                    () -> assertFalse(posture.isEmpty(), "a clean target is still a target"));
        }
    }
}
