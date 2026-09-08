package com.cyberscope.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What a report covering several targets is allowed to claim.
 */
class NetworkReportTest {

    private static final Instant NOW = Instant.parse("2026-09-07T12:00:00Z");

    private static TargetPosture target(String name, ExposureBand band, int checked,
                                        int examined, Duration age) {
        PostureAssessment assessment = new PostureAssessment(band,
                new Coverage(checked, examined), examined, 0, 0,
                new EnumMap<>(Severity.class), List.of());
        return new TargetPosture(name, 1L, NOW.minus(age), assessment,
                PostureTrend.FIRST_SCAN);
    }

    private static ReportProvenance fresh() {
        return new ReportProvenance(NOW,
                new ReportProvenance.Source("NVD corpus", NOW.minus(Duration.ofHours(3)), 384678),
                new ReportProvenance.Source("CISA KEV", NOW.minus(Duration.ofHours(3)), 1694),
                new ReportProvenance.Source("EPSS", NOW.minus(Duration.ofHours(3)), 366252),
                "0.7.0");
    }

    private static NetworkReport report(TargetPosture... targets) {
        return new NetworkReport(NetworkPosture.of(List.of(targets)), fresh(), NOW);
    }

    // ----------------------------------------------------------------- tests

    @Test
    @DisplayName("the headline scopes itself to what was scanned, never to 'the network'")
    void neverClaimsToCoverTheNetwork() {
        // CyberScope has no idea how many machines exist. It knows how many
        // targets someone typed. A host nobody has scanned is absent, not clear.
        String headline = report(
                target("10.0.0.1", ExposureBand.CLEAR, 4, 4, Duration.ofHours(1)),
                target("10.0.0.2", ExposureBand.CLEAR, 3, 3, Duration.ofHours(2))).headline();

        assertAll(
                () -> assertTrue(headline.contains("2 targets scanned"), headline),
                () -> assertFalse(headline.toLowerCase().contains("network"), headline),
                () -> assertTrue(headline.contains("7 of 7"), headline));
    }

    @Test
    @DisplayName("the first caveat says a never-scanned host is absent, not clear")
    void absenceIsNotSafety() {
        List<String> caveats = report(
                target("10.0.0.1", ExposureBand.CLEAR, 4, 4, Duration.ofHours(1))).caveats(NOW);

        assertTrue(caveats.get(0).contains("not counted as clear"),
                "the leading caveat must close the absence-equals-safety reading: "
              + caveats.get(0));
    }

    @Test
    @DisplayName("stale targets are named individually, not counted")
    void staleTargetsAreNamed() {
        // "2 targets are stale" tells a reader a number. Naming them tells them
        // which machine to re-scan.
        NetworkReport report = report(
                target("fresh-host", ExposureBand.CLEAR, 2, 2, Duration.ofHours(2)),
                target("old-host", ExposureBand.CLEAR, 2, 2, Duration.ofDays(30)));

        assertAll(
                () -> assertEquals(1, report.staleTargets(NOW).size()),
                () -> assertTrue(report.caveats(NOW).stream()
                                .anyMatch(c -> c.contains("old-host") && c.contains("30 days")),
                        report.caveats(NOW).toString()),
                () -> assertTrue(report.caveats(NOW).stream()
                                .noneMatch(c -> c.contains("fresh-host")),
                        "a fresh host must not be listed as stale"));
    }

    @Test
    @DisplayName("the oldest scan is what dates the report")
    void oldestTargetIsIdentified() {
        NetworkReport report = report(
                target("recent", ExposureBand.CLEAR, 2, 2, Duration.ofHours(1)),
                target("ancient", ExposureBand.CLEAR, 2, 2, Duration.ofDays(40)),
                target("middling", ExposureBand.CLEAR, 2, 2, Duration.ofDays(3)));

        assertAll(
                () -> assertEquals("ancient", report.oldest().orElseThrow().target()),
                () -> assertEquals(Duration.ofDays(40).minus(Duration.ofHours(1)),
                        report.ageSpread()));
    }

    @Test
    @DisplayName("one busy host dominating the coverage figure is called out")
    void serviceWeightingIsDisclosed() {
        // 18 services on one host, 1 on another. "8 of 19 checked" is a statement
        // about the busy host wearing the costume of a network figure.
        NetworkReport report = report(
                target("busy", ExposureBand.INDETERMINATE, 7, 18, Duration.ofHours(1)),
                target("quiet", ExposureBand.CLEAR, 1, 1, Duration.ofHours(1)));

        assertAll(
                () -> assertEquals("busy", report.dominantTarget().orElseThrow().target()),
                () -> assertTrue(report.caveats(NOW).stream()
                                .anyMatch(c -> c.contains("weighted by service count")
                                        && c.contains("busy")),
                        report.caveats(NOW).toString()));
    }

    @Test
    @DisplayName("evenly sized targets produce no weighting caveat")
    void noWeightingWarningWhenNobodyDominates() {
        NetworkReport report = report(
                target("a", ExposureBand.CLEAR, 3, 3, Duration.ofHours(1)),
                target("b", ExposureBand.CLEAR, 3, 3, Duration.ofHours(1)),
                target("c", ExposureBand.CLEAR, 3, 3, Duration.ofHours(1)));

        assertAll(
                () -> assertTrue(report.dominantTarget().isEmpty()),
                () -> assertTrue(report.caveats(NOW).stream()
                                .noneMatch(c -> c.contains("weighted by service count")),
                        "a warning that appears when it does not apply stops being read"));
    }

    @Test
    @DisplayName("the worst target's band is the network band")
    void worstTargetSetsTheBand() {
        NetworkReport report = report(
                target("a", ExposureBand.CLEAR, 3, 3, Duration.ofHours(1)),
                target("b", ExposureBand.CRITICAL, 3, 3, Duration.ofHours(1)),
                target("c", ExposureBand.CLEAR, 3, 3, Duration.ofHours(1)));

        assertAll(
                () -> assertEquals(ExposureBand.CRITICAL, report.band()),
                () -> assertEquals("b", report.targets().get(0).target()));
    }

    @Test
    @DisplayName("no scans at all says so rather than reporting a clean network")
    void emptyReportIsHonest() {
        NetworkReport empty = new NetworkReport(NetworkPosture.empty(), fresh(), NOW);
        assertAll(
                () -> assertTrue(empty.headline().contains("No scans yet"), empty.headline()),
                () -> assertEquals(ExposureBand.INDETERMINATE, empty.band()),
                () -> assertEquals(Duration.ZERO, empty.ageSpread()));
    }

    @Test
    @DisplayName("a single target has no age spread")
    void oneTargetHasNoSpread() {
        assertEquals(Duration.ZERO,
                report(target("only", ExposureBand.CLEAR, 1, 1, Duration.ofDays(5)))
                        .ageSpread());
    }

    @Test
    @DisplayName("provenance is mandatory here too")
    void provenanceRequired() {
        org.junit.jupiter.api.Assertions.assertThrows(NullPointerException.class,
                () -> new NetworkReport(NetworkPosture.empty(), null, NOW));
    }
}
