package com.cyberscope.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A report that cannot say what data it was scored against is an assertion.
 */
class ReportProvenanceTest {

    private static final Instant NOW = Instant.parse("2026-09-06T12:00:00Z");

    private static ReportProvenance.Source source(String name, Duration age, int count) {
        return new ReportProvenance.Source(name, NOW.minus(age), count);
    }

    private static ReportProvenance fresh() {
        return new ReportProvenance(NOW,
                source("NVD corpus", Duration.ofHours(6), 384678),
                source("CISA KEV", Duration.ofHours(5), 1694),
                source("EPSS", Duration.ofHours(4), 366252),
                "0.7.0");
    }

    @Test
    @DisplayName("current data produces no warnings at all")
    void freshDataIsSilent() {
        ReportProvenance provenance = fresh();
        assertAll(
                () -> assertTrue(provenance.warnings(NOW).isEmpty()),
                () -> assertFalse(provenance.isDegraded(NOW)),
                () -> assertTrue(provenance.hasVulnerabilityData()),
                () -> assertTrue(provenance.hasExploitData()));
    }

    @Test
    @DisplayName("no index: the report must say its silence proves nothing")
    void noIndexOverridesEverythingElse() {
        ReportProvenance provenance = ReportProvenance.withoutIndex(NOW, "0.7.0");
        List<String> warnings = provenance.warnings(NOW);

        assertAll(
                () -> assertFalse(provenance.hasVulnerabilityData()),
                () -> assertEquals(1, warnings.size(),
                        "one clear sentence beats four: " + warnings),
                () -> assertTrue(warnings.get(0).contains("says nothing about the security"),
                        warnings.get(0)));
    }

    @Test
    @DisplayName("a stale corpus says a finding count is a floor, not a total")
    void staleCorpusExplainsTheConsequence() {
        ReportProvenance provenance = new ReportProvenance(NOW,
                source("NVD corpus", Duration.ofDays(21), 384678),
                source("CISA KEV", Duration.ofHours(5), 1694),
                source("EPSS", Duration.ofHours(4), 366252), "0.7.0");

        String warning = provenance.warnings(NOW).get(0);
        assertAll(
                () -> assertTrue(warning.contains("21 days"), warning),
                // A warning that states a fact without its consequence tells the
                // reader something is wrong but not what to do about it.
                () -> assertTrue(warning.contains("floor, not a total"), warning));
    }

    @Test
    @DisplayName("stale EPSS explains that every probability has drifted")
    void staleEpssNamesTheDrift() {
        ReportProvenance provenance = new ReportProvenance(NOW,
                source("NVD corpus", Duration.ofHours(2), 384678),
                source("CISA KEV", Duration.ofHours(2), 1694),
                source("EPSS", Duration.ofDays(9), 366252), "0.7.0");

        assertTrue(provenance.warnings(NOW).stream()
                        .anyMatch(w -> w.contains("recomputed daily") && w.contains("9 days")),
                provenance.warnings(NOW).toString());
    }

    @Test
    @DisplayName("missing exploitation data says findings fall back to CVSS order")
    void noExploitDataChangesTheRanking() {
        ReportProvenance provenance = new ReportProvenance(NOW,
                source("NVD corpus", Duration.ofHours(2), 384678), null, null, "0.7.0");

        assertAll(
                () -> assertFalse(provenance.hasExploitData()),
                () -> assertTrue(provenance.warnings(NOW).stream()
                                .anyMatch(w -> w.contains("CVSS severity alone")),
                        provenance.warnings(NOW).toString()));
    }

    @Test
    @DisplayName("KEV missing on its own is called out separately from EPSS")
    void feedsAreReportedIndependently() {
        ReportProvenance provenance = new ReportProvenance(NOW,
                source("NVD corpus", Duration.ofHours(2), 384678),
                null,
                source("EPSS", Duration.ofHours(2), 366252), "0.7.0");

        List<String> warnings = provenance.warnings(NOW);
        assertAll(
                () -> assertTrue(provenance.hasExploitData(), "EPSS alone still counts"),
                () -> assertTrue(warnings.stream().anyMatch(w -> w.contains("KEV")), warnings.toString()),
                () -> assertFalse(warnings.stream().anyMatch(w -> w.contains("EPSS scores were not")),
                        warnings.toString()));
    }

    @Test
    @DisplayName("the staleness boundary is inclusive at seven days")
    void stalenessBoundary() {
        assertAll(
                () -> assertFalse(source("x", Duration.ofDays(6), 1).isStale(NOW)),
                () -> assertTrue(source("x", Duration.ofDays(7), 1).isStale(NOW)));
    }

    @Test
    @DisplayName("a source timestamped in the future is not negative-aged")
    void futureTimestampIsClamped() {
        ReportProvenance.Source ahead =
                new ReportProvenance.Source("EPSS", NOW.plus(Duration.ofDays(3)), 10);
        assertAll(
                () -> assertEquals(Duration.ZERO, ahead.age(NOW)),
                () -> assertFalse(ahead.isStale(NOW)));
    }

    @Test
    @DisplayName("a source describes itself with its count and its date")
    void sourceDescribesItself() {
        String described = source("NVD corpus", Duration.ofHours(6), 384678)
                .describe(ZoneOffset.UTC);
        assertAll(
                () -> assertTrue(described.contains("384,678"), described),
                () -> assertTrue(described.contains("NVD corpus"), described),
                () -> assertTrue(described.contains("6 Sep 2026"), described));
    }

    @Test
    @DisplayName("a missing version is 'unknown', never blank or null")
    void versionAlwaysReadable() {
        assertAll(
                () -> assertTrue(new ReportProvenance(NOW, null, null, null, null)
                        .describe(ZoneOffset.UTC).contains("unknown")),
                () -> assertTrue(new ReportProvenance(NOW, null, null, null, "  ")
                        .describe(ZoneOffset.UTC).contains("unknown")));
    }
}
