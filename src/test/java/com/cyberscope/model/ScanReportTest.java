package com.cyberscope.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("what a report is allowed to say")
class ScanReportTest {

    private static final Instant NOW = Instant.parse("2026-09-06T12:00:00Z");
    private static final Instant SCANNED = NOW.minus(Duration.ofHours(2));

    // ------------------------------------------------------------- fixtures

    private static ExploitSignal kev() {
        return new ExploitSignal(0.9, 0.99, KevStatus.LISTED, null, null);
    }

    private static Vulnerability finding(String id, Severity severity) {
        return new Vulnerability(id, severity, 7.5, "AV:N", "3.1", SCANNED, "desc",
                MatchPrecision.VERSION_EXACT, "cpe", kev());
    }

    private static Port port(int number) {
        return new Port(number, Protocol.TCP, PortState.OPEN, "syn-ack",
                new Service("http", "nginx", "1.24.0", "", List.of(),
                            DetectionMethod.PROBED, 10));
    }

    private static PostureAssessment assessment(ExposureBand band, int checked, int examined,
                                                Vulnerability... found) {
        Map<Severity, Integer> bySeverity = new EnumMap<>(Severity.class);
        List<RankedFinding> ranked = new ArrayList<>();
        for (Vulnerability v : found) {
            bySeverity.merge(v.severity(), 1, Integer::sum);
            ranked.add(new RankedFinding(port(443), "f5:nginx 1.24.0", v));
        }
        return new PostureAssessment(band, new Coverage(checked, examined), examined,
                found.length, found.length, bySeverity, List.copyOf(ranked));
    }

    private static ReportProvenance freshProvenance() {
        return new ReportProvenance(NOW,
                new ReportProvenance.Source("NVD corpus", NOW.minus(Duration.ofHours(6)), 384678),
                new ReportProvenance.Source("CISA KEV", NOW.minus(Duration.ofHours(5)), 1694),
                new ReportProvenance.Source("EPSS", NOW.minus(Duration.ofHours(4)), 366252),
                "0.7.0");
    }

    private static ScanReport report(PostureAssessment assessment, ReportProvenance provenance) {
        return new ScanReport("192.168.1.14", 7L, SCANNED, ScanType.QUICK,
                List.of("nmap", "-sV", "192.168.1.14"), assessment, List.of(), provenance);
    }

    // ----------------------------------------------------------------- tests

    @Test
    @DisplayName("a report cannot be built without provenance")
    void provenanceIsMandatory() {
        // Without it there is no way to reproduce the report, and no way to tell
        // it apart from a later one scored against different data.
        assertThrows(NullPointerException.class, () -> new ScanReport(
                "192.168.1.14", 7L, SCANNED, ScanType.QUICK, List.of("nmap"),
                assessment(ExposureBand.CLEAR, 4, 4), List.of(), null));
    }

    @Nested
    @DisplayName("the headline never states a finding count without coverage")
    class Headline {

        @Test
        void findingsAlwaysCarryTheirScope() {
            String headline = report(assessment(ExposureBand.HIGH, 6, 8,
                    finding("CVE-1", Severity.HIGH),
                    finding("CVE-2", Severity.MEDIUM)), freshProvenance()).headline();

            assertAll(
                    () -> assertTrue(headline.contains("2 findings"), headline),
                    () -> assertTrue(headline.contains("6 of 8"), headline),
                    () -> assertTrue(headline.contains("75%"), headline),
                    () -> assertTrue(headline.startsWith("HIGH"), headline));
        }

        @Test
        @DisplayName("a clean result still states how much was looked at")
        void nothingFoundIsNotTheWholeSentence() {
            String headline = report(assessment(ExposureBand.CLEAR, 8, 8), freshProvenance())
                    .headline();
            assertAll(
                    () -> assertTrue(headline.contains("nothing found"), headline),
                    () -> assertTrue(headline.contains("8 of 8"), headline),
                    () -> assertTrue(headline.contains("100%"), headline));
        }

        @Test
        @DisplayName("an indeterminate report leads with what could NOT be checked")
        void indeterminateLeadsWithCoverage() {
            // 2 of 9 checked. A finding count from a fifth of a host is not the
            // headline, and putting it first would be the single-number problem
            // wearing a different hat.
            String headline = report(assessment(ExposureBand.INDETERMINATE, 2, 9,
                    finding("CVE-1", Severity.HIGH)), freshProvenance()).headline();

            assertAll(
                    () -> assertTrue(headline.startsWith("INDETERMINATE"), headline),
                    () -> assertTrue(headline.indexOf("2 of 9") < headline.indexOf("1 finding"),
                            "coverage must come before the count: " + headline),
                    () -> assertTrue(headline.contains("22%"), headline));
        }

        @Test
        void singularReadsCorrectly() {
            String headline = report(assessment(ExposureBand.HIGH, 4, 4,
                    finding("CVE-1", Severity.HIGH)), freshProvenance()).headline();
            assertAll(
                    () -> assertTrue(headline.contains("1 finding"), headline),
                    () -> assertFalse(headline.contains("1 findings"), headline));
        }
    }

    @Nested
    @DisplayName("the recorded command")
    class Command {

        @Test
        @DisplayName("the -oX temp path is stripped")
        void outputPathIsRemoved() {
            ScanReport report = new ScanReport("127.0.0.1", 1L, SCANNED, ScanType.QUICK,
                    List.of("nmap", "-sV", "-T4", "-F", "-oX",
                            "/tmp/cyberscope-scan-17234220050205854625.xml", "127.0.0.1"),
                    assessment(ExposureBand.CLEAR, 1, 1), List.of(), freshProvenance());

            assertAll(
                    () -> assertEquals("nmap -sV -T4 -F 127.0.0.1", report.commandLine()),
                    () -> assertFalse(report.commandLine().contains("/tmp/"),
                            "a report gets forwarded; it must not carry a local path"),
                    () -> assertFalse(report.commandLine().contains("-oX")));
        }

        @Test
        @DisplayName("every output flag is handled, not just -oX")
        void allOutputFlagsAreStripped() {
            for (String flag : List.of("-oX", "-oN", "-oG", "-oA")) {
                List<String> cleaned = ScanReport.sanitiseCommand(
                        List.of("nmap", flag, "/tmp/out.xml", "10.0.0.1"));
                assertEquals(List.of("nmap", "10.0.0.1"), cleaned, flag);
            }
        }

        @Test
        @DisplayName("the scan flags a reader needs are kept")
        void diagnosticFlagsSurvive() {
            // -sV is why versions were probed at all. Stripping it would remove
            // the reader's ability to judge the evidence.
            List<String> cleaned = ScanReport.sanitiseCommand(
                    List.of("nmap", "-sV", "-T4", "--top-ports", "1000", "10.0.0.1"));
            assertEquals(List.of("nmap", "-sV", "-T4", "--top-ports", "1000", "10.0.0.1"),
                    cleaned);
        }

        @Test
        void aTrailingOutputFlagDoesNotOverrun() {
            assertEquals(List.of("nmap"), ScanReport.sanitiseCommand(List.of("nmap", "-oX")));
        }
    }

    @Nested
    @DisplayName("caveats: the reader's reasons to distrust this")
    class Caveats {

        @Test
        @DisplayName("a fresh, fully covered, fully fed report has none")
        void aCleanReportIsNotPaddedWithWarnings() {
            assertTrue(report(assessment(ExposureBand.CLEAR, 8, 8), freshProvenance())
                    .caveats(NOW).isEmpty(),
                    "warnings that appear on every report stop being read");
        }

        @Test
        @DisplayName("evidence age comes before index age")
        void scanAgeIsTheFirstCaveat() {
            // The provenance here is DELIBERATELY degraded. An earlier version of
            // this test used fresh feeds, which emit no warnings at all -- so
            // reordering the two blocks changed nothing and a mutation that put
            // index warnings first survived. An ordering test needs both orders
            // to be populated.
            ReportProvenance stale = new ReportProvenance(NOW,
                    new ReportProvenance.Source("NVD corpus",
                            NOW.minus(Duration.ofDays(20)), 384678),
                    new ReportProvenance.Source("CISA KEV",
                            NOW.minus(Duration.ofDays(20)), 1694),
                    new ReportProvenance.Source("EPSS",
                            NOW.minus(Duration.ofDays(20)), 366252), "0.7.0");

            ScanReport old = new ScanReport("192.168.1.14", 7L,
                    NOW.minus(Duration.ofDays(30)), ScanType.QUICK, List.of("nmap"),
                    assessment(ExposureBand.CLEAR, 4, 8), List.of(), stale);

            List<String> caveats = old.caveats(NOW);
            assertAll(
                    () -> assertTrue(caveats.size() >= 4, caveats.toString()),
                    // The scan is the evidence; the index is the interpretation.
                    // A reader who only reads one line gets the one about the
                    // evidence.
                    () -> assertTrue(caveats.get(0).contains("30 days"),
                            "the age of the evidence must lead: " + caveats.get(0)),
                    () -> assertTrue(caveats.get(1).contains("not checked"), caveats.get(1)),
                    () -> assertTrue(caveats.stream().anyMatch(c -> c.contains("corpus")
                                    || c.contains("floor, not a total")),
                            "index warnings must still be present, just later: " + caveats),
                    () -> assertTrue(
                            caveats.indexOf(caveats.get(0))
                                    < caveats.stream().filter(c -> c.contains("EPSS"))
                                             .findFirst().map(caveats::indexOf).orElse(99),
                            "scan age must precede index warnings: " + caveats));
        }

        @Test
        @DisplayName("unchecked services are called out even when nothing was found")
        void uncheckedServicesAreNeverSilent() {
            List<String> caveats = report(assessment(ExposureBand.INDETERMINATE, 2, 9),
                    freshProvenance()).caveats(NOW);

            assertTrue(caveats.stream().anyMatch(c -> c.contains("7 open services")),
                    "seven services nobody could look at must be stated: " + caveats);
        }

        @Test
        @DisplayName("no index means the report says its silence is meaningless")
        void noIndexIsStatedLoudly() {
            ScanReport report = report(assessment(ExposureBand.INDETERMINATE, 0, 5),
                    ReportProvenance.withoutIndex(NOW, "0.7.0"));

            assertTrue(report.caveats(NOW).stream()
                            .anyMatch(c -> c.contains("says nothing about the security")),
                    "a report with no index must not let absence read as safety: "
                  + report.caveats(NOW));
        }
    }

    @Test
    @DisplayName("findings keep the exploitation-first order the UI uses")
    void findingOrderMatchesTheUi() {
        // The report and the screen must not disagree about what matters most.
        PostureAssessment posture = assessment(ExposureBand.HIGH, 4, 4,
                finding("CVE-B", Severity.HIGH), finding("CVE-A", Severity.HIGH));
        assertEquals(posture.ranked(), report(posture, freshProvenance()).findings());
    }

    @Test
    @DisplayName("a clock ahead of ours does not produce a negative scan age")
    void futureScanIsClamped() {
        ScanReport future = new ScanReport("x", 1L, NOW.plus(Duration.ofDays(2)),
                ScanType.QUICK, List.of("nmap"), assessment(ExposureBand.CLEAR, 1, 1),
                List.of(), freshProvenance());
        assertAll(
                () -> assertEquals(Duration.ZERO, future.scanAge(NOW)),
                () -> assertFalse(future.scanIsStale(NOW)));
    }

    @Test
    @DisplayName("the authorisation notice is on every report and says CyberScope cannot verify")
    void authorisationNoticeIsUnambiguous() {
        assertAll(
                () -> assertTrue(ScanReport.AUTHORISATION_NOTICE.contains("cannot verify")),
                () -> assertTrue(ScanReport.AUTHORISATION_NOTICE.contains("unlawful")));
    }
}
