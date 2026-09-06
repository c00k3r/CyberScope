package com.cyberscope.service.score;

import com.cyberscope.model.Coverage;
import com.cyberscope.model.Cpe;
import com.cyberscope.model.DetectionMethod;
import com.cyberscope.model.ExploitSignal;
import com.cyberscope.model.ExposureBand;
import com.cyberscope.model.KevStatus;
import com.cyberscope.model.MatchPrecision;
import com.cyberscope.model.Port;
import com.cyberscope.model.PortState;
import com.cyberscope.model.PostureAssessment;
import com.cyberscope.model.Protocol;
import com.cyberscope.model.Service;
import com.cyberscope.model.Severity;
import com.cyberscope.model.VulnAssessment;
import com.cyberscope.model.Vulnerability;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PostureScorerTest {

    // ------------------------------------------------------------- fixtures

    private static Port port(int number, String product, String version) {
        return new Port(number, Protocol.TCP, PortState.OPEN, "syn-ack",
                new Service("svc", product, version, "",
                        List.of("cpe:/a:vendor:" + product + ":" + version),
                        DetectionMethod.PROBED, 10));
    }

    private static Cpe cpe(String vendor, String product, String version) {
        return Cpe.parse("cpe:/a:" + vendor + ":" + product + ":" + version).orElseThrow();
    }

    private static Vulnerability finding(String id, Severity severity, ExploitSignal signal) {
        return finding(id, severity, signal, MatchPrecision.VERSION_RANGE);
    }

    private static Vulnerability finding(String id, Severity severity, ExploitSignal signal,
                                         MatchPrecision precision) {
        return new Vulnerability(id, severity, 7.5, "v", "3.1", null,
                id + " description", precision, ">= 1, <= 2", signal);
    }

    private static ExploitSignal kev() {
        return new ExploitSignal(0.9, 0.99, KevStatus.LISTED, null, null);
    }

    private static ExploitSignal ransomware() {
        return new ExploitSignal(0.9, 0.99, KevStatus.RANSOMWARE, null, null);
    }

    private static ExploitSignal epss(double score) {
        return new ExploitSignal(score, 0.5, KevStatus.NOT_LISTED, null, null);
    }

    private static ExploitSignal unscored() {
        return ExploitSignal.UNKNOWN;
    }

    /**
     * In KEV, but with no EPSS score -- the 4.7% of the index EPSS does not
     * cover. Reaches HIGH urgency on KEV membership alone, so it lands in the
     * same band as a high-EPSS finding and the tiebreak has to decide.
     */
    private static ExploitSignal kevUnscored() {
        return new ExploitSignal(null, null, KevStatus.LISTED, null, null);
    }

    /** A map builder that keeps insertion order, as the real service does. */
    private static final class Host {
        private final Map<Port, VulnAssessment> ports = new LinkedHashMap<>();

        Host mapped(int number, String product, String version, Vulnerability... found) {
            ports.put(port(number, product, version),
                    VulnAssessment.mapped(cpe("vendor", product, version), List.of(found)));
            return this;
        }

        Host unresolved(int number, String product, String version) {
            ports.put(port(number, product, version),
                    VulnAssessment.unresolved(cpe("vendor", product, version)));
            return this;
        }

        Host noVersion(int number) {
            ports.put(new Port(number, Protocol.TCP, PortState.OPEN, "syn-ack", Service.UNKNOWN),
                    VulnAssessment.notApplicable("no version"));
            return this;
        }

        PostureAssessment score() {
            return PostureScorer.score(ports);
        }
    }

    // ---------------------------------------------------------------- bands

    @Nested
    @DisplayName("the band comes from the strongest evidence, not from a count")
    class Bands {

        /**
         * The measurement this whole version exists because of. Against the real
         * index, mysql 8.0.36 has 73 findings and tops out at EPSS 0.0111, while
         * nginx 1.24.0 has 2, one of them in KEV at EPSS 1.0.
         *
         * <p>A weighted count ranks MySQL 36 times worse. It is not.
         */
        @Test
        @DisplayName("two quiet findings outrank seventy-three, when one is exploited")
        void oneExploitedBeatsSeventyThreeQuiet() {
            Vulnerability[] mysql = new Vulnerability[73];
            for (int i = 0; i < mysql.length; i++) {
                mysql[i] = finding("CVE-2024-" + (10000 + i), Severity.MEDIUM, epss(0.011));
            }

            ExposureBand quiet = new Host().mapped(3306, "mysql", "8.0.36", mysql).score().band();
            ExposureBand exploited = new Host()
                    .mapped(443, "nginx", "1.24.0", finding("CVE-2023-44487", Severity.HIGH, kev()))
                    .score().band();

            assertEquals(ExposureBand.LOW, quiet, "73 findings, none exploited");
            assertEquals(ExposureBand.HIGH, exploited, "2 findings, one exploited");
            assertTrue(exploited.rank() > quiet.rank(),
                    "the host with fewer findings must rank worse");
        }

        @Test
        @DisplayName("ransomware use is its own band")
        void ransomwareIsCritical() {
            assertEquals(ExposureBand.CRITICAL, new Host()
                    .mapped(445, "smb", "1.0", finding("CVE-X", Severity.HIGH, ransomware()))
                    .score().band());
        }

        @Test
        void kevAloneIsHigh() {
            assertEquals(ExposureBand.HIGH, new Host()
                    .mapped(80, "nginx", "1.24.0", finding("CVE-X", Severity.LOW, kev()))
                    .score().band(),
                    "a LOW-severity CVE that is being exploited is still HIGH exposure");
        }

        @Test
        void aVeryLikelyExploitIsHighWithoutKev() {
            assertEquals(ExposureBand.HIGH, new Host()
                    .mapped(22, "openssh", "9.6", finding("CVE-X", Severity.MEDIUM, epss(0.5)))
                    .score().band());
        }

        @Test
        void elevatedComesFromEpssOrCriticalSeverity() {
            assertEquals(ExposureBand.ELEVATED, new Host()
                    .mapped(22, "openssh", "9.6", finding("CVE-X", Severity.LOW, epss(0.1)))
                    .score().band());
            assertEquals(ExposureBand.ELEVATED, new Host()
                    .mapped(22, "openssh", "9.6", finding("CVE-Y", Severity.CRITICAL, unscored()))
                    .score().band());
        }

        @Test
        @DisplayName("findings with no exploitation evidence are LOW, however many")
        void quietFindingsAreLow() {
            assertEquals(ExposureBand.LOW, new Host()
                    .mapped(5432, "postgresql", "16.1",
                            finding("CVE-A", Severity.HIGH, epss(0.04)),
                            finding("CVE-B", Severity.HIGH, epss(0.02)))
                    .score().band());
        }

        @Test
        void nothingFiledIsClear() {
            PostureAssessment result = new Host().mapped(21, "vsftpd", "3.0.5").score();

            assertEquals(ExposureBand.CLEAR, result.band());
            assertTrue(result.isReassuring());
        }

        /**
         * An unbounded "all versions" match is the class that files a 2008 Red Hat
         * packaging incident against a 2024 OpenSSH. It is reported, but it must
         * not be able to set the band -- otherwise every OpenSSH host on earth
         * reads ELEVATED forever.
         */
        @Test
        @DisplayName("an all-versions match is reported but does not set the band")
        void weakMatchesDoNotVote() {
            PostureAssessment result = new Host()
                    .mapped(22, "openssh", "9.6",
                            finding("CVE-2008-3844", Severity.CRITICAL, kev(),
                                    MatchPrecision.ALL_VERSIONS))
                    .score();

            assertEquals(ExposureBand.LOW, result.band(),
                    "KEV plus CRITICAL, but matched only through an unbounded claim");
            assertEquals(1, result.findingCount(), "and it is still counted and shown");
        }
    }

    // ------------------------------------------------------------- coverage

    @Nested
    @DisplayName("coverage, and what it is allowed to change")
    class CoverageRules {

        /**
         * The asymmetry that makes the whole model honest. Finding an exploited
         * service does not become less true because other services could not be
         * checked -- but "we found nothing" depends entirely on how much was
         * looked at.
         */
        @Test
        @DisplayName("a positive finding survives poor coverage")
        void findingsAreNotDegraded() {
            PostureAssessment result = new Host()
                    .mapped(443, "nginx", "1.24.0", finding("CVE-X", Severity.HIGH, kev()))
                    .unresolved(80, "igor", "1.24.0")
                    .unresolved(8080, "unknown", "1.0")
                    .noVersion(9000)
                    .score();

            assertEquals(25, result.coverage().percent());
            assertFalse(result.coverage().isAdequate());
            assertEquals(ExposureBand.HIGH, result.band(),
                    "one checked service found something exploited; that stands");
        }

        @Test
        @DisplayName("but reassurance does not")
        void cleanIsDegraded() {
            PostureAssessment result = new Host()
                    .mapped(21, "vsftpd", "3.0.5")
                    .unresolved(80, "igor", "1.24.0")
                    .unresolved(8080, "unknown", "1.0")
                    .noVersion(9000)
                    .score();

            assertEquals(25, result.coverage().percent());
            assertEquals(ExposureBand.INDETERMINATE, result.band(),
                    "one clean service out of four is not a clean host");
            assertFalse(result.isReassuring());
        }

        @Test
        @DisplayName("LOW is degraded too -- it is also a form of reassurance")
        void lowIsDegraded() {
            PostureAssessment result = new Host()
                    .mapped(5432, "postgresql", "16.1",
                            finding("CVE-A", Severity.MEDIUM, epss(0.01)))
                    .unresolved(80, "igor", "1.24.0")
                    .unresolved(81, "igor", "1.24.0")
                    .unresolved(82, "igor", "1.24.0")
                    .score();

            assertEquals(ExposureBand.INDETERMINATE, result.band());
        }

        @Test
        @DisplayName("nothing checked at all is indeterminate, never clear")
        void nothingCheckedIsIndeterminate() {
            PostureAssessment result = new Host()
                    .unresolved(80, "igor", "1.24.0")
                    .noVersion(8080)
                    .score();

            assertEquals(0, result.coverage().checked());
            assertEquals(ExposureBand.INDETERMINATE, result.band(),
                    "CLEAR here would describe the index, not the host");
            assertFalse(result.isReassuring());
        }

        @Test
        @DisplayName("adequate coverage lets a clean result stand")
        void goodCoverageAllowsClear() {
            PostureAssessment result = new Host()
                    .mapped(21, "vsftpd", "3.0.5")
                    .mapped(25, "postfix", "3.8.5")
                    .mapped(53, "bind", "9.18.24")
                    .mapped(80, "nginx", "1.24.0")
                    .score();

            assertEquals(100, result.coverage().percent());
            assertEquals(ExposureBand.CLEAR, result.band());
        }

        @Test
        void aHostWithNothingOpenIsNotClear() {
            PostureAssessment empty = PostureScorer.score(Map.of());

            assertEquals(ExposureBand.INDETERMINATE, empty.band());
            assertEquals(0, empty.openPorts());
            assertFalse(empty.isReassuring());
        }

        @Test
        void coverageArithmetic() {
            assertEquals(79, new Coverage(11, 14).percent());
            assertEquals(3, new Coverage(11, 14).unchecked());
            assertFalse(new Coverage(11, 14).isAdequate());
            assertTrue(new Coverage(4, 5).isAdequate());
            assertEquals("11 of 14 services checked", new Coverage(11, 14).describe());
            assertEquals(1.0, Coverage.NONE.fraction(), 1e-9);
            assertThrows(IllegalArgumentException.class, () -> new Coverage(5, 4));
        }
    }

    // -------------------------------------------------------------- actions

    @Nested
    @DisplayName("recommended actions")
    class Actions {

        @Test
        @DisplayName("ranked by exploitation, not by severity")
        void exploitationOutranksSeverity() {
            PostureAssessment result = new Host()
                    .mapped(3306, "mysql", "8.0.36",
                            finding("CVE-QUIET-CRIT", Severity.CRITICAL, epss(0.001)))
                    .mapped(443, "nginx", "1.24.0",
                            finding("CVE-EXPLOITED", Severity.MEDIUM, kev()))
                    .score();

            assertEquals("CVE-EXPLOITED", result.ranked().get(0).vulnerability().cveId(),
                    "a MEDIUM being exploited beats a CRITICAL that is not");
            assertEquals("CVE-QUIET-CRIT", result.ranked().get(1).vulnerability().cveId());
        }

        @Test
        @DisplayName("an action names the service and the port, not just a CVE id")
        void actionsAreActionable() {
            var action = new Host()
                    .mapped(443, "nginx", "1.24.0",
                            finding("CVE-2023-44487", Severity.HIGH, kev()))
                    .score().ranked().get(0);

            assertEquals("443/tcp", action.where());
            assertTrue(action.describe().contains("nginx"), action.describe());
            assertTrue(action.describe().contains("443/tcp"), action.describe());
            assertTrue(action.describe().contains("actively exploited"), action.describe());
        }

        @Test
        void ransomwareIsCalledOutByName() {
            var action = new Host()
                    .mapped(445, "smb", "1.0", finding("CVE-X", Severity.HIGH, ransomware()))
                    .score().ranked().get(0);

            assertTrue(action.describe().contains("ransomware"), action.describe());
            assertEquals(ExposureBand.CRITICAL, action.urgency());
        }

        @Test
        void topActionsIsBounded() {
            Vulnerability[] many = new Vulnerability[20];
            for (int i = 0; i < many.length; i++) {
                many[i] = finding("CVE-" + i, Severity.MEDIUM, epss(0.01));
            }
            PostureAssessment result = new Host().mapped(80, "x", "1.0", many).score();

            assertEquals(20, result.ranked().size());
            assertEquals(3, result.topActions(3).size());
            assertEquals(20, result.topActions(50).size());
        }

        @Test
        @DisplayName("within a band, a measured EPSS outranks an unscored CVE")
        void unscoredFindingsSortBelowScoredOnes() {
            // Both are HIGH urgency: one because KEV lists it, one because its
            // EPSS is over 0.5. 18,261 of the index's 384,513 CVEs (4.7%) carry
            // no EPSS at all, so this ordering decides where a real user's eye
            // lands first, not some corner case.
            PostureAssessment result = new Host()
                    .mapped(443, "nginx", "1.24.0",
                            finding("CVE-UNSCORED", Severity.CRITICAL, kevUnscored()),
                            finding("CVE-MEASURED", Severity.LOW, epss(0.90)))
                    .score();

            assertEquals(List.of("CVE-MEASURED", "CVE-UNSCORED"),
                    result.ranked().stream()
                          .map(f -> f.vulnerability().cveId()).toList(),
                    "an unscored CVE must not sort as if it had scored 1.0 -- no "
                  + "score is an absence of evidence, not evidence of urgency");
        }

        @Test
        @DisplayName("the order is stable between identical runs")
        void orderIsTotal() {
            Host host = new Host().mapped(80, "x", "1.0",
                    finding("CVE-B", Severity.HIGH, epss(0.2)),
                    finding("CVE-A", Severity.HIGH, epss(0.2)));

            assertEquals(List.of("CVE-A", "CVE-B"),
                    host.score().ranked().stream()
                        .map(f -> f.vulnerability().cveId()).toList(),
                    "ties break on CVE id so a report can be diffed");
        }
    }

    // ------------------------------------------------------------ histogram

    @Nested
    @DisplayName("the numbers the dashboard draws")
    class Aggregates {

        @Test
        void countsAndHistogram() {
            PostureAssessment result = new Host()
                    .mapped(22, "openssh", "9.6",
                            finding("CVE-A", Severity.CRITICAL, kev()),
                            finding("CVE-B", Severity.HIGH, epss(0.01)),
                            finding("CVE-C", Severity.HIGH, epss(0.01)))
                    .mapped(80, "nginx", "1.24.0",
                            finding("CVE-D", Severity.MEDIUM, unscored()))
                    .unresolved(8080, "igor", "1.0")
                    .score();

            assertEquals(3, result.openPorts());
            assertEquals(4, result.findingCount());
            assertEquals(1, result.exploitedCount());
            assertEquals(1, result.count(Severity.CRITICAL));
            assertEquals(2, result.count(Severity.HIGH));
            assertEquals(1, result.count(Severity.MEDIUM));
            assertEquals(0, result.count(Severity.LOW));
            assertEquals(1, result.uncheckedCount());
        }

        @Test
        @DisplayName("an unscored CVE does not count as exploited")
        void unscoredIsNotExploited() {
            PostureAssessment result = new Host()
                    .mapped(80, "x", "1.0", finding("CVE-A", Severity.HIGH, unscored()))
                    .score();

            assertEquals(0, result.exploitedCount());
            assertEquals(ExposureBand.LOW, result.band());
        }

        @Test
        void bandSemantics() {
            assertTrue(ExposureBand.CRITICAL.needsAction());
            assertTrue(ExposureBand.HIGH.needsAction());
            assertFalse(ExposureBand.ELEVATED.needsAction());
            assertTrue(ExposureBand.CLEAR.isReassuring());
            assertFalse(ExposureBand.INDETERMINATE.isReassuring());
            assertFalse(ExposureBand.LOW.isReassuring());
            assertTrue(ExposureBand.CRITICAL.rank() > ExposureBand.HIGH.rank());
            assertTrue(ExposureBand.CLEAR.rank() > ExposureBand.INDETERMINATE.rank());
        }
    }
}
