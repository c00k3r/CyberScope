package com.cyberscope.service.report;

import com.cyberscope.model.Cpe;
import com.cyberscope.model.DetectionMethod;
import com.cyberscope.model.MatchPrecision;
import com.cyberscope.model.Port;
import com.cyberscope.model.PortState;
import com.cyberscope.model.Protocol;
import com.cyberscope.model.Service;
import com.cyberscope.model.Severity;
import com.cyberscope.model.VulnAssessment;
import com.cyberscope.model.Vulnerability;
import com.cyberscope.repository.IndexMetadata;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VulnReportFormatterTest {

    private static final Instant NOW = Instant.parse("2026-08-29T12:00:00Z");

    private static IndexMetadata fresh() {
        return new IndexMetadata(NOW.minus(Duration.ofHours(6)), NOW,
                "https://example.invalid/feed", 384_513, 2_093_452, 1999, 2026);
    }

    private static Port port(int number, Service service) {
        return new Port(number, Protocol.TCP, PortState.OPEN, "syn-ack", service);
    }

    private static Service probed(String name, String product, String version, String cpe) {
        return new Service(name, product, version, "", List.of(cpe),
                           DetectionMethod.PROBED, 10);
    }

    private static Cpe cpe(String text) {
        return Cpe.parse(text).orElseThrow();
    }

    private static Vulnerability vuln(String id, Severity severity, double score,
                                      MatchPrecision precision, String matchedOn) {
        return new Vulnerability(id, severity, score, "CVSS:3.1/AV:N", "3.1",
                Instant.parse("2024-07-01T00:00:00Z"),
                id + " does something bad to a service.", precision, matchedOn);
    }

    private static String render(Map<Port, VulnAssessment> assessments,
                                 IndexMetadata index, boolean verbose) {
        return VulnReportFormatter.format(assessments, index, NOW, ZoneOffset.UTC, verbose);
    }

    /** The scan this project keeps coming back to: one nginx, two vendor spellings. */
    private static Map<Port, VulnAssessment> theNginxScan() {
        Map<Port, VulnAssessment> map = new LinkedHashMap<>();
        map.put(port(80, probed("http", "nginx", "1.24.0", "cpe:/a:igor_sysoev:nginx:1.24.0")),
                VulnAssessment.unresolved(cpe("cpe:/a:igor_sysoev:nginx:1.24.0")));
        map.put(port(443, probed("https", "nginx", "1.24.0", "cpe:/a:f5:nginx:1.24.0")),
                VulnAssessment.mapped(cpe("cpe:/a:f5:nginx:1.24.0"), List.of(
                        vuln("CVE-2023-44487", Severity.HIGH, 7.5,
                             MatchPrecision.VERSION_RANGE, ">= 1.9.5, <= 1.25.2"))));
        return map;
    }

    // ------------------------------------------------------------- the gap

    @Nested
    @DisplayName("what could not be checked")
    class Gaps {

        /**
         * The line the whole version exists for. A reader who stops after the
         * findings must already have been told that part of the host was never
         * asked about -- so the warning precedes the first finding.
         */
        @Test
        @DisplayName("the unchecked warning appears before any finding")
        void warningComesFirst() {
            String text = render(theNginxScan(), fresh(), false);

            int warning = text.indexOf("could not be checked");
            int findings = text.indexOf("FINDINGS");
            assertTrue(warning >= 0, text);
            assertTrue(findings >= 0, text);
            assertTrue(warning < findings, "the gap must be stated before the findings");
        }

        /**
         * An earlier draft sorted every port into one list by severity. An
         * unresolved service has no severity, so it sank to the bottom -- exactly
         * backwards for a report arguing that a gap outranks a finding.
         */
        @Test
        @DisplayName("NOT CHECKED is its own section, above FINDINGS")
        void gapsHaveTheirOwnSection() {
            String text = render(theNginxScan(), fresh(), false);

            assertTrue(text.contains("NOT CHECKED"), text);
            assertTrue(text.indexOf("NOT CHECKED") < text.indexOf("FINDINGS"), text);
        }

        @Test
        @DisplayName("both nginx vendor spellings appear, in different sections")
        void theTwoSpellingsAreVisible() {
            String text = render(theNginxScan(), fresh(), false);

            int unresolved = text.indexOf("igor_sysoev:nginx");
            int mapped = text.indexOf("f5:nginx");
            assertTrue(unresolved >= 0 && mapped >= 0, text);
            assertTrue(unresolved < text.indexOf("FINDINGS"),
                    "the CPE that failed belongs in NOT CHECKED");
            assertTrue(mapped > text.indexOf("FINDINGS"),
                    "the CPE that resolved belongs in FINDINGS");
        }

        @Test
        @DisplayName("a table-detected service says why and what to do about it")
        void tableServiceExplainsItself() {
            Map<Port, VulnAssessment> one = new LinkedHashMap<>();
            one.put(port(8080, new Service("http-proxy", "", "", "", List.of(),
                                           DetectionMethod.TABLE, 3)),
                    VulnAssessment.notApplicable(
                            "The service was guessed from the port number (http-proxy),"
                            + " not probed. Re-run with service detection to change this."));

            String text = render(one, fresh(), false);

            assertTrue(text.contains("NO VERSION DETECTED"), text);
            assertTrue(text.contains("guessed from the port number"), text);
            assertTrue(text.contains("Re-run with service detection"), text);
        }

        @Test
        @DisplayName("with nothing to report, the header still says the index is there")
        void noOpenPorts() {
            String text = render(new LinkedHashMap<>(), fresh(), false);

            assertTrue(text.contains("384,513 CVEs"), text);
            assertTrue(text.contains("No open ports to assess"), text);
        }
    }

    // ------------------------------------------------------------- volume

    @Nested
    @DisplayName("keeping 303 findings readable")
    class Volume {

        private static Map<Port, VulnAssessment> mysqlWith(int howMany) {
            List<Vulnerability> many = new java.util.ArrayList<>();
            for (int i = 1; i <= howMany; i++) {
                many.add(vuln(String.format("CVE-2024-%05d", i), Severity.MEDIUM, 6.5,
                              MatchPrecision.VERSION_RANGE, ">= 8.0.0, <= 8.0.39"));
            }
            Map<Port, VulnAssessment> map = new LinkedHashMap<>();
            map.put(port(3306, probed("mysql", "MySQL", "8.0.36", "cpe:/a:oracle:mysql:8.0.36")),
                    VulnAssessment.mapped(cpe("cpe:/a:oracle:mysql:8.0.36"), many));
            return map;
        }

        /**
         * MySQL 8.0.36 really does return 73 findings from the real index. A
         * report that prints all 73 by default is a report nobody reads, and an
         * unread report is worth the same as no report.
         */
        @Test
        @DisplayName("the default view shows a few per port and counts the rest")
        void longListsAreTruncated() {
            String text = render(mysqlWith(73), fresh(), false);

            assertTrue(text.contains("73 found"), "the total must still be stated");
            assertTrue(text.contains("... 70 more"), text);
            assertTrue(text.contains("CVE-2024-00001"), "the first few are listed");
            assertFalse(text.contains("CVE-2024-00050"),
                    "the fiftieth is not, or this is a dump rather than a report");
        }

        @Test
        @DisplayName("--vulns lists every one of them")
        void verboseShowsEverything() {
            String text = render(mysqlWith(73), fresh(), true);

            assertTrue(text.contains("CVE-2024-00050"), "verbose must hide nothing");
            assertTrue(text.contains("CVE-2024-00073"), text);
            assertFalse(text.contains("Run with --vulns"),
                    "no point advertising the flag the reader already used");
        }

        @Test
        @DisplayName("truncation is signposted, not silent")
        void theFooterPointsAtTheFullList() {
            String text = render(mysqlWith(73), fresh(), false);

            assertTrue(text.contains("73 finding(s) in total"), text);
            assertTrue(text.contains("Run with --vulns"), text);
        }

        /**
         * An ALL_VERSIONS finding is NVD saying "every version ever", which for
         * OpenSSH means a 2008 Red Hat packaging incident and a rowhammer attack.
         * They are reported, but they never occupy one of the three default slots.
         */
        @Test
        @DisplayName("weak matches are counted but do not take a default slot")
        void allVersionsFindingsDoNotLead() {
            Map<Port, VulnAssessment> map = new LinkedHashMap<>();
            map.put(port(22, probed("ssh", "OpenSSH", "9.6", "cpe:/a:openbsd:openssh:9.6")),
                    VulnAssessment.mapped(cpe("cpe:/a:openbsd:openssh:9.6"), List.of(
                            vuln("CVE-2024-6387", Severity.HIGH, 8.1,
                                 MatchPrecision.VERSION_RANGE, ">= 8.6, <= 9.8"),
                            vuln("CVE-2008-3844", Severity.HIGH, 9.3,
                                 MatchPrecision.ALL_VERSIONS, "all versions"))));

            String text = render(map, fresh(), false);

            assertTrue(text.contains("CVE-2024-6387"), text);
            assertFalse(text.contains("CVE-2008-3844"),
                    "a 9.3 that NVD files against every version must not lead the list");
            assertTrue(text.contains("NVD files against every version"), text);
        }

        @Test
        @DisplayName("verbose labels the weak ones rather than hiding them")
        void verboseShowsWeakMatchesLabelled() {
            Map<Port, VulnAssessment> map = new LinkedHashMap<>();
            map.put(port(22, probed("ssh", "OpenSSH", "9.6", "cpe:/a:openbsd:openssh:9.6")),
                    VulnAssessment.mapped(cpe("cpe:/a:openbsd:openssh:9.6"), List.of(
                            vuln("CVE-2008-3844", Severity.HIGH, 9.3,
                                 MatchPrecision.ALL_VERSIONS, "all versions"))));

            String text = render(map, fresh(), true);

            assertTrue(text.contains("CVE-2008-3844"), text);
            assertTrue(text.contains("weak evidence"), text);
        }
    }

    // ------------------------------------------------------------- index

    @Nested
    @DisplayName("the index banner")
    class Banner {

        @Test
        @DisplayName("a clean service is reported as clean, and separately")
        void cleanIsItsOwnSection() {
            Map<Port, VulnAssessment> map = new LinkedHashMap<>();
            map.put(port(21, probed("ftp", "vsftpd", "3.0.5",
                                    "cpe:/a:vsftpd_project:vsftpd:3.0.5")),
                    VulnAssessment.mapped(cpe("cpe:/a:vsftpd_project:vsftpd:3.0.5"), List.of()));

            String text = render(map, fresh(), false);

            assertTrue(text.contains("LOOKED UP, NOTHING FILED"), text);
            assertTrue(text.contains("vsftpd_project:vsftpd 3.0.5"), text);
            assertFalse(text.contains("NOT CHECKED"),
                    "a clean lookup is not a gap and must not be filed as one");
        }

        /**
         * The corpus grew 584 CVEs in the one day between two builds made while
         * writing v0.5.0. A three-week-old index reporting "no findings" is
         * reporting on a world three weeks gone.
         */
        @Test
        @DisplayName("a stale index says so, next to the findings it qualifies")
        void stalenessIsWarnedAbout() {
            IndexMetadata old = new IndexMetadata(NOW.minus(Duration.ofDays(23)), NOW,
                    "https://example.invalid/feed", 384_513, 2_093_452, 1999, 2026);

            String text = render(theNginxScan(), old, false);

            assertTrue(text.contains("23 days old"), text);
            assertTrue(text.contains("STALE"), text);
            assertTrue(text.contains("not yet in this copy"),
                    "the warning must say what staleness does to the result");
        }

        @Test
        void aFreshIndexIsNotWarnedAbout() {
            String text = render(theNginxScan(), fresh(), false);

            assertFalse(text.contains("STALE"), text);
            assertFalse(text.contains("not yet in this copy"), text);
        }

        /**
         * No index is not "no vulnerabilities". Without this branch the report
         * would render an empty findings section and read as a clean bill of
         * health for a host nobody looked at.
         */
        @Test
        @DisplayName("with no index at all, nothing is claimed about the host")
        void noIndexClaimsNothing() {
            String text = render(theNginxScan(), null, false);

            assertTrue(text.contains("--update-cve-index"), text);
            assertTrue(text.contains("Nothing below is a statement about these services"),
                    text);
            assertFalse(text.contains("FINDINGS"),
                    "there can be no findings section without an index");
        }
    }
}