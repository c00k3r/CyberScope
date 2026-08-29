package com.cyberscope.service.vuln;

import com.cyberscope.model.Cpe;
import com.cyberscope.model.DetectionMethod;
import com.cyberscope.model.Host;
import com.cyberscope.model.HostState;
import com.cyberscope.model.MappingOutcome;
import com.cyberscope.model.MatchPrecision;
import com.cyberscope.model.Port;
import com.cyberscope.model.PortState;
import com.cyberscope.model.Protocol;
import com.cyberscope.model.Service;
import com.cyberscope.model.Severity;
import com.cyberscope.model.VersionRange;
import com.cyberscope.model.VulnAssessment;
import com.cyberscope.model.Vulnerability;
import com.cyberscope.repository.CveLookup;
import com.cyberscope.repository.CveMatchRow;
import com.cyberscope.repository.RepositoryException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VulnMatchingTest {

    // ------------------------------------------------------------- fixtures

    private static Cpe cpe(String text) {
        return Cpe.parse(text).orElseThrow();
    }

    /** An applicability row with a pinned version. */
    private static CveMatchRow exact(String cveId, String vendor, String product,
                                     String version, double score, String severity) {
        return row(cveId, vendor, product, score, severity, VersionRange.exactly(version));
    }

    /** An applicability row with a wildcard version and bounds. */
    private static CveMatchRow ranged(String cveId, String vendor, String product,
                                      String startIncl, String endIncl,
                                      double score, String severity) {
        return row(cveId, vendor, product, score, severity,
                new VersionRange("*", startIncl, null, endIncl, null));
    }

    /** An applicability row claiming every version, with no bounds. */
    private static CveMatchRow allVersions(String cveId, String vendor, String product,
                                           double score, String severity) {
        return row(cveId, vendor, product, score, severity, VersionRange.allVersions());
    }

    private static CveMatchRow row(String cveId, String vendor, String product,
                                   double score, String severity, VersionRange range) {
        return new CveMatchRow(cveId, score, severity, "CVSS:3.1/AV:N", "3.1",
                Instant.parse("2024-07-01T00:00:00Z"), cveId + " description",
                vendor, product, range);
    }

    private static Service probed(String name, String product, String version, String... cpes) {
        return new Service(name, product, version, "", List.of(cpes), DetectionMethod.PROBED, 10);
    }

    private static Port open(int number, Service service) {
        return new Port(number, Protocol.TCP, PortState.OPEN, "syn-ack", service);
    }

    /**
     * An in-memory {@link CveLookup}.
     *
     * <p>The reason the interface exists. Every outcome below is reachable in
     * microseconds instead of requiring a 328 MB index, and the failure paths --
     * an empty index, a repository that throws -- can be produced on demand rather
     * than by corrupting a file.
     */
    private static final class FakeIndex implements CveLookup {
        private final List<CveMatchRow> rows = new ArrayList<>();
        private boolean populated = true;
        private RepositoryException failure;
        int lookupCalls;
        int populatedCalls;

        FakeIndex with(CveMatchRow... more) {
            rows.addAll(List.of(more));
            return this;
        }

        FakeIndex empty() {
            populated = false;
            return this;
        }

        FakeIndex broken(String message) {
            failure = new RepositoryException(message);
            return this;
        }

        @Override
        public List<CveMatchRow> findByProduct(String vendor, String product)
                throws RepositoryException {
            lookupCalls++;
            if (failure != null) {
                throw failure;
            }
            return rows.stream()
                       .filter(r -> r.vendor().equals(vendor) && r.product().equals(product))
                       .toList();
        }

        @Override
        public boolean isPopulated() throws RepositoryException {
            populatedCalls++;
            if (failure != null) {
                throw failure;
            }
            return populated;
        }
    }

    // ------------------------------------------------------------- matcher

    @Nested
    @DisplayName("the three ways NVD says a version is affected")
    class Precision {

        @Test
        @DisplayName("a pinned version matches by equality")
        void exactMatch() {
            List<Vulnerability> found = CpeMatcher.match(
                    cpe("cpe:/a:f5:nginx:1.24.0"),
                    List.of(exact("CVE-2025-23419", "f5", "nginx", "1.24.0", 6.5, "MEDIUM")));

            assertEquals(1, found.size());
            assertEquals(MatchPrecision.VERSION_EXACT, found.get(0).precision());
            assertEquals("= 1.24.0", found.get(0).matchedOn());
        }

        /**
         * THE test. NVD expresses regreSSHion as a wildcard version with bounds
         * 8.6 <= v <= 9.8. There is no row anywhere saying "openssh:9.6", so an
         * equality-only matcher cannot see unauthenticated remote root.
         */
        @Test
        @DisplayName("a range matches a version NVD never wrote down")
        void rangeMatchFindsRegresshion() {
            List<Vulnerability> found = CpeMatcher.match(
                    cpe("cpe:/a:openbsd:openssh:9.6"),
                    List.of(ranged("CVE-2024-6387", "openbsd", "openssh", "8.6", "9.8",
                                   8.1, "HIGH")));

            assertEquals(1, found.size());
            assertEquals("CVE-2024-6387", found.get(0).cveId());
            assertEquals(MatchPrecision.VERSION_RANGE, found.get(0).precision());
            assertEquals(">= 8.6, <= 9.8", found.get(0).matchedOn());
        }

        @Test
        @DisplayName("an unbounded wildcard matches everything, weakly")
        void allVersionsMatch() {
            List<Vulnerability> found = CpeMatcher.match(
                    cpe("cpe:/a:openbsd:openssh:9.6"),
                    List.of(allVersions("CVE-2007-2768", "openbsd", "openssh", 4.3, "MEDIUM")));

            assertEquals(1, found.size());
            assertEquals(MatchPrecision.ALL_VERSIONS, found.get(0).precision());
            assertTrue(found.get(0).isWeaklyMatched());
            assertEquals("all versions", found.get(0).matchedOn());
        }

        @Test
        void aVersionOutsideTheRangeDoesNotMatch() {
            assertTrue(CpeMatcher.match(
                    cpe("cpe:/a:openbsd:openssh:10.2"),
                    List.of(ranged("CVE-2024-6387", "openbsd", "openssh", "8.6", "9.8",
                                   8.1, "HIGH"))).isEmpty());
        }

        /**
         * Found by mutation testing, then settled by measuring the corpus.
         *
         * <p>Replacing string equality with a version comparison broke nothing, so
         * I went and counted: 9,175 of 64,450 distinct pinned version strings
         * (14.2%, in 3,929 groups) are the same release spelled differently.
         * {@code 1.0.1}, {@code 1.0(1)}, {@code 1.00.01} and {@code 1.0_1} are all
         * in one real group of nine. String equality would make a CVE filed under
         * any of those invisible to a host reporting another -- a false negative
         * created by punctuation alone.
         */
        @Test
        @DisplayName("punctuation and leading zeros do not hide a pinned match")
        void formattingVariantsOfOneReleaseMatch() {
            for (String asFiledByNvd : List.of("1.0.1", "1.0.01", "1.0_1", "1.0(1)",
                                               "1.00.01", "1.0-1")) {
                List<Vulnerability> found = CpeMatcher.match(
                        cpe("cpe:/a:acme:widget:1.0.1"),
                        List.of(exact("CVE-X", "acme", "widget", asFiledByNvd, 7.5, "HIGH")));

                assertEquals(1, found.size(),
                        "NVD filed this as " + asFiledByNvd + "; the host reports 1.0.1");
                assertEquals(MatchPrecision.VERSION_EXACT, found.get(0).precision());
            }
        }

        /**
         * The other half of the same rule. Loosening equality to a comparison must
         * not loosen it into "roughly similar": 1.24 and 1.24.0 differ by a token,
         * not by punctuation, and are different releases.
         */
        @Test
        @DisplayName("a genuinely different version still does not match")
        void loosenedMatchingDoesNotBecomeFuzzyMatching() {
            assertTrue(CpeMatcher.match(
                    cpe("cpe:/a:f5:nginx:1.24.0"),
                    List.of(exact("CVE-X", "f5", "nginx", "1.24", 5.0, "MEDIUM"))).isEmpty());
            assertTrue(CpeMatcher.match(
                    cpe("cpe:/a:openbsd:openssh:9.6"),
                    List.of(exact("CVE-X", "openbsd", "openssh", "9.6p1", 5.0, "MEDIUM"))).isEmpty());
        }

        @Test
        @DisplayName("an undecidable pinned comparison excludes rather than matches")
        void undecidablePinnedVersionDoesNotMatch() {
            assertTrue(CpeMatcher.match(
                    cpe("cpe:/a:acme:widget:1.0"),
                    List.of(exact("CVE-X", "acme", "widget", "-", 9.8, "CRITICAL"))).isEmpty(),
                    "VersionOrder returns null here; null must never widen a match");
        }

        @Test
        @DisplayName("a CPE with no concrete version matches nothing at all")
        void noVersionNoFindings() {
            assertTrue(CpeMatcher.match(
                    cpe("cpe:/a:openbsd:openssh"),
                    List.of(allVersions("CVE-2007-2768", "openbsd", "openssh", 4.3, "MEDIUM")))
                    .isEmpty(),
                    "without a version, an ALL_VERSIONS row would match and mean nothing");
        }

        /**
         * The caller fetches by (vendor, product), so in practice every row belongs
         * to the right product. A matcher that trusts that cannot be tested
         * against the day it stops being true.
         */
        @Test
        @DisplayName("rows for another product are ignored, not trusted")
        void wrongProductRowsAreFiltered() {
            List<Vulnerability> found = CpeMatcher.match(
                    cpe("cpe:/a:f5:nginx:1.24.0"),
                    List.of(exact("CVE-RIGHT", "f5", "nginx", "1.24.0", 6.5, "MEDIUM"),
                            exact("CVE-WRONG", "apache", "http_server", "1.24.0", 9.8, "CRITICAL")));

            assertEquals(1, found.size());
            assertEquals("CVE-RIGHT", found.get(0).cveId());
        }
    }

    @Nested
    @DisplayName("one CVE, several applicability statements")
    class Deduplication {

        /**
         * CVE-2024-6387 states itself twice: once as {@code < 4.4} and once as
         * {@code >= 8.6, <= 9.8}. Against 9.6 only the second applies -- but a
         * single CVE matching two rows must still appear once.
         */
        @Test
        @DisplayName("a CVE matching twice is reported once")
        void duplicatesCollapse() {
            List<Vulnerability> found = CpeMatcher.match(
                    cpe("cpe:/a:openbsd:openssh:9.6"),
                    List.of(ranged("CVE-2024-6387", "openbsd", "openssh", "8.6", "9.8", 8.1, "HIGH"),
                            ranged("CVE-2024-6387", "openbsd", "openssh", "9.0", "9.7", 8.1, "HIGH")));

            assertEquals(1, found.size());
        }

        /**
         * When the same CVE matches through both a strong and a weak statement,
         * the finding is as strong as its best evidence. Reporting it as
         * ALL_VERSIONS would understate it and push it below better-evidenced
         * findings in the report.
         */
        @Test
        @DisplayName("the strongest evidence wins, whatever order the rows arrive in")
        void strongestPrecisionSurvives() {
            CveMatchRow weak = allVersions("CVE-DUP", "openbsd", "openssh", 7.0, "HIGH");
            CveMatchRow strong = exact("CVE-DUP", "openbsd", "openssh", "9.6", 7.0, "HIGH");

            assertEquals(MatchPrecision.VERSION_EXACT,
                    CpeMatcher.match(cpe("cpe:/a:openbsd:openssh:9.6"),
                                     List.of(weak, strong)).get(0).precision());
            assertEquals(MatchPrecision.VERSION_EXACT,
                    CpeMatcher.match(cpe("cpe:/a:openbsd:openssh:9.6"),
                                     List.of(strong, weak)).get(0).precision());
        }
    }

    @Nested
    @DisplayName("report order")
    class Ordering {

        /**
         * Decided by looking at real data, not by taste.
         *
         * <p>For OpenSSH 9.6 the corpus contains CVE-2008-3844 at 9.3 HIGH -- a
         * 2008 compromise of Red Hat's build machines, filed against "all versions
         * of OpenSSH" -- and CVE-2024-6387 at 8.1 HIGH, which is regreSSHion.
         * Sorting by severity alone puts the sixteen-year-old packaging incident
         * above the unauthenticated remote root, verified against the live index.
         */
        @Test
        @DisplayName("evidence quality outranks severity")
        void weakMatchesSinkBelowStrongOnes() {
            List<Vulnerability> found = CpeMatcher.match(
                    cpe("cpe:/a:openbsd:openssh:9.6"),
                    List.of(allVersions("CVE-2008-3844", "openbsd", "openssh", 9.3, "HIGH"),
                            ranged("CVE-2024-6387", "openbsd", "openssh", "8.6", "9.8",
                                   8.1, "HIGH")));

            assertEquals(List.of("CVE-2024-6387", "CVE-2008-3844"),
                    found.stream().map(Vulnerability::cveId).toList(),
                    "the higher-scoring finding is the weaker one and must not lead");
        }

        @Test
        @DisplayName("within a band, severity leads")
        void severityOrdersWithinAband() {
            List<Vulnerability> found = CpeMatcher.match(
                    cpe("cpe:/a:openbsd:openssh:9.6"),
                    List.of(exact("CVE-MED", "openbsd", "openssh", "9.6", 5.0, "MEDIUM"),
                            exact("CVE-CRIT", "openbsd", "openssh", "9.6", 9.8, "CRITICAL"),
                            exact("CVE-HIGH", "openbsd", "openssh", "9.6", 7.5, "HIGH")));

            assertEquals(List.of("CVE-CRIT", "CVE-HIGH", "CVE-MED"),
                    found.stream().map(Vulnerability::cveId).toList());
        }

        @Test
        @DisplayName("an unscored CVE sorts below a scored one, not above")
        void unknownSeverityDoesNotLead() {
            List<Vulnerability> found = CpeMatcher.match(
                    cpe("cpe:/a:openbsd:openssh:9.6"),
                    List.of(row("CVE-UNSCORED", "openbsd", "openssh", 0.0, null,
                                VersionRange.exactly("9.6")),
                            exact("CVE-LOW", "openbsd", "openssh", "9.6", 3.1, "LOW")));

            assertEquals("CVE-LOW", found.get(0).cveId());
            assertEquals(Severity.UNKNOWN, found.get(1).severity());
        }
    }

    // ------------------------------------------------------------- outcomes

    @Nested
    @DisplayName("the four outcomes")
    class Outcomes {

        @Test
        @DisplayName("MAPPED: the lookup happened and found something")
        void mapped() {
            VulnAssessment result = new VulnerabilityService(
                    new FakeIndex().with(ranged("CVE-2024-6387", "openbsd", "openssh",
                                                "8.6", "9.8", 8.1, "HIGH")))
                    .assess(open(22, probed("ssh", "OpenSSH", "9.6",
                                            "cpe:/a:openbsd:openssh:9.6")));

            assertEquals(MappingOutcome.MAPPED, result.outcome());
            assertEquals(1, result.vulnerabilities().size());
            assertEquals(Severity.HIGH, result.worstSeverity());
            assertFalse(result.isConfirmedClean());
        }

        /**
         * The only empty result that means anything good. vsftpd 3.0.5 produces
         * exactly this against the real index: the product is known to NVD and
         * nothing is filed against that version.
         */
        @Test
        @DisplayName("MAPPED with nothing found is the only 'clean' there is")
        void mappedAndEmptyIsClean() {
            VulnAssessment result = new VulnerabilityService(
                    new FakeIndex().with(exact("CVE-OLD", "vsftpd_project", "vsftpd",
                                               "2.3.4", 9.8, "CRITICAL")))
                    .assess(open(21, probed("ftp", "vsftpd", "3.0.5",
                                            "cpe:/a:vsftpd_project:vsftpd:3.0.5")));

            assertEquals(MappingOutcome.MAPPED, result.outcome());
            assertTrue(result.vulnerabilities().isEmpty());
            assertTrue(result.isConfirmedClean());
            assertTrue(result.detail().contains("No CVEs are filed"), result.detail());
        }

        /**
         * The finding this whole version exists for. Nmap names nginx
         * {@code igor_sysoev} -- a vendor string that appears zero times in the
         * 1999-2026 corpus, because NVD files nginx under {@code f5}, with 41 CVEs.
         */
        @Test
        @DisplayName("UNRESOLVED: nothing is filed under that vendor at all")
        void unresolved() {
            VulnAssessment result = new VulnerabilityService(
                    new FakeIndex().with(exact("CVE-2025-23419", "f5", "nginx",
                                               "1.24.0", 6.5, "MEDIUM")))
                    .assess(open(80, probed("http", "nginx", "1.24.0",
                                            "cpe:/a:igor_sysoev:nginx:1.24.0")));

            assertEquals(MappingOutcome.UNRESOLVED, result.outcome());
            assertTrue(result.vulnerabilities().isEmpty());
            assertFalse(result.isConfirmedClean(),
                    "an unresolved lookup must never read as clean");
            assertTrue(result.detail().contains("igor_sysoev:nginx"), result.detail());
            assertTrue(result.detail().contains("no question was answered"), result.detail());
        }

        @Test
        @DisplayName("NOT_APPLICABLE: a table guess carries no CPE to look up")
        void tableServiceIsNotApplicable() {
            VulnAssessment result = new VulnerabilityService(new FakeIndex())
                    .assess(open(8080, new Service("http-proxy", "", "", "",
                                                   List.of(), DetectionMethod.TABLE, 3)));

            assertEquals(MappingOutcome.NOT_APPLICABLE, result.outcome());
            assertTrue(result.detail().contains("guessed from the port number"), result.detail());
            assertTrue(result.detail().contains("http-proxy"), result.detail());
        }

        /**
         * Also found by mutation testing. The previous table-service fixture had
         * no CPEs, so it reached {@code NOT_APPLICABLE} through the empty-CPE path
         * and never exercised the {@code isFingerprinted()} guard at all --
         * deleting the guard broke nothing.
         *
         * <p>This fixture is synthetic on purpose: Nmap does not currently publish
         * a CPE for a table lookup (verified -- port 8080 without {@code -sV}
         * yields {@code <service name="http-proxy" method="table" conf="3"/>},
         * no product, no version, no CPE). The guard encodes the rule anyway,
         * because "a guess from a port number is not evidence" is CyberScope's
         * decision, not a lucky property of Nmap's current output.
         */
        @Test
        @DisplayName("a table guess is refused even if it somehow carries a CPE")
        void tableEvidenceIsRefusedOnPrinciple() {
            VulnAssessment result = new VulnerabilityService(
                    new FakeIndex().with(exact("CVE-X", "openbsd", "openssh",
                                               "9.6", 9.8, "CRITICAL")))
                    .assess(open(22, new Service("ssh", "OpenSSH", "9.6", "",
                                                 List.of("cpe:/a:openbsd:openssh:9.6"),
                                                 DetectionMethod.TABLE, 3)));

            assertEquals(MappingOutcome.NOT_APPLICABLE, result.outcome());
            assertTrue(result.detail().contains("guessed from the port number"), result.detail());
        }

        @Test
        @DisplayName("NOT_APPLICABLE: probed, but Nmap reported no version")
        void probedWithoutVersionIsNotApplicable() {
            VulnAssessment result = new VulnerabilityService(new FakeIndex())
                    .assess(open(22, probed("ssh", "OpenSSH", "", "cpe:/a:openbsd:openssh")));

            assertEquals(MappingOutcome.NOT_APPLICABLE, result.outcome());
            assertTrue(result.detail().contains("no version"), result.detail());
        }

        @Test
        @DisplayName("NOT_APPLICABLE: no service element at all")
        void noServiceIsNotApplicable() {
            VulnAssessment result = new VulnerabilityService(new FakeIndex())
                    .assess(open(8098, Service.UNKNOWN));

            assertEquals(MappingOutcome.NOT_APPLICABLE, result.outcome());
            assertTrue(result.detail().contains("no service"), result.detail());
        }

        @Test
        @DisplayName("INDEX_UNAVAILABLE: there is no index to ask")
        void noIndexConfigured() {
            VulnAssessment result = new VulnerabilityService(null)
                    .assess(open(22, probed("ssh", "OpenSSH", "9.6",
                                            "cpe:/a:openbsd:openssh:9.6")));

            assertEquals(MappingOutcome.INDEX_UNAVAILABLE, result.outcome());
            assertTrue(result.detail().contains("--update-cve-index"), result.detail());
            assertFalse(result.isConfirmedClean());
        }

        @Test
        @DisplayName("INDEX_UNAVAILABLE: the index exists but is empty")
        void emptyIndex() {
            assertEquals(MappingOutcome.INDEX_UNAVAILABLE,
                    new VulnerabilityService(new FakeIndex().empty())
                            .assess(open(22, probed("ssh", "OpenSSH", "9.6",
                                                    "cpe:/a:openbsd:openssh:9.6")))
                            .outcome());
        }

        @Test
        @DisplayName("a repository failure is an index problem, not a host finding")
        void repositoryFailureDoesNotBecomeSilence() {
            VulnAssessment result = new VulnerabilityService(new FakeIndex().broken("disk gone"))
                    .assess(open(22, probed("ssh", "OpenSSH", "9.6",
                                            "cpe:/a:openbsd:openssh:9.6")));

            assertEquals(MappingOutcome.INDEX_UNAVAILABLE, result.outcome());
            assertTrue(result.detail().contains("disk gone"), result.detail());
        }
    }

    @Nested
    @DisplayName("assessing a host")
    class Hosts {

        @Test
        @DisplayName("only open ports are assessed")
        void closedPortsAreSkipped() {
            Host host = new Host("192.0.2.1", "lab", HostState.UP, List.of(
                    open(22, probed("ssh", "OpenSSH", "9.6", "cpe:/a:openbsd:openssh:9.6")),
                    new Port(23, Protocol.TCP, PortState.CLOSED, "reset", Service.UNKNOWN),
                    new Port(25, Protocol.TCP, PortState.FILTERED, "no-response", Service.UNKNOWN)),
                    List.of());

            Map<Port, VulnAssessment> results =
                    new VulnerabilityService(new FakeIndex()).assess(host);

            assertEquals(1, results.size(), "a closed port has no service to be vulnerable");
            assertEquals(22, results.keySet().iterator().next().number());
        }

        /**
         * The index check is one COUNT query. Running it per port would add a
         * round trip for every service on every host of a /24.
         */
        @Test
        @DisplayName("the index is checked once per service instance, not once per port")
        void indexCheckIsCached() {
            FakeIndex index = new FakeIndex();
            VulnerabilityService service = new VulnerabilityService(index);
            Host host = new Host("192.0.2.1", "lab", HostState.UP, List.of(
                    open(22, probed("ssh", "OpenSSH", "9.6", "cpe:/a:openbsd:openssh:9.6")),
                    open(80, probed("http", "nginx", "1.24.0", "cpe:/a:f5:nginx:1.24.0")),
                    open(443, probed("https", "nginx", "1.24.0", "cpe:/a:f5:nginx:1.24.0"))),
                    List.of());

            service.assess(host);

            assertEquals(1, index.populatedCalls);
            assertEquals(3, index.lookupCalls);
        }

        @Test
        @DisplayName("when a service carries several CPEs, one resolving is enough")
        void severalCpesOneResolves() {
            VulnAssessment result = new VulnerabilityService(
                    new FakeIndex().with(exact("CVE-REAL", "f5", "nginx", "1.24.0", 6.5, "MEDIUM")))
                    .assess(open(80, probed("http", "nginx", "1.24.0",
                                            "cpe:/a:igor_sysoev:nginx:1.24.0",
                                            "cpe:/a:f5:nginx:1.24.0")));

            assertEquals(MappingOutcome.MAPPED, result.outcome());
            assertEquals("f5", result.lookedUp().orElseThrow().vendor());
            assertEquals(1, result.vulnerabilities().size());
        }

        @Test
        @DisplayName("when no CPE resolves, the first one tried is named in the message")
        void severalCpesNoneResolve() {
            VulnAssessment result = new VulnerabilityService(new FakeIndex())
                    .assess(open(80, probed("http", "nginx", "1.24.0",
                                            "cpe:/a:igor_sysoev:nginx:1.24.0",
                                            "cpe:/a:nobody:nginx:1.24.0")));

            assertEquals(MappingOutcome.UNRESOLVED, result.outcome());
            assertTrue(result.detail().contains("igor_sysoev:nginx"), result.detail());
        }
    }

    @Nested
    @DisplayName("the assessment record itself")
    class Invariants {

        /**
         * The invariant that makes the outcome impossible to lose. A findings list
         * without its outcome is the shape every other scanner ships.
         */
        @Test
        @DisplayName("only a MAPPED assessment may carry findings")
        void nonMappedWithFindingsIsRefused() {
            List<Vulnerability> some = List.of(new Vulnerability(
                    "CVE-X", Severity.HIGH, 8.1, null, "3.1", null, "",
                    MatchPrecision.VERSION_RANGE, ">= 1, <= 2"));

            assertThrows(IllegalArgumentException.class, () -> new VulnAssessment(
                    MappingOutcome.UNRESOLVED, null, some, "contradiction"));
            assertThrows(IllegalArgumentException.class, () -> new VulnAssessment(
                    MappingOutcome.NOT_APPLICABLE, null, some, "contradiction"));
        }

        @Test
        @DisplayName("isConfirmedClean is false for every outcome but MAPPED")
        void cleanIsNarrow() {
            assertTrue(VulnAssessment.mapped(cpe("cpe:/a:x:y:1"), List.of()).isConfirmedClean());
            assertFalse(VulnAssessment.unresolved(cpe("cpe:/a:x:y:1")).isConfirmedClean());
            assertFalse(VulnAssessment.notApplicable("no version").isConfirmedClean());
            assertFalse(VulnAssessment.indexUnavailable("no index").isConfirmedClean());
        }

        @Test
        @DisplayName("only MAPPED is conclusive")
        void conclusiveIsNarrow() {
            assertTrue(MappingOutcome.MAPPED.isConclusive());
            assertFalse(MappingOutcome.UNRESOLVED.isConclusive());
            assertFalse(MappingOutcome.NOT_APPLICABLE.isConclusive());
            assertFalse(MappingOutcome.INDEX_UNAVAILABLE.isConclusive());
        }

        @Test
        void weakFindingsAreCounted() {
            VulnAssessment result = VulnAssessment.mapped(cpe("cpe:/a:openbsd:openssh:9.6"),
                    CpeMatcher.match(cpe("cpe:/a:openbsd:openssh:9.6"), List.of(
                            allVersions("CVE-2007-2768", "openbsd", "openssh", 4.3, "MEDIUM"),
                            ranged("CVE-2024-6387", "openbsd", "openssh", "8.6", "9.8",
                                   8.1, "HIGH"))));

            assertEquals(2, result.vulnerabilities().size());
            assertEquals(1, result.weaklyMatchedCount());
        }

        /**
         * An unscored CVE must not be presented as harmless. 71,464 CVEs in the
         * corpus have no CVSS data, usually because NVD has not analysed them yet.
         */
        @Test
        @DisplayName("no score means UNKNOWN, never NONE")
        void unscoredIsNotZero() {
            assertEquals(Severity.UNKNOWN, Severity.fromNvd(null));
            assertEquals(Severity.UNKNOWN, Severity.fromNvd(""));
            assertEquals(Severity.UNKNOWN, Severity.fromNvd("NOT_A_RATING"));
            assertEquals(Severity.NONE, Severity.fromNvd("NONE"));
            assertTrue(Severity.NONE.rank() > Severity.UNKNOWN.rank());
        }

        @Test
        void severityParsesNvdCasing() {
            assertEquals(Severity.CRITICAL, Severity.fromNvd("CRITICAL"));
            assertEquals(Severity.HIGH, Severity.fromNvd("high"));
            assertTrue(Severity.CRITICAL.isAtLeastHigh());
            assertTrue(Severity.HIGH.isAtLeastHigh());
            assertFalse(Severity.MEDIUM.isAtLeastHigh());
        }

        @Test
        void theNvdLinkIsBuiltFromTheId() {
            assertEquals("https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
                    new Vulnerability("CVE-2024-6387", Severity.HIGH, 8.1, null, "3.1",
                            null, "", MatchPrecision.VERSION_RANGE, "").nvdUrl());
        }
    }
}