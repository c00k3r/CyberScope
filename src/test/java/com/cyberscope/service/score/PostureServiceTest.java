package com.cyberscope.service.score;

import com.cyberscope.model.DetectionMethod;
import com.cyberscope.model.ExploitSignal;
import com.cyberscope.model.ExposureBand;
import com.cyberscope.model.Host;
import com.cyberscope.model.HostState;
import com.cyberscope.model.KevStatus;
import com.cyberscope.model.NetworkPosture;
import com.cyberscope.model.Port;
import com.cyberscope.model.PortState;
import com.cyberscope.model.PostureAssessment;
import com.cyberscope.model.PostureTrend;
import com.cyberscope.model.Protocol;
import com.cyberscope.model.ScanType;
import com.cyberscope.model.Service;
import com.cyberscope.model.TargetPosture;
import com.cyberscope.model.VersionRange;
import com.cyberscope.repository.CveLookup;
import com.cyberscope.repository.CveMatchRow;
import com.cyberscope.repository.RepositoryException;
import com.cyberscope.service.scanner.NmapRunResult;
import com.cyberscope.service.scanner.ScanOutcome;
import com.cyberscope.service.vuln.VulnerabilityService;
import com.cyberscope.util.TargetKind;
import com.cyberscope.util.ValidatedTarget;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Re-scoring stored scans against the index as it stands today.
 *
 * <p>The behaviour under test is the v0.6.0 Part 3 decision: a stored scan keeps
 * its ports and version banners but not its findings, so the lookup runs again
 * every time the dashboard opens. The consequence worth testing explicitly is
 * {@link #aQuietScanBecomesUrgentWhenTheIndexChanges} -- the same stored scan,
 * scored twice against two states of the index, must give two different answers.
 * If it ever stops doing that, the schema-free design has silently become a
 * cache and the feature is gone.
 */
class PostureServiceTest {

    private static final Instant WHEN = Instant.parse("2026-09-01T10:00:00Z");

    // ------------------------------------------------------------- fixtures

    private static Port probed(int number, String product, String version, String cpe) {
        return new Port(number, Protocol.TCP, PortState.OPEN, "syn-ack",
                new Service("http", product, version, "", List.of(cpe),
                            DetectionMethod.PROBED, 10));
    }

    private static Port guessed(int number) {
        return new Port(number, Protocol.TCP, PortState.OPEN, "syn-ack",
                new Service("ftp", "", "", "", List.of(), DetectionMethod.TABLE, 3));
    }

    private static ScanOutcome scan(String target, List<Host> hosts) {
        NmapRunResult run = new NmapRunResult(
                new ValidatedTarget(target, TargetKind.IPV4, 1), ScanType.QUICK,
                List.of("nmap", "-sV", target), "<nmaprun/>", WHEN,
                Duration.ofMillis(6000), "");
        return new ScanOutcome(run, hosts);
    }

    private static ScanOutcome oneHost(String target, Port... ports) {
        return scan(target, List.of(
                new Host(target, "", HostState.UP, List.of(ports), List.of())));
    }

    /**
     * A finding that names the exact version.
     *
     * <p>{@code exactly}, not {@code allVersions}. The first draft of this
     * fixture used an unbounded range and every band came back LOW, which looked
     * like a bug in the scorer and was the scorer working: a finding matched only
     * through "this vendor says all versions are affected" is reported but does
     * not get a vote on the band. That is the rule that keeps a 2008 Red Hat
     * packaging incident off a 2024 OpenSSH. Pinned by
     * {@link #aWeaklyMatchedKevFindingStillDoesNotVote}.
     */
    private static CveMatchRow row(String cveId, String severity, ExploitSignal signal) {
        return new CveMatchRow(cveId, 7.5, severity, "AV:N/AC:L", "3.1", WHEN,
                "description", "f5", "nginx", VersionRange.exactly("1.24.0"), signal);
    }

    private static CveMatchRow weakRow(String cveId, ExploitSignal signal) {
        return new CveMatchRow(cveId, 9.8, "CRITICAL", "AV:N/AC:L", "3.1", WHEN,
                "description", "f5", "nginx", VersionRange.allVersions(), signal);
    }

    private static ExploitSignal kev() {
        return new ExploitSignal(0.9, 0.99, KevStatus.LISTED, null, null);
    }

    private static ExploitSignal quiet() {
        return new ExploitSignal(0.001, 0.05, KevStatus.NOT_LISTED, null, null);
    }

    /** An index whose contents can be swapped between two scorings. */
    private static final class FakeIndex implements CveLookup {
        private final List<CveMatchRow> rows = new ArrayList<>();

        FakeIndex with(CveMatchRow... more) {
            rows.addAll(List.of(more));
            return this;
        }

        @Override
        public List<CveMatchRow> findByProduct(String vendor, String product) {
            return rows.stream()
                       .filter(r -> r.vendor().equals(vendor) && r.product().equals(product))
                       .toList();
        }

        @Override
        public boolean isPopulated() {
            return true;
        }
    }

    private static PostureService serviceOver(CveLookup index) {
        return new PostureService(new VulnerabilityService(index));
    }

    // ----------------------------------------------------------------- tests

    @Test
    @DisplayName("the same stored scan changes verdict when the index does")
    void aQuietScanBecomesUrgentWhenTheIndexChanges() {
        ScanOutcome stored = oneHost("192.168.1.14",
                probed(443, "nginx", "1.24.0", "cpe:/a:f5:nginx:1.24.0"));

        PostureAssessment before = serviceOver(
                new FakeIndex().with(row("CVE-1", "MEDIUM", quiet()))).score(stored);

        // Same scan, same ports, same banners. Only the world moved: the CVE is
        // now in CISA KEV.
        PostureAssessment after = serviceOver(
                new FakeIndex().with(row("CVE-1", "MEDIUM", kev()))).score(stored);

        assertAll(
                () -> assertEquals(ExposureBand.LOW, before.band()),
                () -> assertEquals(ExposureBand.HIGH, after.band(),
                        "re-checking against today's index is the whole point of not "
                      + "persisting findings; if this stops changing, the feature is gone"),
                () -> assertEquals(before.findingCount(), after.findingCount(),
                        "the evidence did not change, only what is known about it"));
    }

    @Test
    @DisplayName("a KEV finding matched only by an 'all versions' claim still does not vote")
    void aWeaklyMatchedKevFindingStillDoesNotVote() {
        PostureAssessment assessment = serviceOver(
                new FakeIndex().with(weakRow("CVE-VAGUE", kev())))
                .score(oneHost("192.168.1.14",
                        probed(443, "nginx", "1.24.0", "cpe:/a:f5:nginx:1.24.0")));

        assertAll(
                () -> assertEquals(1, assessment.findingCount(),
                        "it is still reported -- suppressing it would be a false negative"),
                () -> assertEquals(ExposureBand.LOW, assessment.band(),
                        "CRITICAL severity and in KEV, but matched through an unbounded "
                      + "vendor claim: reported, not counted towards the band"));
    }

    @Test
    @DisplayName("with no CVE index nothing is CLEAR -- it is INDETERMINATE")
    void noIndexMeansNoOpinion() {
        PostureService service = new PostureService(null);
        PostureAssessment assessment = service.score(oneHost("10.0.0.1",
                probed(443, "nginx", "1.24.0", "cpe:/a:f5:nginx:1.24.0")));

        assertEquals(ExposureBand.INDETERMINATE, assessment.band(),
                "reporting CLEAR with no index is a statement about the index, "
              + "not about the host");
    }

    @Test
    @DisplayName("a scan of several hosts is one target on the dashboard")
    void hostsInOneScanAreMergedIntoOneRow() {
        // A CIDR scan is one target the user typed and several machines. The
        // dashboard's unit is the target, because that is what they act on.
        ScanOutcome range = scan("192.168.1.0/30", List.of(
                new Host("192.168.1.1", "", HostState.UP,
                        List.of(probed(443, "nginx", "1.24.0", "cpe:/a:f5:nginx:1.24.0")),
                        List.of()),
                new Host("192.168.1.2", "", HostState.UP,
                        List.of(probed(80, "nginx", "1.24.0", "cpe:/a:f5:nginx:1.24.0")),
                        List.of())));

        PostureAssessment assessment = serviceOver(
                new FakeIndex().with(row("CVE-1", "HIGH", kev()))).score(range);

        assertAll(
                () -> assertEquals(2, assessment.openPorts(), "both hosts' ports counted"),
                () -> assertEquals(2, assessment.findingCount()),
                () -> assertEquals(ExposureBand.HIGH, assessment.band()));
    }

    @Test
    @DisplayName("unprobed services drag coverage down and block a clean verdict")
    void unprobedServicesShowUpAsCoverage() {
        ScanOutcome mostlyGuessed = oneHost("10.0.0.5",
                probed(443, "nginx", "1.24.0", "cpe:/a:f5:nginx:1.24.0"),
                guessed(21), guessed(23), guessed(25), guessed(110));

        PostureAssessment assessment = serviceOver(new FakeIndex()).score(mostlyGuessed);

        assertAll(
                () -> assertEquals(5, assessment.coverage().examined()),
                () -> assertTrue(assessment.coverage().percent() < 80),
                () -> assertEquals(ExposureBand.INDETERMINATE, assessment.band(),
                        "four services nobody could look at is not a clean host"));
    }

    @Test
    @DisplayName("the trend comes from re-scoring the previous scan, not from a stored band")
    void trendIsComputedFromBothScans() {
        PostureService service = serviceOver(
                new FakeIndex().with(row("CVE-1", "HIGH", kev())));

        ScanOutcome previous = oneHost("192.168.1.14", guessed(21));
        ScanOutcome latest = oneHost("192.168.1.14",
                probed(443, "nginx", "1.24.0", "cpe:/a:f5:nginx:1.24.0"));

        TargetPosture worse = service.score("192.168.1.14", 9L, latest, previous);
        TargetPosture first = service.score("192.168.1.14", 9L, latest, null);

        assertAll(
                () -> assertEquals(ExposureBand.HIGH, worse.band()),
                () -> assertEquals(PostureTrend.UNCOMPARABLE, worse.trend(),
                        "the previous scan could not be assessed, so the two are "
                      + "not comparable -- that is not an improvement"),
                () -> assertEquals(PostureTrend.FIRST_SCAN, first.trend()),
                () -> assertEquals(9L, worse.scanId()),
                () -> assertEquals(WHEN, worse.scannedAt()));
    }

    @Test
    @DisplayName("network() scores every request and rolls them up worst-first")
    void networkRollsUpEveryRequest() {
        PostureService service = serviceOver(
                new FakeIndex().with(row("CVE-1", "HIGH", kev())));

        NetworkPosture posture = service.network(List.of(
                new PostureService.ScoreRequest("clean-host", 1L,
                        oneHost("clean-host", probed(22, "openssh", "9.6",
                                "cpe:/a:openbsd:openssh:9.6")), null),
                new PostureService.ScoreRequest("hot-host", 2L,
                        oneHost("hot-host", probed(443, "nginx", "1.24.0",
                                "cpe:/a:f5:nginx:1.24.0")), null)));

        assertAll(
                () -> assertEquals(2, posture.targets().size()),
                () -> assertEquals("hot-host", posture.targets().get(0).target()),
                () -> assertEquals(ExposureBand.HIGH, posture.band()),
                () -> assertEquals("hot-host", posture.topActions(1).get(0).target()));
    }

    @Test
    @DisplayName("no scans at all is an empty network, not a clean one")
    void emptyRequestListIsEmptyNetwork() {
        NetworkPosture posture = serviceOver(new FakeIndex()).network(List.of());
        assertAll(
                () -> assertTrue(posture.isEmpty()),
                () -> assertEquals(ExposureBand.INDETERMINATE, posture.band()));
    }
}
