package com.cyberscope.service.compare;
 
import com.cyberscope.model.DetectionMethod;
import com.cyberscope.model.Host;
import com.cyberscope.model.HostState;
import com.cyberscope.model.Port;
import com.cyberscope.model.PortState;
import com.cyberscope.model.PortSummary;
import com.cyberscope.model.Protocol;
import com.cyberscope.model.ScanType;
import com.cyberscope.model.Service;
import com.cyberscope.service.scanner.NmapRunResult;
import com.cyberscope.service.scanner.ScanOutcome;
import com.cyberscope.util.NetworkContext;
import com.cyberscope.util.TargetKind;
import com.cyberscope.util.ValidatedTarget;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
 
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
 
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
 
class ScanComparatorTest {
 
    // ------------------------------------------------------------- fixtures
 
    private static final String IP = "127.0.0.1";
 
    private static Service probed(String name, String product, String version) {
        return new Service(name, product, version, "", List.of(),
                DetectionMethod.PROBED, 10);
    }
 
    private static Service inferred(String name) {
        return new Service(name, "", "", "", List.of(), DetectionMethod.TABLE, 3);
    }
 
    private static Port port(int number, PortState state, Service service) {
        return new Port(number, Protocol.TCP, state, "syn-ack", service);
    }
 
    private static PortSummary closed(Set<Integer> ports) {
        return new PortSummary(PortState.CLOSED, ports.size(),
                new LinkedHashMap<>(Map.of("reset", ports.size())), ports);
    }
 
    private static ScanOutcome scan(String when, List<Port> ports, List<PortSummary> summaries) {
        return scan(when, IP, ScanType.QUICK, NetworkContext.UNKNOWN, ports, summaries);
    }
 
    private static ScanOutcome scan(String when, String target, ScanType type,
                                    NetworkContext context,
                                    List<Port> ports, List<PortSummary> summaries) {
        NmapRunResult run = new NmapRunResult(
                new ValidatedTarget(target, TargetKind.IPV4, 1), type,
                List.of("nmap", target), "", Instant.parse(when),
                Duration.ofSeconds(6), "", context);
        return new ScanOutcome(run,
                List.of(new Host(IP, "localhost", HostState.UP, ports, summaries)));
    }
 
    private static final String MONDAY = "2026-08-24T09:00:00Z";
    private static final String FRIDAY = "2026-08-28T09:00:00Z";
 
    // ------------------------------------------------------------ rule 1
 
    @Nested
    @DisplayName("rule 1: a port only one scan covered is never a change")
    class CoverageGate {
 
        /**
         * The failure this whole version exists to prevent. Monday scanned ports
         * 1-100 and never looked at 3306; Friday scanned it and found it open.
         * Reporting "3306 opened" would send somebody to investigate a database
         * that may have been running for a year.
         */
        @Test
        @DisplayName("a port the earlier scan never examined is not reported as opened")
        void aPortOutsideTheEarlierScanIsNotAChange() {
            ScanOutcome before = scan(MONDAY, List.of(port(80, PortState.OPEN, probed("http", "nginx", "1.24.0"))),
                    List.of(closed(Set.of(22, 443))));
            ScanOutcome after = scan(FRIDAY, List.of(
                    port(80, PortState.OPEN, probed("http", "nginx", "1.24.0")),
                    port(3306, PortState.OPEN, probed("mysql", "MySQL", "8.0.36"))),
                    List.of(closed(Set.of(22, 443))));
 
            ScanDiff diff = ScanComparator.compare(before, after);
 
            assertTrue(diff.hostChanges().isEmpty(),
                    "3306 was not covered by the earlier scan; it cannot be a change");
            assertTrue(diff.hosts().get(0).uncomparedPorts().contains(3306));
        }
 
        @Test
        void uncomparedPortsAreReportedSeparatelyFromChanges() {
            ScanOutcome before = scan(MONDAY, List.of(), List.of(closed(Set.of(22, 80))));
            ScanOutcome after = scan(FRIDAY, List.of(), List.of(closed(Set.of(80, 443))));
 
            ScanDiff diff = ScanComparator.compare(before, after);
 
            assertEquals(Set.of(22, 443), diff.hosts().get(0).uncomparedPorts());
            assertTrue(diff.hosts().get(0).changes().isEmpty());
            assertTrue(diff.hosts().get(0).hasCoverageGap());
        }
 
        @Test
        @DisplayName("incomplete coverage raises a warning of its own")
        void unnamedPortsAreWarnedAbout() {
            PortSummary unnamed = new PortSummary(PortState.FILTERED, 10,
                    new LinkedHashMap<>(Map.of("host-unreach", 10)), Set.of());
            ScanOutcome before = scan(MONDAY, List.of(), List.of(unnamed));
            ScanOutcome after = scan(FRIDAY, List.of(), List.of(closed(Set.of(80))));
 
            ScanDiff diff = ScanComparator.compare(before, after);
 
            assertTrue(diff.warnings().stream()
                    .anyMatch(w -> w.kind() == DiffWarning.Kind.COVERAGE_INCOMPLETE));
        }
    }
 
    // ------------------------------------------------------------ rule 2
 
    @Nested
    @DisplayName("rule 2: state is comparable whenever both scans covered the port")
    class StateChanges {
 
        /**
         * The correction to the first draft of the rule. 3306 was closed on
         * Monday -- known only because it appeared in an extraports summary --
         * and is open on Friday. Being summarised is not weak evidence: the TCP
         * handshake happened, Nmap simply declined to print ninety-nine
         * identical lines. This is a real host change and the most important
         * finding the tool can produce.
         */
        @Test
        @DisplayName("closed in a summary, then open: a real host change")
        void aPortKnownOnlyFromASummaryCanStillOpen() {
            ScanOutcome before = scan(MONDAY, List.of(), List.of(closed(Set.of(22, 80, 3306))));
            ScanOutcome after = scan(FRIDAY,
                    List.of(port(3306, PortState.OPEN, probed("mysql", "MySQL", "8.0.36"))),
                    List.of(closed(Set.of(22, 80))));
 
            ScanDiff diff = ScanComparator.compare(before, after);
 
            assertEquals(1, diff.hostChanges().size());
            PortChange change = diff.hostChanges().get(0);
            assertEquals(ChangeKind.PORT_OPENED, change.kind());
            assertEquals(3306, change.port());
            assertTrue(change.isHostChange());
            assertTrue(change.before().fromSummary(), "the earlier view came from a summary");
        }
 
        @Test
        void aPortThatClosesIsReportedAsClosed() {
            ScanOutcome before = scan(MONDAY,
                    List.of(port(8080, PortState.OPEN, probed("http", "nginx", "1.24.0"))),
                    List.of());
            ScanOutcome after = scan(FRIDAY, List.of(), List.of(closed(Set.of(8080))));
 
            ScanDiff diff = ScanComparator.compare(before, after);
 
            assertEquals(ChangeKind.PORT_CLOSED, diff.hostChanges().get(0).kind());
        }
 
        @Test
        @DisplayName("closed becoming filtered is a change, not an open or close")
        void otherTransitionsAreStateChanges() {
            ScanOutcome before = scan(MONDAY, List.of(), List.of(closed(Set.of(22))));
            ScanOutcome after = scan(FRIDAY,
                    List.of(port(22, PortState.FILTERED, inferred("ssh"))), List.of());
 
            ScanDiff diff = ScanComparator.compare(before, after);
 
            assertEquals(ChangeKind.STATE_CHANGED, diff.hostChanges().get(0).kind());
        }
 
        @Test
        void anUnchangedHostProducesNothing() {
            List<Port> ports = List.of(port(80, PortState.OPEN, probed("http", "nginx", "1.24.0")));
            ScanDiff diff = ScanComparator.compare(
                    scan(MONDAY, ports, List.of(closed(Set.of(22)))),
                    scan(FRIDAY, ports, List.of(closed(Set.of(22)))));
 
            assertTrue(diff.isEmpty());
            assertTrue(diff.hostChanges().isEmpty());
            assertTrue(diff.evidenceChanges().isEmpty());
        }
    }
 
    // ------------------------------------------------------------ rule 3
 
    @Nested
    @DisplayName("rule 3: service is comparable only when both sides were probed")
    class ServiceChanges {
 
        @Test
        void aVersionMoveBetweenTwoProbesIsAHostChange() {
            ScanDiff diff = ScanComparator.compare(
                    scan(MONDAY, List.of(port(22, PortState.OPEN, probed("ssh", "OpenSSH", "9.6p1"))), List.of()),
                    scan(FRIDAY, List.of(port(22, PortState.OPEN, probed("ssh", "OpenSSH", "9.8p1"))), List.of()));
 
            PortChange change = diff.hostChanges().get(0);
            assertEquals(ChangeKind.VERSION_CHANGED, change.kind());
            assertTrue(change.describe().contains("9.6p1"));
            assertTrue(change.describe().contains("9.8p1"));
        }
 
        @Test
        void adifferentServiceEntirelyIsDistinguishedFromAVersionMove() {
            ScanDiff diff = ScanComparator.compare(
                    scan(MONDAY, List.of(port(80, PortState.OPEN, probed("http", "nginx", "1.24.0"))), List.of()),
                    scan(FRIDAY, List.of(port(80, PortState.OPEN, probed("http", "Apache httpd", "2.4.58"))), List.of()));
 
            assertEquals(ChangeKind.SERVICE_CHANGED, diff.hostChanges().get(0).kind());
        }
 
        /**
         * The case the project's whole thesis is built on. Nothing about the
         * host changed; what changed is that CyberScope can no longer confirm
         * what is running. Reporting that as a host change would be a false
         * finding; reporting nothing at all would hide a real signal.
         */
        @Test
        @DisplayName("probed becoming inferred is an evidence change, not a host change")
        void losingAProbeIsNotAHostChange() {
            ScanDiff diff = ScanComparator.compare(
                    scan(MONDAY, List.of(port(443, PortState.OPEN, probed("https", "nginx", "1.24.0"))), List.of()),
                    scan(FRIDAY, List.of(port(443, PortState.OPEN, inferred("https"))), List.of()));
 
            assertTrue(diff.hostChanges().isEmpty(), "the host may be entirely unchanged");
            assertEquals(1, diff.evidenceChanges().size());
 
            PortChange change = diff.evidenceChanges().get(0);
            assertEquals(ChangeKind.EVIDENCE_LOST, change.kind());
            assertFalse(change.isHostChange());
        }
 
        @Test
        void gainingAProbeIsRecordedWithItsDirection() {
            ScanDiff diff = ScanComparator.compare(
                    scan(MONDAY, List.of(port(443, PortState.OPEN, inferred("https"))), List.of()),
                    scan(FRIDAY, List.of(port(443, PortState.OPEN, probed("https", "nginx", "1.24.0"))), List.of()));
 
            assertEquals(ChangeKind.EVIDENCE_GAINED, diff.evidenceChanges().get(0).kind());
            assertTrue(diff.hostChanges().isEmpty());
        }
 
        /**
         * A table lookup is a function of the port number. Two of them at the
         * same port cannot disagree unless the port changed, and the port is the
         * same port -- so there is nothing to compare and nothing to report.
         */
        @Test
        @DisplayName("two inferences agreeing prove nothing and report nothing")
        void twoTableGuessesProduceNoChange() {
            ScanDiff diff = ScanComparator.compare(
                    scan(MONDAY, List.of(port(443, PortState.OPEN, inferred("https"))), List.of()),
                    scan(FRIDAY, List.of(port(443, PortState.OPEN, inferred("https"))), List.of()));
 
            assertTrue(diff.hostChanges().isEmpty());
            assertTrue(diff.evidenceChanges().isEmpty());
        }
 
        /**
         * A closed port still carries a service name from the port table. It
         * describes the number, not anything listening, so comparing two of them
         * would manufacture findings about ports that are shut.
         */
        @Test
        @DisplayName("service is not compared on ports that are not open")
        void closedPortsDoNotProduceServiceChanges() {
            ScanDiff diff = ScanComparator.compare(
                    scan(MONDAY, List.of(port(22, PortState.CLOSED, inferred("ssh"))), List.of()),
                    scan(FRIDAY, List.of(port(22, PortState.CLOSED, probed("ssh", "OpenSSH", "9.8p1"))), List.of()));
 
            assertTrue(diff.hostChanges().isEmpty());
            assertTrue(diff.evidenceChanges().isEmpty());
        }
 
        @Test
        @DisplayName("a port collapsed into a summary produces no evidence change")
        void aSummarisedPortIsNotTreatedAsLostEvidence() {
            // Open in both, but the later scan collapsed it. Nothing was
            // attempted and lost; it simply was not listed individually.
            ScanOutcome before = scan(MONDAY,
                    List.of(port(80, PortState.OPEN, probed("http", "nginx", "1.24.0"))), List.of());
            ScanOutcome after = scan(FRIDAY, List.of(),
                    List.of(new PortSummary(PortState.OPEN, 1,
                            new LinkedHashMap<>(Map.of("syn-ack", 1)), Set.of(80))));
 
            ScanDiff diff = ScanComparator.compare(before, after);
 
            assertTrue(diff.hostChanges().isEmpty());
            assertTrue(diff.evidenceChanges().isEmpty());
        }
    }
 
    // ------------------------------------------------------------ rule 4
 
    @Nested
    @DisplayName("rule 4: a different route undermines the whole comparison")
    class PathWarning {
 
        @Test
        void adifferentInterfaceMakesTheDiffUntrustworthy() {
            ScanOutcome before = scan(MONDAY, IP, ScanType.QUICK,
                    new NetworkContext("192.168.1.10", "eth0", false),
                    List.of(port(80, PortState.OPEN, probed("http", "nginx", "1.24.0"))), List.of());
            ScanOutcome after = scan(FRIDAY, IP, ScanType.QUICK,
                    new NetworkContext("10.8.0.6", "tun0", true),
                    List.of(port(80, PortState.OPEN, probed("http", "Apache httpd", "2.4.58"))), List.of());
 
            ScanDiff diff = ScanComparator.compare(before, after);
 
            assertFalse(diff.isTrustworthy());
            assertTrue(diff.warnings().stream()
                    .anyMatch(w -> w.kind() == DiffWarning.Kind.PATH_DIFFERS));
            // The differences are still computed -- they are just not to be read
            // as changes to one machine.
            assertEquals(1, diff.hostChanges().size());
        }
 
        /**
         * Every scan recorded before v0.4.0 has no context. If an unknown route
         * counted as a different one, opening any older comparison would raise
         * this warning on a history that has nothing wrong with it.
         */
        @Test
        @DisplayName("an unrecorded route does not raise the warning")
        void unknownContextsDoNotWarn() {
            ScanDiff diff = ScanComparator.compare(
                    scan(MONDAY, List.of(), List.of(closed(Set.of(80)))),
                    scan(FRIDAY, List.of(), List.of(closed(Set.of(80)))));
 
            assertTrue(diff.isTrustworthy());
            assertTrue(diff.warnings().stream()
                    .noneMatch(w -> w.kind() == DiffWarning.Kind.PATH_DIFFERS));
        }
    }
 
    // -------------------------------------------------------------- general
 
    @Nested
    @DisplayName("ordering and framing")
    class Framing {
 
        /**
         * Callers pass whichever scan is convenient first. If the comparator did
         * not normalise, a diff could report a port as having closed when it in
         * fact opened -- worse than producing no diff at all.
         */
        @Test
        @DisplayName("arguments in either order give the same answer")
        void theOlderScanIsAlwaysBefore() {
            ScanOutcome older = scan(MONDAY, List.of(), List.of(closed(Set.of(3306))));
            ScanOutcome newer = scan(FRIDAY,
                    List.of(port(3306, PortState.OPEN, probed("mysql", "MySQL", "8.0.36"))), List.of());
 
            ScanDiff forwards = ScanComparator.compare(older, newer);
            ScanDiff backwards = ScanComparator.compare(newer, older);
 
            assertEquals(ChangeKind.PORT_OPENED, forwards.hostChanges().get(0).kind());
            assertEquals(ChangeKind.PORT_OPENED, backwards.hostChanges().get(0).kind());
            assertEquals(forwards.before().run().startedAt(), backwards.before().run().startedAt());
            assertEquals(Duration.ofDays(4), forwards.interval());
        }
 
        @Test
        void differentScanTypesAreWarnedAbout() {
            ScanOutcome before = scan(MONDAY, IP, ScanType.QUICK, NetworkContext.UNKNOWN,
                    List.of(), List.of(closed(Set.of(80))));
            ScanOutcome after = scan(FRIDAY, IP, ScanType.STANDARD, NetworkContext.UNKNOWN,
                    List.of(), List.of(closed(Set.of(80))));
 
            assertTrue(ScanComparator.compare(before, after).warnings().stream()
                    .anyMatch(w -> w.kind() == DiffWarning.Kind.SCAN_TYPE_DIFFERS));
        }
 
        @Test
        void differentTargetsAreWarnedAbout() {
            ScanOutcome before = scan(MONDAY, "10.0.0.1", ScanType.QUICK,
                    NetworkContext.UNKNOWN, List.of(), List.of(closed(Set.of(80))));
            ScanOutcome after = scan(FRIDAY, "10.0.0.2", ScanType.QUICK,
                    NetworkContext.UNKNOWN, List.of(), List.of(closed(Set.of(80))));
 
            assertTrue(ScanComparator.compare(before, after).warnings().stream()
                    .anyMatch(w -> w.kind() == DiffWarning.Kind.TARGET_DIFFERS));
        }
 
        /**
         * Reverse DNS can be unavailable on one run and present on the next.
         * Keying hosts by display name would report the machine as removed and a
         * different one as added.
         */
        @Test
        @DisplayName("a host is matched by address, not by hostname")
        void hostnameChangesDoNotSplitAHost() {
            NmapRunResult run1 = new NmapRunResult(
                    new ValidatedTarget(IP, TargetKind.IPV4, 1), ScanType.QUICK,
                    List.of("nmap", IP), "", Instant.parse(MONDAY), Duration.ofSeconds(1), "");
            NmapRunResult run2 = new NmapRunResult(
                    new ValidatedTarget(IP, TargetKind.IPV4, 1), ScanType.QUICK,
                    List.of("nmap", IP), "", Instant.parse(FRIDAY), Duration.ofSeconds(1), "");
 
            ScanOutcome before = new ScanOutcome(run1, List.of(
                    new Host(IP, "localhost", HostState.UP, List.of(), List.of(closed(Set.of(80))))));
            ScanOutcome after = new ScanOutcome(run2, List.of(
                    new Host(IP, "", HostState.UP, List.of(), List.of(closed(Set.of(80))))));
 
            ScanDiff diff = ScanComparator.compare(before, after);
 
            assertEquals(1, diff.hosts().size());
            assertEquals(HostDiff.Presence.IN_BOTH, diff.hosts().get(0).presence());
            assertTrue(diff.addedHosts().isEmpty());
            assertTrue(diff.removedHosts().isEmpty());
        }
 
        @Test
        void hostsAppearingAndDisappearingAreReported() {
            NmapRunResult run1 = new NmapRunResult(
                    new ValidatedTarget("192.0.2.0/29", TargetKind.CIDR, 8), ScanType.QUICK,
                    List.of("nmap"), "", Instant.parse(MONDAY), Duration.ofSeconds(1), "");
            NmapRunResult run2 = new NmapRunResult(
                    new ValidatedTarget("192.0.2.0/29", TargetKind.CIDR, 8), ScanType.QUICK,
                    List.of("nmap"), "", Instant.parse(FRIDAY), Duration.ofSeconds(1), "");
 
            ScanOutcome before = new ScanOutcome(run1, List.of(
                    new Host("192.0.2.1", "", HostState.UP, List.of(), List.of()),
                    new Host("192.0.2.2", "", HostState.UP, List.of(), List.of())));
            ScanOutcome after = new ScanOutcome(run2, List.of(
                    new Host("192.0.2.1", "", HostState.UP, List.of(), List.of()),
                    new Host("192.0.2.7", "", HostState.UP, List.of(), List.of())));
 
            ScanDiff diff = ScanComparator.compare(before, after);
 
            assertEquals(1, diff.addedHosts().size());
            assertEquals("192.0.2.7", diff.addedHosts().get(0).address());
            assertEquals(1, diff.removedHosts().size());
            assertEquals("192.0.2.2", diff.removedHosts().get(0).address());
        }
    }
}
 

