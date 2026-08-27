package com.cyberscope.service.report;
 
import com.cyberscope.model.DetectionMethod;
import com.cyberscope.model.Host;
import com.cyberscope.model.HostState;
import com.cyberscope.model.Port;
import com.cyberscope.model.PortState;
import com.cyberscope.model.PortSummary;
import com.cyberscope.model.Protocol;
import com.cyberscope.model.ScanType;
import com.cyberscope.model.Service;
import com.cyberscope.service.compare.ScanComparator;
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
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
 
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
 
class FormatterTest {
 
    private static Service probed(String name, String product, String version) {
        return new Service(name, product, version, "", List.of(), DetectionMethod.PROBED, 10);
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
 
    private static NmapRunResult run(String when, NetworkContext context) {
        return new NmapRunResult(
                new ValidatedTarget("127.0.0.1", TargetKind.IPV4, 1), ScanType.QUICK,
                List.of("nmap", "-sV", "127.0.0.1"), "", Instant.parse(when),
                Duration.ofSeconds(6), "", context);
    }
 
    private static ScanOutcome outcome(String when, List<Port> ports, Set<Integer> collapsed) {
        return outcome(when, NetworkContext.UNKNOWN, ports, collapsed);
    }
 
    private static ScanOutcome outcome(String when, NetworkContext context,
                                       List<Port> ports, Set<Integer> collapsed) {
        return new ScanOutcome(run(when, context), List.of(
                new Host("127.0.0.1", "localhost", HostState.UP, ports,
                        collapsed.isEmpty() ? List.of() : List.of(closed(collapsed)))));
    }
 
    // ------------------------------------------------------- scan report
 
    @Nested
    @DisplayName("the scan report")
    class Report {
 
        /**
         * "1 open port" is not a result -- a reader cannot tell a clean host
         * from a scan that barely looked. The denominator only exists because
         * the extraports summary is now parsed.
         */
        @Test
        @DisplayName("quotes what was scanned, not only what was open")
        void coverageIsReported() {
            ScanOutcome scan = outcome("2026-08-27T09:00:00Z",
                    List.of(port(8080, PortState.OPEN, probed("http", "nginx", "1.24.0"))),
                    Set.of(22, 80, 443));
 
            String text = ScanReportFormatter.format(
                    scan.run(), scan.hosts(), ZoneOffset.UTC);
 
            assertTrue(text.contains("4 ports scanned"), text);
            assertTrue(text.contains("1 open"), text);
            assertTrue(text.contains("3 closed"), text);
        }
 
        @Test
        @DisplayName("lists closed and filtered ports Nmap reported individually")
        void nonOpenPortsAppearInTheTable() {
            ScanOutcome scan = outcome("2026-08-27T09:00:00Z", List.of(
                    port(8080, PortState.OPEN, probed("http", "nginx", "1.24.0")),
                    port(22, PortState.FILTERED, inferred("ssh"))), Set.of());
 
            String text = ScanReportFormatter.format(
                    scan.run(), scan.hosts(), ZoneOffset.UTC);
 
            assertTrue(text.contains("22/tcp"), "a filtered port must still be listed");
            assertTrue(text.contains("filtered"), text);
        }
 
        @Test
        void theRouteIsShownOnlyWhenItIsKnown() {
            ScanOutcome withRoute = outcome("2026-08-27T09:00:00Z",
                    new NetworkContext("192.168.1.10", "eth0", false), List.of(), Set.of(80));
            ScanOutcome without = outcome("2026-08-27T09:00:00Z", List.of(), Set.of(80));
 
            assertTrue(ScanReportFormatter.format(withRoute.run(), withRoute.hosts(),
                    ZoneOffset.UTC).contains("192.168.1.10 via eth0"));
            assertFalse(ScanReportFormatter.format(without.run(), without.hosts(),
                    ZoneOffset.UTC).contains("Route"));
        }
    }
 
    // ------------------------------------------------------- comparison
 
    @Nested
    @DisplayName("the comparison report")
    class Diff {
 
        @Test
        @DisplayName("host changes and evidence changes get separate headings")
        void theTwoKindsAreNotMixed() {
            ScanOutcome before = outcome("2026-08-20T09:00:00Z", List.of(
                    port(443, PortState.OPEN, probed("https", "nginx", "1.24.0"))), Set.of(3306));
            ScanOutcome after = outcome("2026-08-27T09:00:00Z", List.of(
                    port(443, PortState.OPEN, inferred("https")),
                    port(3306, PortState.OPEN, probed("mysql", "MySQL", "8.0.36"))), Set.of());
 
            String text = ScanDiffFormatter.format(
                    ScanComparator.compare(before, after), ZoneOffset.UTC);
 
            assertTrue(text.contains("CHANGES ON THE HOST"), text);
            assertTrue(text.contains("CHANGES IN WHAT WE KNOW"), text);
            assertTrue(text.contains("3306/tcp opened"), text);
            assertTrue(text.contains("443/tcp no longer probed"), text);
            assertTrue(text.contains("not in the host"),
                    "the evidence section must say what it means");
        }
 
        /**
         * A warning that the two scans may describe different machines has to
         * be read before the differences it qualifies, not discovered under
         * them.
         */
        @Test
        @DisplayName("a path warning appears above the changes")
        void warningsComeFirst() {
            ScanOutcome before = outcome("2026-08-20T09:00:00Z",
                    new NetworkContext("192.168.1.10", "eth0", false),
                    List.of(port(80, PortState.OPEN, probed("http", "nginx", "1.24.0"))),
                    Set.of(3306));
            ScanOutcome after = outcome("2026-08-27T09:00:00Z",
                    new NetworkContext("10.8.0.6", "tun0", true),
                    List.of(port(80, PortState.OPEN, probed("http", "nginx", "1.24.0")),
                            port(3306, PortState.OPEN, probed("mysql", "MySQL", "8.0.36"))),
                    Set.of());
 
            String text = ScanDiffFormatter.format(
                    ScanComparator.compare(before, after), ZoneOffset.UTC);
 
            int warning = text.indexOf("PATH_DIFFERS");
            int changes = text.indexOf("CHANGES ON THE HOST");
            assertTrue(warning >= 0, "the warning must be printed");
            assertTrue(changes >= 0, "the changes must still be printed");
            assertTrue(warning < changes, "the warning must come first");
            assertTrue(text.contains("may not describe the same machine"), text);
        }
 
        /**
         * "No changes found" and "nothing changed" are different claims. Without
         * this section the report makes the second while supporting only the
         * first.
         */
        @Test
        @DisplayName("ports only one scan covered are stated, not omitted")
        void uncomparedPortsAreReported() {
            ScanOutcome before = outcome("2026-08-20T09:00:00Z", List.of(), Set.of(80));
            ScanOutcome after = outcome("2026-08-27T09:00:00Z", List.of(), Set.of(80, 443, 8080));
 
            String text = ScanDiffFormatter.format(
                    ScanComparator.compare(before, after), ZoneOffset.UTC);
 
            assertTrue(text.contains("NOT COMPARED"), text);
            assertTrue(text.contains("2 ports were examined by only one"), text);
            assertTrue(text.contains("Nothing can be said"), text);
        }
 
        @Test
        void anIdenticalPairSaysSoPlainly() {
            List<Port> ports = List.of(port(80, PortState.OPEN, probed("http", "nginx", "1.24.0")));
            String text = ScanDiffFormatter.format(ScanComparator.compare(
                    outcome("2026-08-20T09:00:00Z", ports, Set.of(22)),
                    outcome("2026-08-27T09:00:00Z", ports, Set.of(22))), ZoneOffset.UTC);
 
            assertTrue(text.contains("No differences found"), text);
            assertTrue(text.contains("0 changes on the host"), text);
        }
    }
}
 

