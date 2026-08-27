package com.cyberscope.service.scanner;

import com.cyberscope.model.Host;
import com.cyberscope.model.PortState;
import com.cyberscope.model.PortSummary;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Parsing the {@code <extraports>} block.
 *
 * <p>Both fixtures are captured from real Nmap 7.94SVN output rather than
 * hand-written, because the shape of this element is exactly the thing that was
 * assumed wrongly before v0.4.0.
 */
class NmapExtraPortsTest {

    private static String fixture(String name) throws Exception {
        try (InputStream in = NmapExtraPortsTest.class
                .getResourceAsStream("/fixtures/" + name)) {
            assertNotNull(in, "missing fixture: " + name);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /**
     * The headline regression. Before v0.4.0 the parser read only {@code <port>}
     * elements, so a 100-port scan produced a Host that believed one port had
     * been examined.
     */
    @Test
    @DisplayName("a Quick scan reports 100 ports scanned, not 1")
    void collapsedPortsAreCounted() throws Exception {
        List<Host> hosts = NmapXmlParser.parse(fixture("nmap-extraports.xml"));
        Host host = hosts.get(0);

        assertEquals(1, host.ports().size(), "Nmap listed exactly one port");
        assertEquals(1, host.summaries().size());
        assertEquals(100, host.scannedPortCount(), "1 listed + 99 collapsed");
    }

    @Test
    void theSummaryCarriesStateCountAndReason() throws Exception {
        Host host = NmapXmlParser.parse(fixture("nmap-extraports.xml")).get(0);
        PortSummary summary = host.summaries().get(0);

        assertEquals(PortState.CLOSED, summary.state());
        assertEquals(99, summary.count());
        assertEquals(99, summary.reasons().get("reset"));
        assertEquals("reset", summary.reasonNames());
    }

    @Test
    @DisplayName("the port list expands to exactly the count Nmap reported")
    void thePortListAgreesWithTheCount() throws Exception {
        Host host = NmapXmlParser.parse(fixture("nmap-extraports.xml")).get(0);
        PortSummary summary = host.summaries().get(0);

        assertTrue(summary.hasPortNumbers());
        assertEquals(summary.count(), summary.ports().size(),
                "count and the expanded ports attribute must agree");
        assertTrue(host.coverageIsComplete());
        assertEquals(100, host.coveredPorts().size());
    }

    @Test
    @DisplayName("a port that only the summary mentions can be answered for")
    void statesFromTheSummaryAreQueryable() throws Exception {
        Host host = NmapXmlParser.parse(fixture("nmap-extraports.xml")).get(0);

        assertEquals(Optional.of(PortState.OPEN), host.stateOf(8080));
        assertEquals(Optional.of(PortState.CLOSED), host.stateOf(3306));
        assertEquals(Optional.empty(), host.stateOf(65000),
                "a port outside the scan must be empty, never CLOSED");
    }

    /**
     * A black-holed host produced one filtered block with two reasons.
     * Reading only the first would have silently dropped ten ports of coverage.
     */
    @Test
    @DisplayName("several <extrareasons> under one block are all read")
    void multipleReasonsAreMerged() throws Exception {
        Host host = NmapXmlParser.parse(fixture("nmap-extraports-partial.xml")).get(0);
        PortSummary summary = host.summaries().get(0);

        assertEquals(PortState.FILTERED, summary.state());
        assertEquals(120, summary.count());
        assertEquals(2, summary.reasons().size());
        assertEquals(110, summary.reasons().get("no-response"));
        assertEquals(10, summary.reasons().get("host-unreach"));
    }

    /**
     * The ports attribute is #IMPLIED in Nmap's DTD. A reason without it is
     * legal input, so it must parse -- and must leave coverage marked
     * incomplete rather than pretending those ports were never scanned.
     */
    @Test
    @DisplayName("a missing ports attribute is legal and makes coverage incomplete")
    void anAbsentPortsAttributeIsNotAnError() throws Exception {
        Host host = NmapXmlParser.parse(fixture("nmap-extraports-partial.xml")).get(0);

        assertEquals(120, host.scannedPortCount(), "the count is still trustworthy");
        // 1-4 (4) + 6-9 (4) + 11-12 (2) + 14-35 (22) = 32 named;
        // the other 10 are counted but not named.
        assertEquals(32, host.coveredPorts().size(), "only the named ports are known");
        assertFalse(host.coverageIsComplete(),
                "one reason gave no port list, so coverage is a subset");
    }

    /**
     * The proof that this was never a hypothetical bug.
     *
     * <p>{@code nmap-single-host.xml} was captured in v0.0.7 and has been in the
     * test suite ever since. It contained an {@code <extraports>} block the
     * whole time, and the parser silently discarded it through four releases:
     * every scan reported a fraction of what it had actually examined, and
     * nothing in the suite noticed because nothing asked.
     */
    @Test
    @DisplayName("the v0.0.7 fixture always had a summary we were throwing away")
    void theOldestFixtureWasAlreadyHidingPorts() throws Exception {
        Host host = NmapXmlParser.parse(fixture("nmap-single-host.xml")).get(0);

        assertFalse(host.summaries().isEmpty(),
                "this fixture has carried an extraports block since v0.0.7");
        assertTrue(host.scannedPortCount() > host.ports().size(),
                "the scan examined more ports than it listed");
    }

    @Test
    @DisplayName("a host with no ports section at all still parses")
    void hostsWithoutAPortsSectionAreUnaffected() throws Exception {
        List<Host> hosts = NmapXmlParser.parse(fixture("nmap-host-down.xml"));

        for (Host host : hosts) {
            assertEquals(List.of(), host.summaries());
            assertTrue(host.coverageIsComplete());
            assertEquals(host.ports().size(), host.scannedPortCount());
        }
    }

    @Test
    @DisplayName("a malformed count is rejected rather than silently zeroed")
    void aBadCountThrows() {
        String bad = """
                <?xml version="1.0"?>
                <nmaprun><host><status state="up"/>
                <address addr="127.0.0.1" addrtype="ipv4"/>
                <ports><extraports state="closed" count="not-a-number">
                <extrareasons reason="reset" count="9" ports="1-9"/>
                </extraports></ports></host></nmaprun>
                """;
        org.junit.jupiter.api.Assertions.assertThrows(XmlParseException.class,
                () -> NmapXmlParser.parse(bad));
    }

    @Test
    @DisplayName("a malformed ports attribute is rejected, not ignored")
    void aBadPortListThrows() {
        String bad = """
                <?xml version="1.0"?>
                <nmaprun><host><status state="up"/>
                <address addr="127.0.0.1" addrtype="ipv4"/>
                <ports><extraports state="closed" count="9">
                <extrareasons reason="reset" count="9" ports="1-9,70000"/>
                </extraports></ports></host></nmaprun>
                """;
        org.junit.jupiter.api.Assertions.assertThrows(XmlParseException.class,
                () -> NmapXmlParser.parse(bad));
    }
}