package com.cyberscope.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Coverage: what a scan actually examined, as opposed to what it reported. */
class HostCoverageTest {

    private static Port open(int number) {
        return new Port(number, Protocol.TCP, PortState.OPEN, "syn-ack", Service.UNKNOWN);
    }

    /**
     * Mirrors a real Quick scan: one open port, ninety-nine collapsed as closed.
     *
     * <p>The port set holds exactly 99 entries, matching the count. An earlier
     * draft of this fixture declared count=99 while naming five ports "for
     * brevity" -- which is precisely the incomplete-coverage state, so it made
     * the completeness test fail for the right reason. A fixture that does not
     * satisfy its own invariants tests nothing.
     */
    private static Host realisticQuickScan() {
        Set<Integer> closed = new LinkedHashSet<>(Set.of(22, 80, 443, 3306, 5432));
        for (int p = 9000; closed.size() < 99; p++) {
            closed.add(p);
        }
        return new Host("127.0.0.1", "localhost", HostState.UP,
                List.of(open(8080)),
                List.of(new PortSummary(PortState.CLOSED, 99, Map.of("reset", 99), closed)));
    }

    @Test
    @DisplayName("a 100-port scan counts as 100 ports, not 1")
    void scannedCountIncludesCollapsedPorts() {
        assertEquals(100, realisticQuickScan().scannedPortCount());
    }

    @Test
    void openPortsStillOnlyReturnsOpenOnes() {
        Host host = realisticQuickScan();
        assertEquals(1, host.openPorts().size());
        assertEquals(8080, host.openPorts().get(0).number());
    }

    @Test
    @DisplayName("a port only Nmap's summary mentions can still be answered for")
    void stateOfFindsPortsInsideASummary() {
        Host host = realisticQuickScan();
        assertEquals(Optional.of(PortState.OPEN), host.stateOf(8080));
        assertEquals(Optional.of(PortState.CLOSED), host.stateOf(3306));
    }

    /**
     * The single most important assertion in this class. "Not scanned" must
     * never be reported as "closed": a comparison that conflates them will
     * announce that a port opened when the truth is that the previous scan
     * never looked at it. That is an invented finding.
     */
    @Test
    @DisplayName("a port outside the scan is empty, not CLOSED")
    void stateOfReturnsEmptyForAPortThatWasNeverScanned() {
        assertEquals(Optional.empty(), realisticQuickScan().stateOf(65000));
    }

    @Test
    void coveredPortsUnionsIndividualAndSummarisedPorts() {
        Set<Integer> covered = realisticQuickScan().coveredPorts();
        assertTrue(covered.contains(8080), "the individually reported port");
        assertTrue(covered.contains(3306), "a port from the summary");
        assertFalse(covered.contains(65000));
    }

    @Test
    void coverageIsCompleteWhenEverySummaryNamedItsPorts() {
        assertTrue(realisticQuickScan().coverageIsComplete());
    }

    /**
     * Nmap's DTD marks the ports attribute #IMPLIED. When it is missing we know
     * how many ports were in a state but not which, so coverage is a subset and
     * the host must say so.
     */
    @Test
    @DisplayName("a summary with a count but no port list makes coverage incomplete")
    void coverageIsIncompleteWhenASummaryOmittedItsPorts() {
        Host host = new Host("127.0.0.1", "", HostState.UP, List.of(open(80)),
                List.of(new PortSummary(PortState.FILTERED, 10, Map.of("host-unreach", 10),
                        Set.of())));

        assertFalse(host.coverageIsComplete());
        assertEquals(11, host.scannedPortCount(), "the count is still known");
        assertEquals(Set.of(80), host.coveredPorts(), "but only one port can be named");
    }

    @Test
    void anEmptySummaryDoesNotMakeCoverageIncomplete() {
        Host host = new Host("127.0.0.1", "", HostState.UP, List.of(open(80)),
                List.of(new PortSummary(PortState.CLOSED, 0, Map.of(), Set.of())));
        assertTrue(host.coverageIsComplete(), "zero collapsed ports hide nothing");
    }

    @Test
    @DisplayName("the four-argument constructor still works and means no summaries")
    void theLegacyConstructorIsUnchangedInMeaning() {
        Host host = new Host("10.0.0.1", "", HostState.UP, List.of(open(22)));

        assertEquals(List.of(), host.summaries());
        assertEquals(1, host.scannedPortCount());
        assertTrue(host.coverageIsComplete());
    }

    @Test
    void summariesAreDefensivelyCopiedAndUnmodifiable() {
        PortSummary summary = new PortSummary(PortState.CLOSED, 2,
                Map.of("reset", 2), Set.of(1, 2));

        assertEquals(Map.of("reset", 2), summary.reasons());
        org.junit.jupiter.api.Assertions.assertThrows(UnsupportedOperationException.class,
                () -> summary.reasons().put("x", 1));
        org.junit.jupiter.api.Assertions.assertThrows(UnsupportedOperationException.class,
                () -> summary.ports().add(3));
    }

    @Test
    void aNegativeCountIsRejected() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> new PortSummary(PortState.CLOSED, -1, Map.of(), Set.of()));
    }
}