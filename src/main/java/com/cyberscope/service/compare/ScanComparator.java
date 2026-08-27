package com.cyberscope.service.compare;
 
import com.cyberscope.model.Host;
import com.cyberscope.model.Port;
import com.cyberscope.model.PortState;
import com.cyberscope.model.Protocol;
import com.cyberscope.model.Service;
import com.cyberscope.service.scanner.ScanOutcome;
 
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
 
/**
 * Works out what changed between two scans.
 *
 * <p>The rules, in the order they are applied. Each exists to stop the
 * comparator claiming something it cannot know.
 *
 * <ol>
 *   <li><b>Coverage gate.</b> A port is compared only if <em>both</em> scans
 *       observed it. A port one scan never looked at produces no change of any
 *       kind — not "opened", not "closed", nothing.</li>
 *   <li><b>State.</b> Once the gate passes, a differing state is a real change
 *       to the host. This holds whether the state came from an individually
 *       reported port or from an {@code <extraports>} summary: being collapsed
 *       into a summary is not weak evidence, it is Nmap declining to print
 *       ninety-nine identical lines. The TCP handshake happened either way.</li>
 *   <li><b>Service and version.</b> Compared only when both sides were actually
 *       probed. One probed and one inferred is a change in method, not in the
 *       host. Two inferences agreeing proves nothing — a table lookup is a
 *       function of the port number, so it cannot change unless the port
 *       did.</li>
 *   <li><b>Path.</b> If the two scans left this machine by different routes,
 *       the same address may not be the same host, and everything above is
 *       reported as untrustworthy rather than as change.</li>
 * </ol>
 *
 * <p>Rules 2 and 3 are separate because state and identity have different
 * evidence: a state comes from the handshake and is directly observed, while an
 * identity comes either from a probe or from a lookup table. Merging them —
 * requiring a probe before believing a state change — would suppress the single
 * most important finding this tool can produce, which is that a port opened.
 *
 * <p>Stateless and side-effect free. No JavaFX, no SQL, no I/O: it takes two
 * outcomes and returns a value, which is why it can be tested exhaustively
 * without a database or a network.
 */
public final class ScanComparator {
 
    private ScanComparator() {
    }
 
    /**
     * Compares two scans, oldest first regardless of argument order.
     *
     * <p>Callers pass "the one I clicked" and "the one before it" in whatever
     * order is convenient; normalising here means the words "opened" and
     * "closed" in the result are always the right way round.
     */
    public static ScanDiff compare(ScanOutcome first, ScanOutcome second) {
        ScanOutcome before = first;
        ScanOutcome after = second;
        if (after.run().startedAt().isBefore(before.run().startedAt())) {
            before = second;
            after = first;
        }
 
        List<DiffWarning> warnings = collectWarnings(before, after);
        List<HostDiff> hosts = compareHosts(before, after);
 
        boolean anyGap = hosts.stream().anyMatch(HostDiff::hasCoverageGap);
        if (anyGap && warnings.stream().noneMatch(
                w -> w.kind() == DiffWarning.Kind.PARTIAL_OVERLAP)) {
            warnings.add(new DiffWarning(DiffWarning.Kind.PARTIAL_OVERLAP,
                    "Some ports were covered by only one of the two scans and were not compared."));
        }
        return new ScanDiff(before, after, hosts, warnings);
    }
 
    // ------------------------------------------------------------- warnings
 
    private static List<DiffWarning> collectWarnings(ScanOutcome before, ScanOutcome after) {
        List<DiffWarning> warnings = new ArrayList<>();
 
        // Rule 4, and it comes first because it is the one that invalidates the
        // rest rather than qualifying it.
        if (before.run().context().differsFrom(after.run().context())) {
            warnings.add(new DiffWarning(DiffWarning.Kind.PATH_DIFFERS,
                    "These scans left by different routes ("
                    + before.run().context().describe() + " then "
                    + after.run().context().describe()
                    + "). The same address may not be the same machine."));
        }
 
        if (!before.run().target().value().equals(after.run().target().value())) {
            warnings.add(new DiffWarning(DiffWarning.Kind.TARGET_DIFFERS,
                    "Different targets: " + before.run().target().value()
                    + " and " + after.run().target().value() + "."));
        }
 
        if (before.run().scanType() != after.run().scanType()) {
            warnings.add(new DiffWarning(DiffWarning.Kind.SCAN_TYPE_DIFFERS,
                    before.run().scanType().displayName() + " then "
                    + after.run().scanType().displayName()
                    + ": these profiles examine different ports."));
        }
 
        if (!complete(before) || !complete(after)) {
            warnings.add(new DiffWarning(DiffWarning.Kind.COVERAGE_INCOMPLETE,
                    "At least one scan counted ports it could not name, so some "
                    + "ports could not be compared even though they were scanned."));
        }
        return warnings;
    }
 
    private static boolean complete(ScanOutcome outcome) {
        return outcome.hosts().stream().allMatch(Host::coverageIsComplete);
    }
 
    // ---------------------------------------------------------------- hosts
 
    private static List<HostDiff> compareHosts(ScanOutcome before, ScanOutcome after) {
        Map<String, Host> beforeHosts = byAddress(before);
        Map<String, Host> afterHosts = byAddress(after);
 
        Set<String> addresses = new LinkedHashSet<>(beforeHosts.keySet());
        addresses.addAll(afterHosts.keySet());
 
        List<HostDiff> diffs = new ArrayList<>();
        for (String address : addresses) {
            Host oldHost = beforeHosts.get(address);
            Host newHost = afterHosts.get(address);
 
            if (oldHost == null) {
                diffs.add(new HostDiff(address, HostDiff.Presence.ADDED,
                        List.of(), Set.of(), newHost.coverageIsComplete()));
            } else if (newHost == null) {
                diffs.add(new HostDiff(address, HostDiff.Presence.REMOVED,
                        List.of(), Set.of(), oldHost.coverageIsComplete()));
            } else {
                diffs.add(comparePorts(address, oldHost, newHost));
            }
        }
        return diffs;
    }
 
    /**
     * Keyed by IP address, not by display name.
     *
     * <p>A hostname can be absent from one scan and present in the other, or
     * change entirely, without the machine changing. Keying on it would report
     * a host as removed and another as added when reverse DNS was simply
     * unavailable the second time.
     */
    private static Map<String, Host> byAddress(ScanOutcome outcome) {
        Map<String, Host> hosts = new LinkedHashMap<>();
        outcome.hosts().forEach(host -> hosts.put(host.ipAddress(), host));
        return hosts;
    }
 
    // ---------------------------------------------------------------- ports
 
    private static HostDiff comparePorts(String address, Host before, Host after) {
        Set<Integer> beforeCovered = before.coveredPorts();
        Set<Integer> afterCovered = after.coveredPorts();
 
        // Rule 1. The intersection is exactly the set of ports both scans can
        // answer for. Sorted, so a report reads in port order rather than in
        // whatever order the sets happened to iterate.
        Set<Integer> comparable = new TreeSet<>(beforeCovered);
        comparable.retainAll(afterCovered);
 
        Set<Integer> uncompared = new TreeSet<>(beforeCovered);
        uncompared.addAll(afterCovered);
        uncompared.removeAll(comparable);
 
        Map<Integer, Port> beforePorts = listedPorts(before);
        Map<Integer, Port> afterPorts = listedPorts(after);
 
        List<PortChange> changes = new ArrayList<>();
        for (int port : comparable) {
            PortObservation oldView = observe(before, beforePorts, port);
            PortObservation newView = observe(after, afterPorts, port);
            if (oldView == null || newView == null) {
                continue;       // cannot happen given the intersection, but not assumed
            }
            classify(port, protocolOf(beforePorts, afterPorts, port), oldView, newView)
                    .ifPresent(changes::add);
        }
 
        return new HostDiff(address, HostDiff.Presence.IN_BOTH, changes, uncompared,
                before.coverageIsComplete() && after.coverageIsComplete());
    }
 
    private static Map<Integer, Port> listedPorts(Host host) {
        Map<Integer, Port> ports = new LinkedHashMap<>();
        host.ports().forEach(port -> ports.put(port.number(), port));
        return ports;
    }
 
    private static Protocol protocolOf(Map<Integer, Port> before,
                                       Map<Integer, Port> after, int port) {
        Port listed = before.containsKey(port) ? before.get(port) : after.get(port);
        return listed == null ? Protocol.TCP : listed.protocol();
    }
 
    /** Builds the view of one port, from a listed entry or from a summary. */
    private static PortObservation observe(Host host, Map<Integer, Port> listed, int port) {
        Port entry = listed.get(port);
        if (entry != null) {
            return new PortObservation(entry.state(), entry.service(), false);
        }
        Optional<PortState> summarised = host.stateOf(port);
        return summarised.map(PortObservation::summarised).orElse(null);
    }
 
    // ----------------------------------------------------------- the rules
 
    /**
     * Rules 2 and 3, applied to one port both scans observed.
     *
     * @return the change, or empty when the two observations say the same thing
     *         or when nothing meaningful can be compared
     */
    private static Optional<PortChange> classify(int port, Protocol protocol,
                                                 PortObservation before,
                                                 PortObservation after) {
        // --- Rule 2: state. Directly observed on both sides, so a difference
        //     here is a difference in the host, summarised or not.
        if (before.state() != after.state()) {
            ChangeKind kind;
            if (after.isOpen()) {
                kind = ChangeKind.PORT_OPENED;
            } else if (before.isOpen()) {
                kind = ChangeKind.PORT_CLOSED;
            } else {
                kind = ChangeKind.STATE_CHANGED;
            }
            return Optional.of(new PortChange(port, protocol, kind, before, after));
        }
 
        // --- Rule 3: service. Only meaningful for a port that is open in both.
        //     A closed port's service name is a table guess about a port number,
        //     and comparing two of those compares nothing.
        if (!before.isOpen()) {
            return Optional.empty();
        }
 
        // No identification on one side -- typically because Nmap collapsed the
        // port into a summary. Not an evidence change: nothing was attempted and
        // then lost, the port simply was not listed individually.
        if (before.hasNoService() || after.hasNoService()) {
            return Optional.empty();
        }
 
        if (before.isProbed() && after.isProbed()) {
            if (!before.identity().equals(after.identity())) {
                return Optional.of(new PortChange(port, protocol,
                        ChangeKind.SERVICE_CHANGED, before, after));
            }
            if (!sameVersion(before.service(), after.service())) {
                return Optional.of(new PortChange(port, protocol,
                        ChangeKind.VERSION_CHANGED, before, after));
            }
            return Optional.empty();
        }
 
        // Exactly one side was probed. The direction matters: one of these means
        // CyberScope learned something, the other means it lost the ability to
        // confirm something. Neither is a statement about the host.
        if (after.isProbed()) {
            return Optional.of(new PortChange(port, protocol,
                    ChangeKind.EVIDENCE_GAINED, before, after));
        }
        if (before.isProbed()) {
            return Optional.of(new PortChange(port, protocol,
                    ChangeKind.EVIDENCE_LOST, before, after));
        }
 
        // Both inferred from the port number. A table lookup is a function of
        // the port, so it cannot differ unless the port did -- and the port is
        // the same. Nothing to say.
        return Optional.empty();
    }
 
    private static boolean sameVersion(Service before, Service after) {
        return before.version().equals(after.version())
            && before.extraInfo().equals(after.extraInfo());
    }
}
 

