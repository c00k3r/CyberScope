package com.cyberscope.model;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * One host as a scan found it.
 *
 * @param ports     the ports Nmap reported individually -- open ones, and small
 *                  numbers of closed or filtered ones
 * @param summaries the ports Nmap collapsed into {@code <extraports>} blocks.
 *                  Added in v0.4.0; without it a 100-port scan looked like a
 *                  1-port scan. See {@link PortSummary}.
 */
public record Host(String ipAddress, String hostname, HostState state,
                   List<Port> ports, List<PortSummary> summaries) {

    public Host {
        Objects.requireNonNull(ipAddress, "ipAddress must not be null");
        hostname  = hostname  == null ? "" : hostname.trim();
        state     = state     == null ? HostState.UNKNOWN : state;
        ports     = ports     == null ? List.of() : List.copyOf(ports);
        summaries = summaries == null ? List.of() : List.copyOf(summaries);
    }

    /**
     * Kept so that every construction site from v0.0.6 onwards still compiles.
     *
     * <p>A host with no summaries is a truthful description of a scan that
     * reported every port individually -- it is not a placeholder or an unknown
     * value. That is why this overload is safe to keep, rather than a
     * deprecation waiting to happen.
     */
    public Host(String ipAddress, String hostname, HostState state, List<Port> ports) {
        this(ipAddress, hostname, state, ports, List.of());
    }

    public boolean isUp()        { return state == HostState.UP; }
    public boolean hasHostname() { return !hostname.isBlank(); }

    public List<Port> openPorts() {
        return ports.stream().filter(Port::isOpen).toList();
    }

    public String displayName() {
        return hasHostname() ? hostname + " (" + ipAddress + ")" : ipAddress;
    }

    // -------------------------------------------------------------- coverage

    /**
     * How many ports this scan examined: the individually reported ones plus
     * every port collapsed into a summary.
     *
     * <p>This is the number a report should quote. "1 open port" is not a
     * result. "1 open port out of 100 scanned" is.
     */
    public int scannedPortCount() {
        return ports.size() + summaries.stream().mapToInt(PortSummary::count).sum();
    }

    /**
     * Every port number this scan is known to have examined.
     *
     * <p>Incomplete when a summary carried no port list -- see
     * {@link PortSummary#hasPortNumbers()}. Check {@link #coverageIsComplete()}
     * before drawing any conclusion from a port's absence.
     */
    public Set<Integer> coveredPorts() {
        Set<Integer> covered = new LinkedHashSet<>();
        ports.forEach(p -> covered.add(p.number()));
        summaries.forEach(s -> covered.addAll(s.ports()));
        return Set.copyOf(covered);
    }

    /**
     * True when every port this scan examined can be named.
     *
     * <p>False means some summary counted more ports than it named, so
     * {@link #coveredPorts()} is a subset of what was really scanned. A
     * comparison must not treat a port's absence from an incomplete set as
     * evidence that the port was never scanned.
     */
    public boolean coverageIsComplete() {
        return summaries.stream().allMatch(PortSummary::isFullyEnumerated);
    }

    /**
     * What state a given port was in, if this scan looked at it.
     *
     * <p>{@code Optional.empty()} means "this scan cannot answer that" -- either
     * the port was outside the scanned set, or coverage is incomplete. It does
     * <em>not</em> mean the port was closed. Conflating those two is how a diff
     * invents a change that never happened.
     */
    public Optional<PortState> stateOf(int portNumber) {
        for (Port port : ports) {
            if (port.number() == portNumber) {
                return Optional.of(port.state());
            }
        }
        for (PortSummary summary : summaries) {
            if (summary.ports().contains(portNumber)) {
                return Optional.of(summary.state());
            }
        }
        return Optional.empty();
    }
}