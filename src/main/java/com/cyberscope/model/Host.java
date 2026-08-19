package com.cyberscope.model;

import java.util.List;
import java.util.Objects;

/**
 * A host discovered by a scan.
 *
 * @param hostname the reverse-DNS name, or "" — Nmap emits an empty
 *                 {@code <hostnames>} element when there is no PTR record
 */
public record Host(String ipAddress, String hostname, HostState state, List<Port> ports) {

    public Host {
        Objects.requireNonNull(ipAddress, "ipAddress must not be null");
        hostname = hostname == null ? "" : hostname.trim();
        state    = state    == null ? HostState.UNKNOWN : state;
        ports    = ports    == null ? List.of() : List.copyOf(ports);
    }

    public boolean isUp() {
        return state == HostState.UP;
    }

    public boolean hasHostname() {
        return !hostname.isBlank();
    }

    /** Only the ports Nmap reported as strictly open. */
    public List<Port> openPorts() {
        return ports.stream().filter(Port::isOpen).toList();
    }

    /** e.g. "localhost (127.0.0.1)", or just the address when no name is known. */
    public String displayName() {
        return hasHostname() ? hostname + " (" + ipAddress + ")" : ipAddress;
    }
}
