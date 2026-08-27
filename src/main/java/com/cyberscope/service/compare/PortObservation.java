package com.cyberscope.service.compare;
 
import com.cyberscope.model.DetectionMethod;
import com.cyberscope.model.PortState;
import com.cyberscope.model.Service;
 
import java.util.Objects;
 
/**
 * What one scan saw at one port.
 *
 * <p>Deliberately not {@code Port}. A port Nmap collapsed into an
 * {@code <extraports>} block has a state and nothing else — no service, no
 * reason of its own — so it cannot be a {@code Port}, and inventing one would
 * mean inventing a {@code Service} to go in it.
 *
 * @param state       what the scan observed. Always known: an observation is
 *                    only constructed for a port the scan actually covered
 * @param service     the identification, or {@link Service#UNKNOWN} when there
 *                    was none — which is always the case for a summarised port
 * @param fromSummary true when this came from an {@code <extraports>} block
 *                    rather than an individually reported {@code <port>}
 */
public record PortObservation(PortState state, Service service, boolean fromSummary) {
 
    public PortObservation {
        Objects.requireNonNull(state, "state must not be null");
        service = service == null ? Service.UNKNOWN : service;
    }
 
    /** A port a scan covered but did not identify — the summarised case. */
    public static PortObservation summarised(PortState state) {
        return new PortObservation(state, Service.UNKNOWN, true);
    }
 
    public boolean isOpen() {
        return state == PortState.OPEN;
    }
 
    /**
     * True when the service here was confirmed by an actual probe.
     *
     * <p>The gate on every service and version comparison. Two {@code table}
     * guesses agreeing proves nothing, and a {@code table} guess differing from
     * a probe result is a difference in method, not in the host.
     */
    public boolean isProbed() {
        return service.method() == DetectionMethod.PROBED;
    }
 
    /** True when no identification was attempted or none succeeded. */
    public boolean hasNoService() {
        return service.method() == DetectionMethod.NONE;
    }
 
    /**
     * What the service is, ignoring its version.
     *
     * <p>Used to tell "nginx became Apache" (a different service) from
     * "nginx 1.24 became nginx 1.26" (the same service, upgraded). Those want
     * different words in a report and, later, different weights in a score.
     */
    public String identity() {
        return service.name() + "/" + service.product();
    }
}
 

