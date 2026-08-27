package com.cyberscope.service.compare;
 
import com.cyberscope.model.Protocol;
 
import java.util.Objects;
 
/**
 * One difference at one port, between two scans that both covered it.
 *
 * <p>A {@code PortChange} is only ever constructed for a port <em>both</em>
 * scans observed. A port only one scan covered produces no change of any kind:
 * see {@link HostDiff#uncomparedPorts()}.
 *
 * @param protocol carried from whichever side reported it individually.
 *                 CyberScope runs TCP scans only, so this is always TCP today;
 *                 it is the field that would have to join the comparison key if
 *                 UDP scanning is ever added, because 53/tcp and 53/udp are
 *                 different ports and must not be compared with each other
 */
public record PortChange(int port, Protocol protocol, ChangeKind kind,
                         PortObservation before, PortObservation after) {
 
    public PortChange {
        Objects.requireNonNull(kind, "kind must not be null");
        Objects.requireNonNull(before, "before must not be null");
        Objects.requireNonNull(after, "after must not be null");
        protocol = protocol == null ? Protocol.TCP : protocol;
    }
 
    /** Whether this describes the target or our view of it. */
    public boolean isHostChange() {
        return kind.isHostChange();
    }
 
    /**
     * A one-line description, built from the fields this record already holds.
     *
     * <p>A convenience over data the caller has, not a presentation decision
     * baked into the model -- the same justification as
     * {@code PortSummary.reasonNames()}. A UI that wants different wording
     * still has everything it needs.
     */
    public String describe() {
        String where = port + "/" + protocol;
        return switch (kind) {
            case PORT_OPENED -> where + " opened"
                    + (after.hasNoService() ? "" : "  " + after.service().describe());
            case PORT_CLOSED -> where + " closed (was "
                    + (before.hasNoService() ? "open" : before.service().describe()) + ")";
            case STATE_CHANGED -> where + " " + before.state() + " -> " + after.state();
            case SERVICE_CHANGED -> where + " service changed: "
                    + before.service().describe() + " -> " + after.service().describe();
            case VERSION_CHANGED -> where + " version changed: "
                    + before.service().describe() + " -> " + after.service().describe();
            case EVIDENCE_GAINED -> where + " now probed (was inferred): "
                    + after.service().describe()
                    + "  confidence " + before.service().confidence()
                    + " -> " + after.service().confidence();
            case EVIDENCE_LOST -> where + " no longer probed, only inferred"
                    + "  confidence " + before.service().confidence()
                    + " -> " + after.service().confidence()
                    + "  (the host may be unchanged; it can no longer be confirmed)";
        };
    }
}
 

