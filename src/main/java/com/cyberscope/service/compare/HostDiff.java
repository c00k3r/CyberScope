package com.cyberscope.service.compare;
 
import java.util.List;
import java.util.Objects;
import java.util.Set;
 
/**
 * How one host differs between two scans.
 *
 * @param presence       whether the host appeared in both scans
 * @param changes        differences at ports both scans covered
 * @param uncomparedPorts ports one scan covered and the other did not. These
 *                       are <strong>not</strong> changes and must never be
 *                       reported as any: a port absent from one scan's coverage
 *                       says nothing about the host
 * @param coverageComplete false when either scan counted ports it could not
 *                       name, so even {@code uncomparedPorts} understates what
 *                       could not be compared
 */
public record HostDiff(String address, Presence presence,
                       List<PortChange> changes,
                       Set<Integer> uncomparedPorts,
                       boolean coverageComplete) {
 
    public enum Presence { IN_BOTH, ADDED, REMOVED }
 
    public HostDiff {
        Objects.requireNonNull(address, "address must not be null");
        Objects.requireNonNull(presence, "presence must not be null");
        changes = changes == null ? List.of() : List.copyOf(changes);
        uncomparedPorts = uncomparedPorts == null ? Set.of() : Set.copyOf(uncomparedPorts);
    }
 
    /** Differences that describe the target rather than our view of it. */
    public List<PortChange> hostChanges() {
        return changes.stream().filter(PortChange::isHostChange).toList();
    }
 
    /** Differences in detection quality: the host may be entirely unchanged. */
    public List<PortChange> evidenceChanges() {
        return changes.stream().filter(c -> !c.isHostChange()).toList();
    }
 
    /**
     * True when nothing at all was found.
     *
     * <p>Note what this does not consider: {@code uncomparedPorts}. A host with
     * no changes and forty uncompared ports is unchanged <em>as far as these two
     * scans can tell</em>, which is a weaker statement than "unchanged" and one
     * a report should make carefully.
     */
    public boolean isUnchanged() {
        return presence == Presence.IN_BOTH && changes.isEmpty();
    }
 
    /** True when the two scans could not see the same set of ports. */
    public boolean hasCoverageGap() {
        return !uncomparedPorts.isEmpty() || !coverageComplete;
    }
}
 

