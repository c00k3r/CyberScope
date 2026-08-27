package com.cyberscope.service.compare;
 
import com.cyberscope.service.scanner.ScanOutcome;
 
import java.time.Duration;
import java.util.List;
import java.util.Objects;
 
/**
 * The result of comparing two scans.
 *
 * <p>{@code before} is always the older of the two, whatever order they were
 * handed to the comparator in. Normalising that removes a whole class of
 * confusing output -- a diff that reports a port as having closed when it in
 * fact opened is worse than no diff.
 */
public record ScanDiff(ScanOutcome before, ScanOutcome after,
                       List<HostDiff> hosts, List<DiffWarning> warnings) {
 
    public ScanDiff {
        Objects.requireNonNull(before, "before must not be null");
        Objects.requireNonNull(after, "after must not be null");
        hosts    = hosts    == null ? List.of() : List.copyOf(hosts);
        warnings = warnings == null ? List.of() : List.copyOf(warnings);
    }
 
    /** How much time separates the two scans. */
    public Duration interval() {
        return Duration.between(before.run().startedAt(), after.run().startedAt());
    }
 
    /** Every difference that describes the target, across all hosts. */
    public List<PortChange> hostChanges() {
        return hosts.stream().flatMap(h -> h.hostChanges().stream()).toList();
    }
 
    /** Every difference that describes our view of the target. */
    public List<PortChange> evidenceChanges() {
        return hosts.stream().flatMap(h -> h.evidenceChanges().stream()).toList();
    }
 
    public List<HostDiff> addedHosts() {
        return hosts.stream().filter(h -> h.presence() == HostDiff.Presence.ADDED).toList();
    }
 
    public List<HostDiff> removedHosts() {
        return hosts.stream().filter(h -> h.presence() == HostDiff.Presence.REMOVED).toList();
    }
 
    /**
     * True when at least one warning means these differences should not be read
     * as changes to a host.
     */
    public boolean isTrustworthy() {
        return warnings.stream().noneMatch(DiffWarning::invalidatesComparison);
    }
 
    /**
     * True when nothing changed and nothing was added or removed.
     *
     * <p>Says nothing about coverage. "No changes found" and "nothing changed"
     * are different claims, and only the first is one this class can make.
     */
    public boolean isEmpty() {
        return hosts.stream().allMatch(HostDiff::isUnchanged);
    }
}
 

