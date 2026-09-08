package com.cyberscope.model;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * What one scan says about one host: two figures, never collapsed into one.
 *
 * <p>{@link #band()} answers <em>how exposed is this host</em>.
 * {@link #coverage()} answers <em>how much of it did we actually see</em>. The
 * second qualifies the first, and a surface that shows one without the other is
 * making a claim it cannot support.
 *
 * @param band              exposure, from the strongest evidence present
 * @param coverage          how much of the host could be assessed
 * @param openPorts         open services found
 * @param findingCount      total findings across every mapped service
 * @param exploitedCount    findings CISA confirms are exploited in the wild
 * @param findingsBySeverity histogram for the severity bars; never null
 * @param ranked            findings ordered by urgency, for recommended actions
 */
public record PostureAssessment(ExposureBand band, Coverage coverage,
                                int openPorts, int findingCount, int exploitedCount,
                                Map<Severity, Integer> findingsBySeverity,
                                List<RankedFinding> ranked) {

    public PostureAssessment {
        if (band == null || coverage == null) {
            throw new IllegalArgumentException("band and coverage are required");
        }
        // EnumMap(Map) throws IllegalArgumentException("Specified map is empty")
        // when handed an EMPTY map that is not itself an EnumMap -- it has no
        // other way to learn the key type. Map.of() is exactly that, so a caller
        // passing the most natural empty map got an exception from a constructor
        // whose whole job is to accept one. Found by a renderer test that built
        // a clean report; PostureScorer never hit it because it always builds an
        // EnumMap first.
        findingsBySeverity = findingsBySeverity == null || findingsBySeverity.isEmpty()
                ? new EnumMap<>(Severity.class)
                : new EnumMap<>(findingsBySeverity);
        ranked = ranked == null ? List.of() : List.copyOf(ranked);
    }

    /** A host with nothing open. Not the same as a host that is clear. */
    public static PostureAssessment empty() {
        return new PostureAssessment(ExposureBand.INDETERMINATE, Coverage.NONE,
                0, 0, 0, new EnumMap<>(Severity.class), List.of());
    }

    public int count(Severity severity) {
        return findingsBySeverity.getOrDefault(severity, 0);
    }

    /** Services that could not be looked up. Shown as its own bar, in grey. */
    public int uncheckedCount() {
        return coverage.unchecked();
    }

    /**
     * True only when the band is CLEAR.
     *
     * <p>Deliberately narrow, and deliberately not {@code band != CRITICAL}.
     * Five of the six bands are not good news and only one of them is.
     */
    public boolean isReassuring() {
        return band.isReassuring();
    }

    /** The worst few findings, for the recommended-actions card. */
    public List<RankedFinding> topActions(int limit) {
        return ranked.size() <= limit ? ranked : List.copyOf(ranked.subList(0, limit));
    }
}
