package com.cyberscope.model;

import java.util.Optional;

/**
 * One applicability statement's version constraint, exactly as NVD expresses it.
 *
 * <p>Deliberately a dumb record. It holds the four bounds and the pinned version
 * and answers structural questions about itself; it does not know how to compare
 * two version strings. That logic lives in {@code util.VersionOrder}, because
 * {@code model/} does not depend on {@code util/} -- the same layering rule this
 * project has had since v0.0.6 -- and because a comparator that cannot always
 * decide (see {@code VersionOrder}) does not belong inside a value object whose
 * methods look total.
 *
 * <p>{@code service/vuln/CpeMatcher} in Part 3 combines the two.
 *
 * @param pinned        the version named in the CPE string, or {@link Cpe#ANY}
 * @param startIncluding lower bound, inclusive; may be null
 * @param startExcluding lower bound, exclusive; may be null
 * @param endIncluding   upper bound, inclusive; may be null
 * @param endExcluding   upper bound, exclusive; may be null
 */
public record VersionRange(String pinned,
                           String startIncluding, String startExcluding,
                           String endIncluding, String endExcluding) {

    public VersionRange {
        pinned = (pinned == null || pinned.isBlank()) ? Cpe.ANY : pinned;
        startIncluding = blankToNull(startIncluding);
        startExcluding = blankToNull(startExcluding);
        endIncluding = blankToNull(endIncluding);
        endExcluding = blankToNull(endExcluding);
    }

    /** A statement that pins one exact version. */
    public static VersionRange exactly(String version) {
        return new VersionRange(version, null, null, null, null);
    }

    /** A statement with a wildcard version and no bounds: every version. */
    public static VersionRange allVersions() {
        return new VersionRange(Cpe.ANY, null, null, null, null);
    }

    /** True when the CPE string named a concrete version rather than {@code *}. */
    public boolean isPinned() {
        return !Cpe.ANY.equals(pinned);
    }

    /** True when at least one of the four bounds is present. */
    public boolean hasBounds() {
        return startIncluding != null || startExcluding != null
            || endIncluding != null || endExcluding != null;
    }

    /**
     * The precision this statement can produce, before any version is considered.
     *
     * <p>Structural, not evaluative: it says what <em>kind</em> of claim this is,
     * not whether a given version satisfies it.
     */
    public MatchPrecision precision() {
        if (isPinned()) {
            return MatchPrecision.VERSION_EXACT;
        }
        return hasBounds() ? MatchPrecision.VERSION_RANGE : MatchPrecision.ALL_VERSIONS;
    }

    public Optional<String> lowerBound() {
        return Optional.ofNullable(startIncluding != null ? startIncluding : startExcluding);
    }

    public Optional<String> upperBound() {
        return Optional.ofNullable(endIncluding != null ? endIncluding : endExcluding);
    }

    /** A short human-readable form for the report, e.g. {@code >= 8.6, <= 9.8}. */
    public String describe() {
        if (isPinned()) {
            return "= " + pinned;
        }
        if (!hasBounds()) {
            return "all versions";
        }
        StringBuilder out = new StringBuilder();
        if (startIncluding != null) out.append(">= ").append(startIncluding);
        if (startExcluding != null) append(out, "> " + startExcluding);
        if (endIncluding != null)   append(out, "<= " + endIncluding);
        if (endExcluding != null)   append(out, "< " + endExcluding);
        return out.toString();
    }

    private static void append(StringBuilder out, String clause) {
        if (out.length() > 0) {
            out.append(", ");
        }
        out.append(clause);
    }

    private static String blankToNull(String value) {
        return (value == null || value.isBlank()) ? null : value;
    }
}