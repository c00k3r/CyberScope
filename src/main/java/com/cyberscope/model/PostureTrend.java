package com.cyberscope.model;

/**
 * How a target's exposure moved since the scan before it.
 *
 * <p>Deliberately four values and not a number. A "risk score went from 78 to
 * 71" line invites arithmetic that the underlying data does not support --
 * {@link ExposureBand} is an ordinal scale, so the distance between CRITICAL and
 * HIGH is not a quantity and subtracting them produces a figure with no meaning.
 * What a reader can act on is the direction.
 *
 * <h2>Why UNKNOWN is separate from UNCHANGED</h2>
 *
 * A target scanned once has no previous band. Reporting that as "unchanged"
 * would be a claim about a comparison that was never made -- the same class of
 * false reassurance that {@link ExposureBand#INDETERMINATE} exists to prevent.
 * A first scan is a starting point, and the dashboard says so.
 *
 * <h2>Movement into or out of INDETERMINATE is not progress</h2>
 *
 * INDETERMINATE means "we could not see enough to say". Going from CLEAR to
 * INDETERMINATE is not a deterioration in the host, and going the other way is
 * not an improvement in the host; both are changes in what could be measured. So
 * either side being INDETERMINATE yields {@link #UNCOMPARABLE}, which the
 * dashboard renders as a neutral mark rather than an arrow.
 */
public enum PostureTrend {

    /** Exposure got worse than the previous scan of this target. */
    WORSENED("▲", "worse than the previous scan"),

    /** Exposure improved. */
    IMPROVED("▼", "better than the previous scan"),

    /** Same band as last time. */
    UNCHANGED("–", "unchanged since the previous scan"),

    /** One of the two scans could not be assessed well enough to compare. */
    UNCOMPARABLE("·", "not comparable: one of the two scans was indeterminate"),

    /** No previous scan of this target. */
    FIRST_SCAN("·", "first scan of this target");

    private final String mark;
    private final String meaning;

    PostureTrend(String mark, String meaning) {
        this.mark = mark;
        this.meaning = meaning;
    }

    /**
     * A single character for the table cell.
     *
     * <p>Never the only signal: {@link #meaning()} goes in the tooltip and the
     * band's own label sits in the adjacent column, so the arrow is redundant
     * coding for a colour-blind reader and in a greyscale screenshot.
     */
    public String mark() {
        return mark;
    }

    public String meaning() {
        return meaning;
    }

    /** True only for a real deterioration -- the one case worth colouring red. */
    public boolean isWorse() {
        return this == WORSENED;
    }

    public boolean isBetter() {
        return this == IMPROVED;
    }

    /**
     * Compares two bands.
     *
     * @param previous the band of the scan before this one, or null if none
     */
    public static PostureTrend between(ExposureBand previous, ExposureBand current) {
        if (previous == null) {
            return FIRST_SCAN;
        }
        if (previous == ExposureBand.INDETERMINATE || current == ExposureBand.INDETERMINATE) {
            return UNCOMPARABLE;
        }
        int delta = Integer.compare(current.rank(), previous.rank());
        if (delta > 0) {
            return WORSENED;
        }
        return delta < 0 ? IMPROVED : UNCHANGED;
    }
}
