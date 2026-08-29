package com.cyberscope.model;

import java.util.Locale;

/**
 * A CVSS qualitative severity rating.
 *
 * <p>Two things about this enum are load-bearing.
 *
 * <p><b>{@link #UNKNOWN} is not {@link #NONE}.</b> 71,464 CVEs in the corpus carry
 * no CVSS score at all -- typically because NVD has not analysed them yet. "Not
 * scored" and "scored zero" are different facts and a report that renders them the
 * same way tells the reader an unanalysed advisory is harmless.
 *
 * <p><b>{@link #CRITICAL} and {@link #NONE} exist only in CVSS v3 and later.</b>
 * CVSS v2 rates everything LOW / MEDIUM / HIGH, so a v2-only CVE can never be
 * CRITICAL no matter how bad it is. That is a property of the scoring system, not
 * of the vulnerability, and it is why {@code Vulnerability} carries the CVSS
 * version alongside the rating.
 */
public enum Severity {

    CRITICAL(4), HIGH(3), MEDIUM(2), LOW(1), NONE(0), UNKNOWN(-1);

    private final int rank;

    Severity(int rank) {
        this.rank = rank;
    }

    /** Higher is worse. {@link #UNKNOWN} sorts below {@link #NONE} deliberately. */
    public int rank() {
        return rank;
    }

    public boolean isKnown() {
        return this != UNKNOWN;
    }

    /** True for the two ratings that warrant attention in a summary line. */
    public boolean isAtLeastHigh() {
        return this == HIGH || this == CRITICAL;
    }

    /**
     * Maps NVD's {@code baseSeverity} string.
     *
     * @return {@link #UNKNOWN} for null, blank, or anything unrecognised -- a
     *         rating we cannot interpret must not be silently downgraded to NONE
     */
    public static Severity fromNvd(String text) {
        if (text == null || text.isBlank()) {
            return UNKNOWN;
        }
        try {
            return valueOf(text.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException unrecognised) {
            return UNKNOWN;
        }
    }
}