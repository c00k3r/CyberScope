package com.cyberscope.model;

/**
 * Whether CISA has confirmed a vulnerability is being exploited in the wild.
 *
 * <p>The strongest signal available in public data, and by far the rarest:
 * 1,692 of the 384,513 CVEs in the corpus are listed, which is <b>0.44%</b>.
 * Compare with CVSS, which rates 47% of a typical host's findings HIGH or
 * CRITICAL. A flag that fires on half your findings is not triage; one that
 * fires on four in a thousand is.
 *
 * <p>{@link #RANSOMWARE} is a separate value rather than a boolean beside
 * {@link #LISTED} because it changes what a reader should do, not merely how
 * bad it is. 352 of the 1,692 KEV entries (21%) carry it.
 */
public enum KevStatus {

    /**
     * Not in the KEV catalogue.
     *
     * <p>Which means <em>not known to be exploited</em>, not <em>not
     * exploited</em>. KEV is a record of what CISA has confirmed, and the
     * catalogue grows precisely because things that were not on it turn out to
     * be exploited.
     */
    NOT_LISTED("not known to be exploited"),

    /** Confirmed exploited in the wild. */
    LISTED("known exploited"),

    /** Confirmed exploited, and used in ransomware campaigns. */
    RANSOMWARE("known exploited, used in ransomware");

    private final String description;

    KevStatus(String description) {
        this.description = description;
    }

    public String description() {
        return description;
    }

    /** True for both {@link #LISTED} and {@link #RANSOMWARE}. */
    public boolean isKnownExploited() {
        return this != NOT_LISTED;
    }
}