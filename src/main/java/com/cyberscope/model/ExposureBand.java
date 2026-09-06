package com.cyberscope.model;

/**
 * How exposed a host is, expressed as a band rather than a number.
 *
 * <h2>Why not a score out of 100</h2>
 *
 * A number invites arithmetic that is not meaningful. Is a host at 62 in worse
 * shape than one at 71? Is 73 findings twice as bad as 36? Neither question has
 * an answer, but a number implies both do.
 *
 * <p>Worse, any number computed from a count of findings is measurably wrong.
 * Against the real index:
 *
 * <pre>
 *   product                  CVE count  max EPSS  KEV
 *   oracle:mysql                    73    0.0111    0
 *   f5:nginx                         2    1.0000    1
 * </pre>
 *
 * A count ranks MySQL 36 times worse than nginx. nginx is the one being
 * exploited. A CVE count measures how diligently a vendor's PSIRT publishes
 * advisories, not how exposed a host is.
 *
 * <h2>The rule</h2>
 *
 * The band is driven by the <b>strongest evidence present</b>, never by a total.
 * One actively-exploited vulnerability outranks seventy quiet ones, which is how
 * a person would triage it and is not how a sum behaves.
 *
 * <p>Findings matched only through an unbounded "all versions" claim are
 * excluded from the decision. Those are the class that puts a 2008 Red Hat
 * packaging incident on a 2024 OpenSSH; they are reported, but they do not get
 * to set the band.
 */
public enum ExposureBand {

    /** Something here is exploited in the wild AND used in ransomware campaigns. */
    CRITICAL(5, "Critical", "actively exploited in ransomware campaigns"),

    /** Exploited in the wild, or an EPSS score at or above 0.5. */
    HIGH(4, "High", "actively exploited, or very likely to be"),

    /** EPSS at or above 0.1, or a CRITICAL CVSS on well-evidenced matching. */
    ELEVATED(3, "Elevated", "elevated likelihood of exploitation"),

    /** Findings exist, but nothing suggests they are being exploited. */
    LOW(2, "Low", "known vulnerabilities, no evidence of exploitation"),

    /** Every service was looked up and nothing is filed against any of them. */
    CLEAR(1, "Clear", "looked up, nothing filed"),

    /**
     * Too little of the host could be assessed for a band to mean anything.
     *
     * <p>Note what this is <em>not</em> applied to. A CRITICAL or HIGH finding is
     * positive evidence and survives poor coverage untouched -- discovering an
     * exploited service does not become less true because other services could
     * not be checked. It is <b>reassurance</b> that low coverage destroys, so
     * only a band that would have been {@link #CLEAR} or {@link #LOW} degrades
     * to this one.
     */
    INDETERMINATE(0, "Indeterminate", "too little of this host could be checked");

    private final int rank;
    private final String label;
    private final String meaning;

    ExposureBand(int rank, String label, String meaning) {
        this.rank = rank;
        this.label = label;
        this.meaning = meaning;
    }

    /** Higher is worse. {@link #INDETERMINATE} is lowest and is not "good". */
    public int rank() {
        return rank;
    }

    public String label() {
        return label;
    }

    public String meaning() {
        return meaning;
    }

    /** True for the bands that describe something the user should act on today. */
    public boolean needsAction() {
        return this == CRITICAL || this == HIGH;
    }

    /**
     * True only for {@link #CLEAR}.
     *
     * <p>The single method any "this host looks fine" message must go through,
     * for the same reason {@code VulnAssessment.isConfirmedClean()} exists one
     * layer down: {@code band != CRITICAL} is easy to write and true of five
     * values, only one of which is good news.
     */
    public boolean isReassuring() {
        return this == CLEAR;
    }
}
