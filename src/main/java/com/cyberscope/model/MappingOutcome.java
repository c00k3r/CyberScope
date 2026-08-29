package com.cyberscope.model;

/**
 * What happened when CyberScope tried to look a service up in the CVE index.
 *
 * <p>This enum is the point of v0.5.0. Every scanner reports vulnerabilities;
 * the four values below exist so that CyberScope can also report the three
 * different ways a lookup can fail to produce any -- which every scanner examined
 * while designing this renders identically, as an empty list.
 *
 * <p>The distinction is not academic. Nmap identifies nginx as
 * {@code cpe:/a:igor_sysoev:nginx}. That vendor string appears zero times in the
 * entire 1999-2026 NVD corpus, because NVD files nginx under {@code f5} following
 * the 2019 acquisition -- with 41 CVEs. A scanner that prints an empty list here
 * has told the user their web server is clean. It is not clean; the question was
 * never asked.
 */
public enum MappingOutcome {

    /**
     * A CPE was resolved and the index was searched.
     *
     * <p><b>Zero results is a real answer here</b>, and the only one of the four
     * that may be read as "nothing known against this version".
     */
    MAPPED("looked up"),

    /**
     * Nmap gave a product and a version, but the index has nothing filed under
     * that vendor and product at all.
     *
     * <p>The interesting state. It means the question could not be asked, not
     * that the answer was no.
     */
    UNRESOLVED("could not be looked up"),

    /**
     * There was nothing to look up: no version was detected.
     *
     * <p>Produced by every {@code TABLE} service, because a table lookup is a
     * guess from a port number and carries no CPE. Nmap reports a plain Python
     * HTTP server on 8080 as {@code name="http-proxy" method="table"} with no
     * product, no version and no CPE -- a guess that is also wrong.
     */
    NOT_APPLICABLE("no version detected"),

    /**
     * The CVE index has never been built, or could not be opened.
     *
     * <p>Distinct from {@link #MAPPED} with no results for the same reason as
     * {@link #UNRESOLVED}: the absence of findings says nothing about the host.
     */
    INDEX_UNAVAILABLE("no CVE index");

    private final String summary;

    MappingOutcome(String summary) {
        this.summary = summary;
    }

    public String summary() {
        return summary;
    }

    /**
     * True only for {@link #MAPPED}.
     *
     * <p>The guard every caller should use before writing a sentence containing
     * the word "clean". Reads as a single condition at the call site so that
     * adding a fifth outcome later cannot silently widen it.
     */
    public boolean isConclusive() {
        return this == MAPPED;
    }
}