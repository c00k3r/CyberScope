package com.cyberscope.model;

/**
 * How a CVE's applicability statement matched the version we detected.
 *
 * <p>NVD expresses "which versions are affected" in three structurally different
 * ways, and they carry different amounts of information. Measured across the
 * 224,235 applicability entries in CVE-2024:
 *
 * <pre>
 *   VERSION_EXACT   73.4%   the CPE string pins the version
 *   VERSION_RANGE   25.1%   version is '*', bounds in sibling attributes
 *   ALL_VERSIONS     1.5%   version is '*', no bounds at all
 * </pre>
 *
 * <p>Honouring all three reproduces the NVD API's own answer exactly (verified:
 * OpenSSH 9.6 returns 19 CVEs from the live API and 19 from this index). Honouring
 * only the first drops CVE-2024-6387 -- regreSSHion, unauthenticated root RCE --
 * because NVD never wrote a row saying "openssh:9.6".
 *
 * <p>So all three match. The precision is carried alongside the finding rather
 * than being used to filter it, because the third class is genuinely weaker
 * evidence and the reader is entitled to know which one fired.
 */
public enum MatchPrecision {

    /** The CPE named this exact version. Strongest. */
    VERSION_EXACT("exact version match"),

    /** The detected version fell inside a declared range. */
    VERSION_RANGE("version in affected range"),

    /**
     * The CPE claimed every version, with no bounds.
     *
     * <p>Weakest, and the class that produces most of the noise. For OpenSSH 9.6
     * this class contributes a 2007 PAM/OPIE configuration issue, a 2008 Red Hat
     * <em>packaging</em> compromise, and a rowhammer attack requiring physical
     * DRAM access -- all three technically true and none of them a network finding.
     */
    ALL_VERSIONS("applies to all versions");

    private final String description;

    MatchPrecision(String description) {
        this.description = description;
    }

    /** Human-readable, for the report and the table. */
    public String description() {
        return description;
    }

    /** True for the class that warrants a caveat in the report. */
    public boolean isWeak() {
        return this == ALL_VERSIONS;
    }
}