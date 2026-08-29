package com.cyberscope.repository;

import com.cyberscope.model.VersionRange;

import java.time.Instant;

/**
 * One applicability statement joined to the CVE it belongs to.
 *
 * <p>This is what crosses the repository boundary: a flat row, not a domain
 * object. {@code service/vuln/} turns a stream of these into
 * {@code model.Vulnerability} objects in Part 3 -- deciding, per row, whether the
 * detected version actually satisfies {@link #range()} and with what
 * {@code MatchPrecision}.
 *
 * <p>The repository deliberately does <b>not</b> make that decision. Version
 * comparison is domain logic and it belongs above the SQL, for the same reason
 * {@code ScanRepository} returns rows rather than verdicts: the moment a
 * repository starts deciding what is true, the rules become untestable without a
 * database.
 *
 * <p>One row per applicability statement, so a single CVE can appear several
 * times for the same product with different ranges. CVE-2024-6387 does exactly
 * that: {@code < 4.4} and {@code >= 8.6, <= 9.8} are two statements about one
 * vulnerability.
 */
public record CveMatchRow(String cveId,
                          Double cvssScore, String cvssSeverity,
                          String cvssVector, String cvssVersion,
                          Instant published, String description,
                          String vendor, String product,
                          VersionRange range) {

    public CveMatchRow {
        if (cveId == null || cveId.isBlank()) {
            throw new IllegalArgumentException("cveId must not be blank");
        }
        if (range == null) {
            throw new IllegalArgumentException("range must not be null");
        }
        description = description == null ? "" : description;
    }

    /** The canonical NVD page, for the report and for a clickable cell later. */
    public String nvdUrl() {
        return "https://nvd.nist.gov/vuln/detail/" + cveId;
    }
}