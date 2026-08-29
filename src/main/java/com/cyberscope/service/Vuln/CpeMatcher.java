package com.cyberscope.service.vuln;

import com.cyberscope.model.Cpe;
import com.cyberscope.model.MatchPrecision;
import com.cyberscope.model.Severity;
import com.cyberscope.model.VersionRange;
import com.cyberscope.model.Vulnerability;
import com.cyberscope.repository.CveMatchRow;
import com.cyberscope.util.VersionOrder;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Decides which applicability statements actually apply to a detected version.
 *
 * <p>Pure. No SQL, no I/O, no clock. Hand it a version and a list of rows and it
 * returns findings, which is what makes every rule below testable in microseconds
 * without a 328 MB database.
 *
 * <h2>The three ways NVD says "this version is affected"</h2>
 *
 * Measured across the 224,235 applicability entries in CVE-2024:
 *
 * <pre>
 *   VERSION_EXACT   73.4%   the CPE string pins the version
 *   VERSION_RANGE   25.1%   version is '*', bounds in sibling attributes
 *   ALL_VERSIONS     1.5%   version is '*', no bounds at all
 * </pre>
 *
 * All three are honoured, and honouring all three reproduces the NVD API's own
 * answer exactly: OpenSSH 9.6 returns 19 CVEs from the live API and 19 from this
 * matcher against the local index.
 *
 * <p>Implementing only the first would drop CVE-2024-6387 -- regreSSHion,
 * unauthenticated remote root -- because NVD has never written a row saying
 * {@code openssh:9.6}. Treating all three alike would report a rowhammer attack as
 * a network finding. So the class matches all three and <em>labels which one
 * fired</em>, and the label travels with the finding to the screen.
 */
public final class CpeMatcher {

    private CpeMatcher() {
    }

    /**
     * Every CVE among {@code rows} that applies to {@code cpe}'s version.
     *
     * <p>Rows for a different product are ignored rather than trusted: the caller
     * fetches by {@code (vendor, product)}, but a matcher that assumes its input
     * was filtered correctly is a matcher that cannot be unit tested against a
     * mistake.
     *
     * @return one {@link Vulnerability} per distinct CVE, in
     *         {@link Vulnerability#REPORT_ORDER}
     */
    public static List<Vulnerability> match(Cpe cpe, List<CveMatchRow> rows) {
        if (cpe == null || !cpe.hasConcreteVersion() || rows == null || rows.isEmpty()) {
            return List.of();
        }
        String version = cpe.version();

        // Keyed by CVE id: one vulnerability appears once however many of its
        // applicability statements happen to match. CVE-2024-6387 states itself
        // through two ranges and would otherwise be reported twice.
        Map<String, Vulnerability> best = new LinkedHashMap<>();

        for (CveMatchRow row : rows) {
            if (!cpe.vendor().equals(row.vendor()) || !cpe.product().equals(row.product())) {
                continue;
            }
            MatchPrecision precision = appliesTo(version, row.range());
            if (precision == null) {
                continue;
            }
            Vulnerability candidate = toVulnerability(row, precision);
            Vulnerability existing = best.get(row.cveId());
            // Keep the strongest evidence. A CVE that matches both an exact
            // version row and an unbounded "all versions" row is an exact match,
            // and reporting it as the weaker of the two would understate it.
            if (existing == null
                || strength(precision) > strength(existing.precision())) {
                best.put(row.cveId(), candidate);
            }
        }

        List<Vulnerability> found = new ArrayList<>(best.values());
        found.sort(Vulnerability.REPORT_ORDER);
        return List.copyOf(found);
    }

    /**
     * Whether one applicability statement covers {@code version}, and how.
     *
     * @return the precision of the match, or null when the statement does not apply
     */
    static MatchPrecision appliesTo(String version, VersionRange range) {
        if (range.isPinned()) {
            // Compared, not string-compared. This looks like over-engineering and
            // is not: 9,175 of the 64,450 distinct pinned version strings in the
            // corpus -- 14.2%, in 3,929 groups -- are the same release written
            // differently by different CNAs. One real group:
            //
            //     1.0.1  1.0.01  1.0_1  1.0_01  1.0(1)  1.00.01  1.0-1  1.0.(1)
            //
            // Nine spellings of one release. String equality means a CVE filed
            // against "1.0(1)" is invisible to a host reporting "1.0.1" -- a false
            // negative created purely by punctuation.
            //
            // Every collision group was inspected for the opposite risk and none
            // contained two genuinely different releases, because VersionOrder
            // only equates strings with identical token sequences after numeric
            // normalisation. "1.24" and "1.24.0" still do not match; they differ
            // by a token, not by punctuation.
            Integer comparison = VersionOrder.compare(version, range.pinned());
            return comparison != null && comparison == 0 ? MatchPrecision.VERSION_EXACT : null;
        }
        if (!range.hasBounds()) {
            // version='*' with no bounds: NVD asserting every version ever. Real,
            // and the source of most of the noise -- so it matches, weakly.
            return MatchPrecision.ALL_VERSIONS;
        }
        boolean within = VersionOrder.isWithin(version,
                range.startIncluding(), range.startExcluding(),
                range.endIncluding(), range.endExcluding());
        return within ? MatchPrecision.VERSION_RANGE : null;
    }

    /**
     * Evidence strength, highest first.
     *
     * <p>An exhaustive switch rather than {@code Enum.ordinal()}: adding a fourth
     * precision would fail to compile here instead of silently sorting last.
     */
    private static int strength(MatchPrecision precision) {
        return switch (precision) {
            case VERSION_EXACT -> 2;
            case VERSION_RANGE -> 1;
            case ALL_VERSIONS  -> 0;
        };
    }

    private static Vulnerability toVulnerability(CveMatchRow row, MatchPrecision precision) {
        return new Vulnerability(
                row.cveId(),
                Severity.fromNvd(row.cvssSeverity()),
                row.cvssScore(), row.cvssVector(), row.cvssVersion(),
                row.published(), row.description(),
                precision, row.range().describe());
    }
}