package com.cyberscope.model;

import java.util.Comparator;

/**
 * One finding, with enough context to act on it.
 *
 * <p>A CVE id on its own is not an action. "CVE-2023-44487" tells a reader
 * nothing about what to touch; "nginx 1.24.0 on 443/tcp" does. This record is
 * what the dashboard's recommended-actions list is built from.
 *
 * @param port          the open port the affected service was found on
 * @param product       the resolved {@code vendor:product version}
 * @param vulnerability the finding itself, carrying its own exploitation signal
 */
public record RankedFinding(Port port, String product, Vulnerability vulnerability) {

    /**
     * Recommended-action order: urgency, then exploitation probability, then
     * severity, then CVE id so the list is stable between runs.
     *
     * <p>Severity is third, not first. A CVSS CRITICAL nobody is exploiting is a
     * worse use of the reader's next hour than a CVSS HIGH that is in KEV, and
     * 47% of a typical host's findings are HIGH or CRITICAL -- so severity is a
     * tiebreak, not a sort key.
     *
     * <p>The {@code -1.0} for an unscored CVE is the load-bearing constant. EPSS
     * covers 366,252 of the index's 384,513 CVEs; the other 18,261 (4.7%) have
     * no score at all, which is a population, not a corner case. Sorting them as
     * 0.0 would be a claim they are safe and sorting them as 1.0 a claim they
     * are urgent; both are inventions. {@code -1.0} places them below every
     * scored finding <i>within their band</i>, which says the only true thing:
     * where there is measured evidence, act on that first.
     */
    public static final Comparator<RankedFinding> ACTION_ORDER =
            Comparator.comparingInt((RankedFinding f) -> f.urgency().rank()).reversed()
                    .thenComparing(Comparator.comparingDouble(
                            (RankedFinding f) -> f.vulnerability().signal().epssScore() == null
                                    ? -1.0 : f.vulnerability().signal().epssScore()).reversed())
                    .thenComparing(Comparator.comparingInt(
                            (RankedFinding f) -> f.vulnerability().severity().rank()).reversed())
                    .thenComparing(f -> f.vulnerability().cveId());


    public RankedFinding {
        if (port == null || vulnerability == null) {
            throw new IllegalArgumentException("port and vulnerability are required");
        }
        product = product == null ? "" : product;
    }

    /** e.g. {@code 443/tcp}. */
    public String where() {
        return port.number() + "/" + port.protocol().toString().toLowerCase(java.util.Locale.ROOT);
    }

    /**
     * The urgency this single finding justifies, using the same rule as the
     * host-level band so a card and a summary can never disagree.
     */
    public ExposureBand urgency() {
        ExploitSignal signal = vulnerability.signal();
        if (vulnerability.isWeaklyMatched()) {
            return ExposureBand.LOW;
        }
        if (signal.isRansomware()) {
            return ExposureBand.CRITICAL;
        }
        if (signal.isKnownExploited() || signal.epssAtLeast(0.5)) {
            return ExposureBand.HIGH;
        }
        if (signal.epssAtLeast(0.1) || vulnerability.severity() == Severity.CRITICAL) {
            return ExposureBand.ELEVATED;
        }
        return ExposureBand.LOW;
    }

    /** One line for the recommended-actions list. */
    public String describe() {
        StringBuilder out = new StringBuilder();
        out.append(product.isBlank() ? where() : product).append(" on ").append(where());
        out.append(" — ").append(vulnerability.cveId());
        ExploitSignal signal = vulnerability.signal();
        if (signal.isRansomware()) {
            out.append(" (exploited, used in ransomware)");
        } else if (signal.isKnownExploited()) {
            out.append(" (actively exploited)");
        } else if (signal.hasEpss()) {
            out.append(String.format(" (EPSS %.2f)", signal.epssScore()));
        }
        return out.toString();
    }
}
