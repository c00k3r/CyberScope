package com.cyberscope.repository;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * What the CVE index is, and how old.
 *
 * <p>A vulnerability database is a claim with an expiry date. Between the two
 * builds made while designing this version the corpus grew by <b>584 CVEs in a
 * single day</b> -- 383,929 on 28 August, 384,513 on 29 August. An index a week
 * old is missing roughly four thousand advisories, and nothing about a scan
 * report makes that visible unless the report says so.
 *
 * <p>Two different timestamps are kept, because they answer different questions:
 *
 * <ul>
 *   <li>{@code feedTimestamp} -- when the <em>data</em> was assembled upstream.
 *       This is the honest measure of how old the facts are.</li>
 *   <li>{@code builtAt} -- when <em>we</em> last refreshed. This is what the user
 *       controls, and what a "refresh now" button changes.</li>
 * </ul>
 *
 * <p>Reporting only the second would let a stale mirror look fresh: download a
 * three-week-old feed today and {@code builtAt} says "up to date" while the data
 * is three weeks behind.
 *
 * @param feedTimestamp when the upstream feed was generated; may be null if the
 *                      feed omitted it
 * @param builtAt       when this index finished building locally
 * @param source        the URL family the data came from, recorded so a future
 *                      version can tell a switched data source from a refresh
 * @param cveCount      rows in {@code cve}
 * @param matchCount    rows in {@code cve_match}
 * @param firstYear     earliest CVE year file included
 * @param lastYear      latest CVE year file included
 */
public record IndexMetadata(Instant feedTimestamp, Instant builtAt, String source,
                            int cveCount, int matchCount, int firstYear, int lastYear) {

    /**
     * How long an index may go unrefreshed before the report warns about it.
     *
     * <p>Seven days, chosen from the measured publication rate rather than picked
     * for roundness: at ~584 new CVEs per day, a week-old index is missing on the
     * order of four thousand advisories. That is the point at which "no known
     * vulnerabilities" stops being a statement about the host and starts being a
     * statement about the index.
     */
    public static final Duration STALE_AFTER = Duration.ofDays(7);

    private static final DateTimeFormatter WHEN =
            DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm");

    public IndexMetadata {
        if (builtAt == null) {
            throw new IllegalArgumentException("builtAt must not be null");
        }
        if (source == null || source.isBlank()) {
            throw new IllegalArgumentException("source must not be blank");
        }
    }

    /**
     * How old the underlying data is.
     *
     * <p>Measured from {@code feedTimestamp} when it is known, and from
     * {@code builtAt} only as a fallback -- the age of the data is the question,
     * not the age of our copy of it.
     */
    public Duration age(Instant now) {
        Instant reference = feedTimestamp != null ? feedTimestamp : builtAt;
        Duration age = Duration.between(reference, now);
        // A clock skew, or a feed timestamp slightly in the future, must not
        // present as a negative age. Zero is the honest floor.
        return age.isNegative() ? Duration.ZERO : age;
    }

    public boolean isStale(Instant now) {
        return age(now).compareTo(STALE_AFTER) > 0;
    }

    /** One line for a report header or a status bar. */
    public String describe(Instant now, ZoneId zone) {
        long days = age(now).toDays();
        String freshness = days == 0 ? "today"
                : days == 1 ? "1 day old"
                : days + " days old";
        return String.format("%,d CVEs covering %d-%d, %s (feed %s)%s",
                cveCount, firstYear, lastYear, freshness,
                WHEN.format((feedTimestamp != null ? feedTimestamp : builtAt).atZone(zone)),
                isStale(now) ? "  [STALE -- refresh recommended]" : "");
    }
}