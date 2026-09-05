package com.cyberscope.repository;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * What one feed contains and how old it is.
 *
 * <p>One row per feed rather than one timestamp for the index, because the three
 * feeds move at completely different speeds:
 *
 * <pre>
 *   NVD corpus   grows ~584 CVEs/day; a full rebuild takes ~50 s
 *   EPSS         EVERY score is recomputed daily; a refresh takes ~2 s
 *   KEV          a handful of rows change per week; a refresh takes &lt;1 s
 * </pre>
 *
 * <p>A single "last refreshed" timestamp would be accurate for whichever feed
 * was updated most recently and misleading about the other two. Since the whole
 * argument of this project is that a stale answer must announce itself, three
 * feeds need three ages.
 *
 * @param source          feed identifier: {@code kev} or {@code epss}
 * @param fetchedAt       when CyberScope downloaded it
 * @param sourceTimestamp when the publisher generated it, if it said; may be null
 * @param recordCount     rows stored
 * @param sourceUrl       where it came from
 */
public record FeedMetadata(String source, Instant fetchedAt, Instant sourceTimestamp,
                           int recordCount, String sourceUrl) {

    /**
     * EPSS is recomputed every day, so a week-old copy is a week of drift in
     * every score. KEV changes far more slowly but a new entry is exactly the
     * event you want to hear about, so the same threshold applies to both.
     */
    public static final Duration STALE_AFTER = Duration.ofDays(7);

    private static final DateTimeFormatter WHEN =
            DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm");

    public FeedMetadata {
        if (source == null || source.isBlank()) {
            throw new IllegalArgumentException("source must not be blank");
        }
        if (fetchedAt == null) {
            throw new IllegalArgumentException("fetchedAt must not be null");
        }
    }

    /** Age of the data, measured from the publisher's timestamp where there is one. */
    public Duration age(Instant now) {
        Instant reference = sourceTimestamp != null ? sourceTimestamp : fetchedAt;
        Duration age = Duration.between(reference, now);
        return age.isNegative() ? Duration.ZERO : age;
    }

    public boolean isStale(Instant now) {
        return age(now).compareTo(STALE_AFTER) > 0;
    }

    public String describe(Instant now, ZoneId zone) {
        long days = age(now).toDays();
        String freshness = days == 0 ? "today" : days == 1 ? "1 day old" : days + " days old";
        return String.format("%s: %,d records, %s (%s)%s",
                source.toUpperCase(java.util.Locale.ROOT), recordCount, freshness,
                WHEN.format((sourceTimestamp != null ? sourceTimestamp : fetchedAt).atZone(zone)),
                isStale(now) ? "  [STALE]" : "");
    }
}