package com.cyberscope.model;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * One row of the dashboard: a target, its latest scan, and how that scan scored.
 *
 * <p>Carries the scan's age because <b>every figure in here is as old as the scan
 * it came from.</b> A CLEAR band on a scan from three weeks ago is a statement
 * about three weeks ago, and a dashboard that renders it identically to one taken
 * this morning is telling a quiet lie. The age travels with the assessment so the
 * two cannot be separated on screen.
 *
 * @param target     the target string, exactly as the user typed it
 * @param scanId     so a row can open the scan it came from
 * @param scannedAt  when the scan started
 * @param assessment the posture, scored against the CVE index as it is today
 * @param trend      movement since the previous scan of this same target
 */
public record TargetPosture(String target, long scanId, Instant scannedAt,
                            PostureAssessment assessment, PostureTrend trend) {

    /** A scan older than this is called out on the dashboard. */
    public static final Duration STALE_AFTER = Duration.ofDays(7);

    public TargetPosture {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(scannedAt, "scannedAt");
        Objects.requireNonNull(assessment, "assessment");
        Objects.requireNonNull(trend, "trend");
    }

    public ExposureBand band() {
        return assessment.band();
    }

    public Coverage coverage() {
        return assessment.coverage();
    }

    public Duration age(Instant now) {
        Duration age = Duration.between(scannedAt, now);
        // A clock that went backwards, or a scan saved on a machine ahead of this
        // one. Negative ages render as nonsense like "-3 days old"; clamping to
        // zero at least says "just now", which is closer to true than a negative.
        return age.isNegative() ? Duration.ZERO : age;
    }

    public boolean isStale(Instant now) {
        return age(now).compareTo(STALE_AFTER) >= 0;
    }

    /** e.g. {@code 6 days ago}, {@code 4 hours ago}, {@code just now}. */
    public String describeAge(Instant now) {
        Duration age = age(now);
        long days = age.toDays();
        if (days >= 1) {
            return days + (days == 1 ? " day ago" : " days ago");
        }
        long hours = age.toHours();
        if (hours >= 1) {
            return hours + (hours == 1 ? " hour ago" : " hours ago");
        }
        long minutes = age.toMinutes();
        return minutes < 1 ? "just now"
                           : minutes + (minutes == 1 ? " minute ago" : " minutes ago");
    }
}
