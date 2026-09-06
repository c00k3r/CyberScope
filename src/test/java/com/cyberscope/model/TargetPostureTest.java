package com.cyberscope.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * How old a figure is, which on this dashboard is part of the figure.
 */
class TargetPostureTest {

    private static final Instant NOW = Instant.parse("2026-09-06T12:00:00Z");

    private static TargetPosture at(Instant when) {
        return new TargetPosture("192.168.1.14", 7L, when,
                PostureAssessment.empty(), PostureTrend.FIRST_SCAN);
    }

    private static TargetPosture ago(Duration age) {
        return at(NOW.minus(age));
    }

    @Test
    @DisplayName("age is described in the largest unit that is not zero")
    void ageReadsLikeAPersonWouldSayIt() {
        assertAll(
                () -> assertEquals("just now", ago(Duration.ofSeconds(20)).describeAge(NOW)),
                () -> assertEquals("1 minute ago", ago(Duration.ofMinutes(1)).describeAge(NOW)),
                () -> assertEquals("42 minutes ago", ago(Duration.ofMinutes(42)).describeAge(NOW)),
                () -> assertEquals("1 hour ago", ago(Duration.ofHours(1)).describeAge(NOW)),
                () -> assertEquals("3 hours ago", ago(Duration.ofHours(3)).describeAge(NOW)),
                () -> assertEquals("1 day ago", ago(Duration.ofDays(1)).describeAge(NOW)),
                () -> assertEquals("11 days ago", ago(Duration.ofDays(11)).describeAge(NOW)));
    }

    @Test
    @DisplayName("a scan a week old is stale; a day short of it is not")
    void stalenessBoundary() {
        assertAll(
                () -> assertFalse(ago(Duration.ofDays(6)).isStale(NOW)),
                () -> assertTrue(ago(Duration.ofDays(7)).isStale(NOW),
                        "the boundary is inclusive"),
                () -> assertTrue(ago(Duration.ofDays(30)).isStale(NOW)));
    }

    @Test
    @DisplayName("a scan timestamped in the future does not render a negative age")
    void clockSkewIsClamped() {
        // A scan saved on a machine whose clock is ahead, or a clock that moved
        // backwards. "-3 days ago" is nonsense on a screen; "just now" is at
        // least a sentence, and it is closer to true than a negative number.
        TargetPosture future = at(NOW.plus(Duration.ofDays(3)));
        assertAll(
                () -> assertEquals(Duration.ZERO, future.age(NOW)),
                () -> assertEquals("just now", future.describeAge(NOW)),
                () -> assertFalse(future.isStale(NOW)));
    }

    @Test
    @DisplayName("the assessment's figures are reachable through the row")
    void rowExposesWhatTheTableDraws() {
        TargetPosture posture = ago(Duration.ofHours(2));
        assertAll(
                () -> assertEquals(ExposureBand.INDETERMINATE, posture.band()),
                () -> assertEquals(Coverage.NONE, posture.coverage()),
                () -> assertEquals(PostureTrend.FIRST_SCAN, posture.trend()),
                () -> assertEquals(7L, posture.scanId()));
    }
}
