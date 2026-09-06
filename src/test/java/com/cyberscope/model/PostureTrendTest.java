package com.cyberscope.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("the trend arrow on the dashboard")
class PostureTrendTest {

    @Nested
    @DisplayName("direction")
    class Direction {

        @Test
        void movingUpTheScaleIsWorse() {
            assertAll(
                    () -> assertEquals(PostureTrend.WORSENED,
                            PostureTrend.between(ExposureBand.LOW, ExposureBand.HIGH)),
                    () -> assertEquals(PostureTrend.WORSENED,
                            PostureTrend.between(ExposureBand.HIGH, ExposureBand.CRITICAL)),
                    () -> assertEquals(PostureTrend.WORSENED,
                            PostureTrend.between(ExposureBand.CLEAR, ExposureBand.LOW)));
        }

        @Test
        void movingDownTheScaleIsBetter() {
            assertAll(
                    () -> assertEquals(PostureTrend.IMPROVED,
                            PostureTrend.between(ExposureBand.CRITICAL, ExposureBand.ELEVATED)),
                    () -> assertEquals(PostureTrend.IMPROVED,
                            PostureTrend.between(ExposureBand.LOW, ExposureBand.CLEAR)));
        }

        @Test
        void theSameBandIsUnchanged() {
            assertEquals(PostureTrend.UNCHANGED,
                    PostureTrend.between(ExposureBand.HIGH, ExposureBand.HIGH));
        }
    }

    @Nested
    @DisplayName("the two cases that must not be reported as movement")
    class NotMovement {

        @Test
        @DisplayName("a first scan is not 'unchanged'")
        void firstScanIsItsOwnAnswer() {
            assertEquals(PostureTrend.FIRST_SCAN,
                    PostureTrend.between(null, ExposureBand.CLEAR),
                    "reporting a first scan as unchanged is a claim about a "
                  + "comparison that was never made");
        }

        @Test
        @DisplayName("INDETERMINATE on either side is not comparable")
        void indeterminateIsNotAPositionOnTheScale() {
            assertAll(
                    () -> assertEquals(PostureTrend.UNCOMPARABLE, PostureTrend.between(
                            ExposureBand.CLEAR, ExposureBand.INDETERMINATE),
                            "losing visibility is not the host getting worse"),
                    () -> assertEquals(PostureTrend.UNCOMPARABLE, PostureTrend.between(
                            ExposureBand.INDETERMINATE, ExposureBand.CLEAR),
                            "gaining visibility is not the host getting better"),
                    () -> assertEquals(PostureTrend.UNCOMPARABLE, PostureTrend.between(
                            ExposureBand.INDETERMINATE, ExposureBand.INDETERMINATE)));
        }

        @Test
        @DisplayName("only a real deterioration is coloured")
        void onlyWorseningIsRed() {
            for (PostureTrend trend : PostureTrend.values()) {
                assertEquals(trend == PostureTrend.WORSENED, trend.isWorse(), trend.name());
                assertEquals(trend == PostureTrend.IMPROVED, trend.isBetter(), trend.name());
            }
        }
    }

    @Test
    @DisplayName("every value carries a mark and a sentence explaining it")
    void everyValueIsExplained() {
        for (PostureTrend trend : PostureTrend.values()) {
            assertFalse(trend.mark().isBlank(), trend + " has no mark");
            assertFalse(trend.meaning().isBlank(), trend + " has no explanation");
            assertNotEquals(trend.mark(), trend.meaning(),
                    trend + "'s tooltip is just the arrow again");
        }
    }

    @Test
    @DisplayName("the two directions do not share a mark")
    void upAndDownAreDistinguishable() {
        assertTrue(!PostureTrend.WORSENED.mark().equals(PostureTrend.IMPROVED.mark()),
                "the arrow is the redundant coding for the colour; if both "
              + "directions draw the same character, a greyscale screenshot "
              + "cannot tell them apart");
    }
}
