package com.cyberscope.ui;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The window must open somewhere the user can see it.
 *
 * <p>Every case here was a real geometry produced by running the application
 * against an X server of that size, not an invented number. The 1024x768 case is
 * the one that started this: the window opened at <b>x = -78</b>.
 */
class WindowGeometryTest {

    /** Asserts the whole window lies inside the screen it was fitted to. */
    private static void assertOnScreen(WindowGeometry.Placement p,
                                       double sx, double sy, double sw, double sh) {
        assertAll(
                () -> assertTrue(p.x() >= sx,
                        "left edge at " + p.x() + " is off a screen starting at " + sx),
                () -> assertTrue(p.y() >= sy,
                        "top edge at " + p.y() + " is off a screen starting at " + sy),
                () -> assertTrue(p.x() + p.width() <= sx + sw + 0.001,
                        "right edge at " + (p.x() + p.width()) + " exceeds " + (sx + sw)),
                () -> assertTrue(p.y() + p.height() <= sy + sh + 0.001,
                        "bottom edge at " + (p.y() + p.height()) + " exceeds " + (sy + sh)));
    }

    @Test
    @DisplayName("on a big screen the window opens at its preferred size, centred")
    void bigScreenGetsThePreferredSize() {
        var p = WindowGeometry.fit(0, 0, 1920, 1040);
        assertAll(
                () -> assertEquals(1180, p.width()),
                () -> assertEquals(680, p.height()),
                () -> assertEquals(370, p.x()),
                () -> assertEquals(180, p.y()));
        assertOnScreen(p, 0, 0, 1920, 1040);
    }

    @Test
    @DisplayName("1024x768: the case that opened the window at x = -78")
    void smallScreenNeverGoesNegative() {
        var p = WindowGeometry.fit(0, 0, 1024, 768);
        assertOnScreen(p, 0, 0, 1024, 768);
        assertTrue(p.width() <= 1024,
                "a window wider than the screen is centred into negative x by JavaFX, "
              + "and a compositor that never composites an off-screen surface never "
              + "paints it -- the window exists in the task switcher and is blank");
    }

    @Test
    @DisplayName("a screen smaller than the minimum still yields a reachable window")
    void tinyScreenStillFits() {
        var p = WindowGeometry.fit(0, 0, 800, 600);
        assertOnScreen(p, 0, 0, 800, 600);
        assertAll(
                () -> assertTrue(p.minWidth() <= p.width(),
                        "opening below your own minimum invites the WM to resize you off-screen"),
                () -> assertTrue(p.minHeight() <= p.height()));
    }

    @Test
    @DisplayName("the origin is respected -- a second monitor left of the primary")
    void nonZeroScreenOriginIsHonoured() {
        // Primary at +1920 with another display to its left. Assuming an origin
        // of 0 here opens the window on the wrong monitor.
        var p = WindowGeometry.fit(1920, 0, 1920, 1040);
        assertAll(
                () -> assertEquals(1920 + 370, p.x()),
                () -> assertTrue(p.x() >= 1920, "window opened on the wrong display"));
        assertOnScreen(p, 1920, 0, 1920, 1040);
    }

    @Test
    @DisplayName("a negative origin -- a display above or left of the primary")
    void negativeScreenOriginIsHonoured() {
        var p = WindowGeometry.fit(-1920, -200, 1920, 1040);
        assertOnScreen(p, -1920, -200, 1920, 1040);
    }

    @Test
    @DisplayName("a degenerate screen size never produces a zero or negative window")
    void degenerateScreenIsSurvivable() {
        for (double[] screen : new double[][] {{1, 1}, {0, 0}, {40, 40}, {41, 41}}) {
            var p = WindowGeometry.fit(0, 0, screen[0], screen[1]);
            assertAll("screen " + screen[0] + "x" + screen[1],
                    () -> assertTrue(p.width() > 0,
                            "JavaFX accepts a zero width and renders nothing"),
                    () -> assertTrue(p.height() > 0),
                    () -> assertTrue(p.minWidth() <= p.width()),
                    () -> assertTrue(p.minHeight() <= p.height()));
        }
    }

    @Test
    @DisplayName("the window never covers the whole screen edge to edge")
    void aMarginIsLeftWhenThereIsRoom() {
        var p = WindowGeometry.fit(0, 0, 1200, 700);
        assertAll(
                () -> assertTrue(p.width() < 1200, "no margin left at the sides"),
                () -> assertTrue(p.height() < 700));
        assertOnScreen(p, 0, 0, 1200, 700);
    }
}
