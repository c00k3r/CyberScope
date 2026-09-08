package com.cyberscope.ui;

/**
 * Where the window opens, and how big.
 *
 * <p>Pure arithmetic, no JavaFX, so the rules are unit-tested. The values it is
 * given come from {@code Screen.getPrimary().getVisualBounds()} -- "visual"
 * rather than "bounds" because that already excludes the taskbar or dock, and a
 * window sized to the full bounds opens with its status bar underneath the
 * taskbar.
 *
 * <h2>Why this class exists</h2>
 *
 * v0.5.0 hardcoded {@code new Scene(root, 1040, 560)} and got away with it. The
 * sidebar in v0.6.0 takes 190px that used to be results, so the default grew to
 * 1180x680 -- and a hardcoded size is a bet that every user's screen is bigger
 * than the number you typed.
 *
 * <p>Measured on a 1024x768 display, before this class existed:
 *
 * <pre>
 *   "CyberScope" 1180x680+-78+29
 * </pre>
 *
 * JavaFX centres a window it cannot fit, which for a window wider than the
 * screen means centring it on an area that does not exist: <b>x = -78</b>. The
 * left edge, which is the sidebar, is off the display. On a desktop WM that is
 * an annoyance you drag back. Under a compositor that never composites an
 * off-screen surface -- WSLg, some Wayland setups, RDP sessions -- the result is
 * a window that exists in the task switcher, has a title, and is never painted.
 *
 * <p>So: never ask for a window bigger than the screen, and never let one be
 * positioned off the edge.
 */
final class WindowGeometry {

    /** Preferred size, on a screen with room for it. */
    static final double PREFERRED_WIDTH = 1180;
    static final double PREFERRED_HEIGHT = 680;

    /**
     * Below this the sidebar and a results table cannot both be useful.
     *
     * <p>Applied as a floor on the <i>minimum</i> size, not on the opening size:
     * on a screen too small even for this, the window is sized to the screen and
     * the user scrolls, which is worse than ideal but strictly better than a
     * window whose edges they cannot reach.
     */
    static final double MIN_WIDTH = 960;
    static final double MIN_HEIGHT = 520;

    /** Left around the window so it reads as a window and not as the desktop. */
    private static final double MARGIN = 40;

    private WindowGeometry() {
    }

    /** @param x left edge, @param y top edge, in the screen's coordinate space */
    record Placement(double x, double y, double width, double height,
                     double minWidth, double minHeight) {
    }

    /**
     * Fits the window to a screen.
     *
     * @param screenX      visual bounds minX -- not always 0; a second monitor
     *                     left of the primary one gives the primary a positive
     *                     origin, and a hardcoded 0 would place the window on
     *                     the wrong display
     * @param screenY      visual bounds minY
     * @param screenWidth  visual bounds width  (taskbar already excluded)
     * @param screenHeight visual bounds height
     */
    static Placement fit(double screenX, double screenY,
                         double screenWidth, double screenHeight) {
        double width = clamp(PREFERRED_WIDTH, screenWidth - MARGIN, screenWidth);
        double height = clamp(PREFERRED_HEIGHT, screenHeight - MARGIN, screenHeight);

        // The minimum must never exceed the size we just chose, or the window
        // opens already violating its own constraint and some window managers
        // resize it back off the screen.
        double minWidth = Math.min(MIN_WIDTH, width);
        double minHeight = Math.min(MIN_HEIGHT, height);

        // max(screenX, ...) so a window that still cannot fit is flush with the
        // top-left corner rather than centred into negative coordinates.
        double x = Math.max(screenX, screenX + (screenWidth - width) / 2);
        double y = Math.max(screenY, screenY + (screenHeight - height) / 2);

        return new Placement(x, y, width, height, minWidth, minHeight);
    }

    /**
     * Re-opens the window where it was left, or falls back to {@link #fit}.
     *
     * <p>A saved window position is <b>untrusted input that happens to live in
     * your own home directory.</b> It was written by a possibly different
     * version of this program, on a possibly different display arrangement, and
     * nothing stops a user editing the file. Three concrete ways it goes wrong:
     *
     * <ul>
     *   <li><b>The monitor is gone.</b> Saved at x=2200 on a two-screen desk,
     *       re-opened on the laptop alone: the window is placed entirely outside
     *       the only display, and the failure mode is the one this class was
     *       written for -- a window that exists, has a title, and is never
     *       painted.</li>
     *   <li><b>The screen shrank.</b> 1920x1080 saved, projector at 1024x768
     *       today. A window wider than the screen cannot be dragged back by its
     *       title bar on every window manager.</li>
     *   <li><b>The file is nonsense.</b> A hand-edited {@code width=0}, a
     *       {@code NaN} from a formatting bug, a truncated write. JavaFX accepts
     *       a zero-sized stage and renders nothing.</li>
     * </ul>
     *
     * So the saved values are treated as a <i>request</i>: size is capped at the
     * screen, position is clamped so the whole window is on it, and anything
     * that is not a usable number is discarded in favour of the default
     * placement. Clamping rather than rejecting matters -- a user who moved the
     * window slightly off the bottom edge gets it nudged back, not reset to the
     * centre.
     *
     * @param saved   the stored geometry, or {@code null} for "nothing saved"
     * @return where to actually open
     */
    static Placement restore(double[] saved,
                             double screenX, double screenY,
                             double screenWidth, double screenHeight) {
        Placement fallback = fit(screenX, screenY, screenWidth, screenHeight);
        if (saved == null || saved.length != 4 || !allFinite(saved)) {
            return fallback;
        }
        double width = saved[2];
        double height = saved[3];
        if (width < 1 || height < 1) {
            return fallback;
        }

        // Cap first, then place: the position that keeps a window on screen
        // depends on how wide it ended up being.
        width = Math.min(width, screenWidth);
        height = Math.min(height, screenHeight);

        double x = clampInto(saved[0], screenX, screenX + screenWidth - width);
        double y = clampInto(saved[1], screenY, screenY + screenHeight - height);

        return new Placement(x, y, width, height,
                Math.min(MIN_WIDTH, width), Math.min(MIN_HEIGHT, height));
    }

    private static boolean allFinite(double[] values) {
        for (double value : values) {
            if (!Double.isFinite(value)) {
                return false;
            }
        }
        return true;
    }

    /**
     * {@code value} pulled inside {@code [low, high]}.
     *
     * <p>{@code high} can be below {@code low} when the window is exactly as
     * wide as the screen, so {@code low} wins -- flush with the left edge, which
     * is the only position that fits.
     */
    private static double clampInto(double value, double low, double high) {
        return Math.max(low, Math.min(value, Math.max(low, high)));
    }

    /**
     * {@code preferred}, reduced to fit, but never below a floor.
     *
     * <p>The {@code hardLimit} is what stops a pathological screen size -- a
     * headless VM reporting 1x1, a display not yet initialised -- from producing
     * a negative or zero dimension, which JavaFX accepts and then renders as
     * nothing.
     */
    private static double clamp(double preferred, double available, double hardLimit) {
        double fitted = Math.min(preferred, available);
        return fitted < 1 ? Math.max(1, Math.min(preferred, hardLimit)) : fitted;
    }
}
