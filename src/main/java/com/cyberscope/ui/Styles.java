package com.cyberscope.ui;

import javafx.scene.Parent;

import java.net.URL;

/**
 * One place that knows where the stylesheet lives and what the style classes
 * are called.
 *
 * <p>Style class names are strings, and strings scattered across a UI are how a
 * rename silently stops working: JavaFX does not warn about a selector that
 * matches nothing, so a typo is invisible until someone notices the colour is
 * missing. Naming them once as constants means a rename is a compile error in
 * the Java and a one-line edit in the CSS.
 */
final class Styles {

    private static final String STYLESHEET = "/css/app.css";

    // --- shell -----------------------------------------------------------
    static final String APP_SHELL     = "app-shell";
    static final String SIDEBAR       = "sidebar";
    static final String WORDMARK      = "wordmark";
    static final String SCOPE_NOTE    = "scope-note";
    static final String NAV_ITEM      = "nav-item";
    static final String NAV_LABEL     = "nav-label";
    static final String NAV_ICON      = "nav-icon";
    /** The page currently showing. Exactly one row carries this at a time. */
    static final String NAV_ACTIVE    = "nav-active";
    /** A page that cannot be opened, with the reason in its tooltip. */
    static final String NAV_BLOCKED   = "nav-blocked";

    // --- page ------------------------------------------------------------
    static final String PAGE          = "page";
    static final String PAGE_HEADER   = "page-header";
    static final String PAGE_TITLE    = "page-title";
    static final String PAGE_SCROLL   = "page-scroll";
    static final String PROSE         = "prose";

    // --- structure -------------------------------------------------------
    static final String SCAN_PANE     = "scan-pane";
    static final String HISTORY_PANE  = "history-pane";
    static final String STATUS_BAR    = "status-bar";
    static final String INDEX_BAR     = "index-bar";
    static final String INDEX_STALE   = "index-stale";

    // --- type ------------------------------------------------------------
    static final String SECTION_TITLE = "section-title";
    static final String MUTED         = "muted";
    static final String HINT          = "hint-label";
    static final String WARNING       = "warning-label";
    static final String SUMMARY       = "summary-label";

    // --- controls --------------------------------------------------------
    static final String PRIMARY       = "primary";
    static final String DESTRUCTIVE   = "destructive";
    static final String TARGET_FIELD  = "target-field";

    // --- table cells -----------------------------------------------------
    static final String PORT_CELL     = "port-cell";
    static final String PROBED        = "evidence-probed";
    static final String INFERRED      = "evidence-inferred";

    // --- dashboard --------------------------------------------------------
    static final String CARD          = "card";
    static final String CARD_TITLE    = "card-title";
    static final String CARD_VALUE    = "card-value";
    static final String CARD_NOTE     = "card-note";
    static final String EMPTY_STATE   = "empty-state";

    /** A band, rendered as a chip that always carries its own name. */
    static final String BAND_CHIP          = "band-chip";
    static final String BAND_CRITICAL      = "band-critical";
    static final String BAND_HIGH          = "band-high";
    static final String BAND_ELEVATED      = "band-elevated";
    static final String BAND_LOW           = "band-low";
    static final String BAND_CLEAR         = "band-clear";
    static final String BAND_INDETERMINATE = "band-indeterminate";

    static final String BAR_TRACK       = "bar-track";
    static final String BAR_FILL        = "bar-fill";
    static final String BAR_LABEL       = "bar-label";
    static final String BAR_COUNT       = "bar-count";
    static final String FILL_CRITICAL   = "fill-critical";
    static final String FILL_HIGH       = "fill-high";
    static final String FILL_ELEVATED   = "fill-elevated";
    static final String FILL_LOW        = "fill-low";
    /** Open services no lookup could be performed for. Not a severity. */
    static final String FILL_UNCHECKED  = "fill-unchecked";

    static final String RING_TRACK      = "ring-track";
    static final String RING_FILL       = "ring-fill";
    static final String RING_FILL_POOR  = "ring-fill-poor";
    static final String RING_VALUE      = "ring-value";

    static final String ACTION_RANK     = "action-rank";
    static final String ACTION_TEXT     = "action-text";
    static final String ACTION_WHY      = "action-why";

    static final String TREND_WORSE     = "trend-worse";
    static final String TREND_BETTER    = "trend-better";
    static final String TREND_FLAT      = "trend-flat";
    static final String STALE           = "stale";

    // --- vulnerabilities --------------------------------------------------
    /** Findings at HIGH or CRITICAL. */
    static final String VULN_SEVERE   = "vuln-severe";
    /** Looked up, nothing filed. The only green that means "clean". */
    static final String VULN_CLEAN    = "vuln-clean";

    // --- comparison ------------------------------------------------------
    /** A change that increases exposure: a port opened. */
    static final String CHANGE_WORSE  = "change-worse";
    /** A change that decreases exposure: a port closed. */
    static final String CHANGE_BETTER = "change-better";

    private Styles() {
    }

    /**
     * Attaches the stylesheet to a root node.
     *
     * <p>Attached to the {@link Parent}, not the {@code Scene}, so a view carries
     * its own appearance wherever it is placed -- the headless snapshot harness
     * and any future window get the styling without having to remember to add it.
     * The trade-off is that dialogs, which live in their own Scene, are not
     * covered; they use the JavaFX defaults, which is fine because CyberScope's
     * dialogs are plain text.
     *
     * <p>Fails loudly. A missing stylesheet is a packaging mistake -- the resource
     * did not make it into {@code target/classes} -- and it produces an
     * unstyled window that looks like a CSS bug. Better to say so than to let
     * someone spend an hour debugging selectors that were never loaded.
     */
    static void apply(Parent root) {
        URL sheet = Styles.class.getResource(STYLESHEET);
        if (sheet == null) {
            throw new IllegalStateException(
                    "Stylesheet not found on the classpath: " + STYLESHEET
                  + " -- check that src/main/resources is being copied to target/classes");
        }
        root.getStylesheets().add(sheet.toExternalForm());
    }
}
