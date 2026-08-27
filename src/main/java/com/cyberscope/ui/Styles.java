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
 
    // --- structure -------------------------------------------------------
    static final String SCAN_PANE     = "scan-pane";
    static final String HISTORY_PANE  = "history-pane";
    static final String STATUS_BAR    = "status-bar";
 
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
 

