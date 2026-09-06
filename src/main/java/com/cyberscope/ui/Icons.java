package com.cyberscope.ui;

import javafx.scene.Group;
import javafx.scene.Node;
import javafx.scene.layout.StackPane;
import javafx.scene.paint.Color;
import javafx.scene.shape.SVGPath;
import javafx.scene.shape.StrokeLineCap;
import javafx.scene.shape.StrokeLineJoin;
import javafx.scene.transform.Scale;

import java.util.EnumMap;
import java.util.Map;

/**
 * The sidebar icons, drawn as vector paths.
 *
 * <h2>Why not an icon font, and why not emoji</h2>
 *
 * The obvious cheap answer is a glyph in the label text -- a shield, a gear.
 * That is the same trap as {@code -fx-font-family}, which this project already
 * measured: JavaFX takes the first font family and, if the glyph is missing,
 * does not go looking in another. A character with no glyph in the platform UI
 * font renders as a box, and which characters those are differs on Windows,
 * macOS and Linux. A sidebar that shows six tofu squares on someone else's
 * machine is worse than no icons.
 *
 * <p>The second option is an icon font (FontAwesome, and the {@code Ikonli}
 * wrapper). That is a runtime dependency, a licence to carry, and about 200 KB
 * in the jar for six shapes.
 *
 * <p>So: {@link SVGPath}, which is in {@code javafx.graphics} and always
 * renders. Every icon here is <b>stroked, not filled</b>. Stroking sidesteps
 * fill rules entirely -- a filled ring needs {@code EVEN_ODD} and a
 * counter-wound inner subpath to punch its hole, and getting that wrong
 * produces a solid blob rather than an error. Stroked outlines also match the
 * line-art style of the rest of the UI.
 *
 * <p>The stroke colour is left unset so CSS can paint it: {@code -fx-stroke} on
 * {@code .nav-icon} follows the theme, and the active item's icon takes the
 * accent, without this class knowing any colour.
 */
final class Icons {

    /** All paths are authored on a 24x24 grid, then scaled by the caller. */
    private static final double GRID = 24.0;

    private static final Map<PageId, String[]> PATHS = new EnumMap<>(PageId.class);

    static {
        // Dashboard: four panels of unequal height -- a layout, not a window.
        PATHS.put(PageId.DASHBOARD, new String[] {
                "M4 4 h6 v7 h-6 z",
                "M14 4 h6 v4 h-6 z",
                "M14 11 h6 v9 h-6 z",
                "M4 14 h6 v6 h-6 z" });

        // Network scan: a radar sweep. Two arcs and the sweep line.
        PATHS.put(PageId.SCAN, new String[] {
                "M12 3 A9 9 0 1 0 21 12",
                "M12 8 A4 4 0 1 0 16 12",
                "M12 12 L20 4" });

        // Scan history: a clock, hands at "past".
        PATHS.put(PageId.HISTORY, new String[] {
                "M12 4 A8 8 0 1 0 12.01 4",
                "M12 7.5 V12 L15.5 14" });

        // Vulnerabilities: a shield with a fracture, not a tick. The page lists
        // what is wrong; an intact shield would say the opposite.
        PATHS.put(PageId.VULNERABILITIES, new String[] {
                "M12 3 L19 6 V12 C19 16 16 19 12 21 C8 19 5 16 5 12 V6 Z",
                "M12 8.5 V13",
                "M12 15.5 V16.5" });

        // Settings: sliders. A gear needs a dozen arcs to read as a gear at 16px.
        PATHS.put(PageId.SETTINGS, new String[] {
                "M4 7 H20", "M4 12 H20", "M4 17 H20",
                "M15 5 A2 2 0 1 0 15.01 5",
                "M9 10 A2 2 0 1 0 9.01 10",
                "M14 15 A2 2 0 1 0 14.01 15" });

        // About: the usual i in a circle.
        PATHS.put(PageId.ABOUT, new String[] {
                "M12 4 A8 8 0 1 0 12.01 4",
                "M12 11 V16",
                "M12 7.8 V8.3" });
    }

    private Icons() {
    }

    /**
     * One icon, sized to {@code size} pixels square.
     *
     * <p>Several icons are more than one stroke, so the paths go in a
     * {@link Group}. Two details in here are easy to get wrong:
     *
     * <ul>
     *   <li>The group is scaled with an explicit {@link Scale} transform pivoted
     *       at the origin, not {@code setScaleX}. {@code setScaleX} pivots on
     *       the node's centre, which is fine for one shape and wrong for six --
     *       each path would shrink toward its own centre and the composition
     *       would come apart.</li>
     *   <li>The group is wrapped in a fixed-size {@link StackPane}. A scale
     *       transform does not change a node's <i>layout</i> bounds, so an
     *       unwrapped group reserves 24px of row height no matter what size it
     *       draws at, and the nav rows would be spaced for icons twice the size
     *       of the ones they show.</li>
     * </ul>
     *
     * <p>The result is {@code mouseTransparent} so a click anywhere on the nav
     * row hits the row, not the glyph.
     */
    static Node of(PageId page, double size) {
        Group group = new Group();
        for (String data : PATHS.get(page)) {
            SVGPath path = new SVGPath();
            path.setContent(data);
            path.setFill(Color.TRANSPARENT);
            // Stroke colour is NOT set here. -fx-stroke comes from .nav-icon in
            // app.css, so the icon follows the theme and the active state
            // without this class knowing a single colour. Width is in grid
            // units, so it scales with the icon.
            path.setStrokeWidth(1.8);
            path.setStrokeLineCap(StrokeLineCap.ROUND);
            path.setStrokeLineJoin(StrokeLineJoin.ROUND);
            path.getStyleClass().add(Styles.NAV_ICON);
            group.getChildren().add(path);
        }
        double scale = size / GRID;
        group.getTransforms().add(new Scale(scale, scale, 0, 0));

        StackPane box = new StackPane(group);
        box.setMinSize(size, size);
        box.setPrefSize(size, size);
        box.setMaxSize(size, size);
        box.setMouseTransparent(true);
        return box;
    }
}
