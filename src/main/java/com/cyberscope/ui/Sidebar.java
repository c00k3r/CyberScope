package com.cyberscope.ui;

import com.cyberscope.App;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Label;
import javafx.scene.control.Tooltip;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

import java.util.EnumMap;
import java.util.Map;

/**
 * The left rail.
 *
 * <p>A renderer, and only a renderer. Every rule about what can be opened lives
 * in {@link Navigation}; this class asks and draws. It holds no state of its own
 * beyond the row nodes, which is why the active-item highlight cannot drift out
 * of step with the page actually showing -- there is only one copy of that fact.
 *
 * <p>The rows are {@link HBox}es with a click handler, not {@code Button}s. A
 * button brings Modena's focus ring, its own hover fill and its own pressed
 * state, all of which have to be overridden to get a flat nav row, and the
 * result is more CSS than the plain node needs.
 *
 * <h2>Keyboard access</h2>
 *
 * Until v0.7.0 the cost of that choice was that the whole navigation was
 * unreachable without a mouse -- {@code Node} is not focus-traversable by
 * default, so Tab skipped the rail entirely and no key did anything. That gap
 * was noted in this class from v0.6.0 and is closed here, deliberately rather
 * than by turning the rows into buttons.
 *
 * <p>Three rules, and the second is the one that is easy to get wrong:
 *
 * <ol>
 *   <li><b>One tab stop, not six.</b> Six focusable rows means six Tab presses
 *       between the window edge and the content. The rail is a single control
 *       with a selection, so it behaves like one: Tab enters it at the row that
 *       is currently showing, arrows move within it, Tab leaves it. This is the
 *       roving tab stop pattern, and {@link #makeTabStop} is the whole of it.</li>
 *   <li><b>Arrows move focus; they do not navigate.</b> Focus-follows-arrow
 *       would be fewer keystrokes and is wrong here: showing a page re-runs its
 *       queries and rebuilds its table, so arrowing from the top of the rail to
 *       the bottom would run four page loads and discard whatever row the user
 *       had selected. Activation is explicit -- Enter or Space.</li>
 *   <li><b>Blocked rows are not focusable at all.</b> They are skipped by
 *       {@link Navigation#neighbour} and never become the tab stop, so a
 *       keyboard user cannot land somewhere Enter does nothing.</li>
 * </ol>
 */
final class Sidebar {

    private static final double ICON_SIZE = 17;

    private final Navigation navigation;
    private final Map<PageId, HBox> rows = new EnumMap<>(PageId.class);
    private final VBox root = new VBox();

    Sidebar(Navigation navigation) {
        this.navigation = navigation;
        build();
        navigation.onChange(page -> {
            highlight(page);
            // A page opened by mouse moves the tab stop too, so the next Tab
            // press enters the rail where the user actually is rather than
            // wherever the keyboard was last used.
            makeTabStop(page);
        });
        highlight(navigation.current());
        makeTabStop(navigation.current());
    }

    Region root() {
        return root;
    }

    private void build() {
        root.getStyleClass().add(Styles.SIDEBAR);
        root.setMinWidth(190);
        root.setPrefWidth(190);

        Label wordmark = new Label("CyberScope");
        wordmark.getStyleClass().add(Styles.WORDMARK);

        Label version = new Label("v" + App.VERSION);
        version.getStyleClass().add(Styles.MUTED);

        VBox brand = new VBox(1, wordmark, version);
        brand.setPadding(new Insets(18, 16, 16, 18));

        VBox items = new VBox(2);
        items.setPadding(new Insets(0, 10, 0, 10));
        for (PageId page : navigation.pages()) {
            HBox row = navRow(page);
            rows.put(page, row);
            items.getChildren().add(row);
        }

        Region filler = new Region();
        VBox.setVgrow(filler, Priority.ALWAYS);

        // The standing constraint, on screen, on every page. Not a dialog you
        // click through once and forget: the rule applies to every scan, so it
        // sits where it is always visible.
        Label scope = new Label("Authorised targets only");
        scope.setWrapText(true);
        scope.getStyleClass().add(Styles.SCOPE_NOTE);
        VBox.setMargin(scope, new Insets(0, 14, 16, 18));

        root.getChildren().setAll(brand, items, filler, scope);
    }

    private HBox navRow(PageId page) {
        Label label = new Label(page.title());
        label.getStyleClass().add(Styles.NAV_LABEL);

        HBox row = new HBox(11, Icons.of(page, ICON_SIZE), label);
        row.setAlignment(Pos.CENTER_LEFT);
        row.setPadding(new Insets(8, 12, 8, 12));
        row.getStyleClass().add(Styles.NAV_ITEM);

        if (navigation.isBlocked(page)) {
            row.getStyleClass().add(Styles.NAV_BLOCKED);
            // The reason, not just a grey row. "Scan history is unavailable"
            // tells the user nothing they cannot already see; the sentence
            // underneath is the part they can act on.
            row.setDisable(false);   // still hoverable, so the tooltip can show
            Tooltip tip = new Tooltip(page.title() + " is unavailable.\n"
                    + navigation.blockedReason(page).orElse(""));
            tip.setWrapText(true);
            tip.setMaxWidth(280);
            Tooltip.install(row, tip);
        } else {
            row.setOnMouseClicked(event -> navigation.goTo(page));
            row.setOnKeyPressed(event -> onKey(page, event));
            // Accessible text, not the visible label: a screen reader announcing
            // "Dashboard" alone does not say what the row does when the rail has
            // no other context. The subtitle is the same sentence the tooltip
            // shows, so the two cannot drift apart.
            row.setAccessibleText(page.title() + ". " + page.subtitle());
            Tooltip tip = new Tooltip(page.subtitle());
            tip.setWrapText(true);
            tip.setMaxWidth(280);
            Tooltip.install(row, tip);
        }
        return row;
    }

    /**
     * Enter and Space open; Up and Down move focus; Home and End jump.
     *
     * <p>Every handled key is consumed. An unconsumed arrow key reaches the
     * {@code ScrollPane} the page sits in and scrolls the content underneath,
     * so the rail would move focus and the page would move at the same time.
     */
    private void onKey(PageId page, KeyEvent event) {
        switch (event.getCode()) {
            case ENTER, SPACE -> {
                navigation.goTo(page);
                event.consume();
            }
            case UP -> moveFocus(navigation.neighbour(page, -1), event);
            case DOWN -> moveFocus(navigation.neighbour(page, +1), event);
            // From anywhere in the rail, one key to either end. neighbour()
            // from the last page wrapping forward lands on the first reachable
            // one, which is exactly what Home means -- and it stays right if a
            // page is blocked, which an index of 0 would not.
            case HOME -> moveFocus(navigation.neighbour(lastPage(), +1), event);
            case END -> moveFocus(navigation.neighbour(firstPage(), -1), event);
            default -> {
                // Tab, Escape, anything else: left alone, so the standard
                // traversal out of the rail keeps working.
            }
        }
    }

    private PageId firstPage() {
        return navigation.pages().get(0);
    }

    private PageId lastPage() {
        return navigation.pages().get(navigation.pages().size() - 1);
    }

    private void moveFocus(PageId target, KeyEvent event) {
        HBox row = rows.get(target);
        if (row != null) {
            makeTabStop(target);
            row.requestFocus();
        }
        event.consume();
    }

    /**
     * Makes {@code page}'s row the rail's single entry in the Tab order.
     *
     * <p>Called on every navigation and every arrow press, so the row that has
     * focus is also the row Tab comes back to. Setting it on a blocked page is
     * a no-op by construction: blocked rows are never put in {@code rows} with
     * traversal enabled, and {@link Navigation} cannot make one current.
     */
    private void makeTabStop(PageId page) {
        rows.forEach((id, row) ->
                row.setFocusTraversable(id == page && !navigation.isBlocked(id)));
    }

    private void highlight(PageId active) {
        rows.forEach((page, row) -> {
            row.getStyleClass().remove(Styles.NAV_ACTIVE);
            if (page == active) {
                row.getStyleClass().add(Styles.NAV_ACTIVE);
            }
        });
    }
}
