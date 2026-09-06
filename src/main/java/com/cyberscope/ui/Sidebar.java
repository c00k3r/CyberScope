package com.cyberscope.ui;

import com.cyberscope.App;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Label;
import javafx.scene.control.Tooltip;
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
 * <p>The rows are {@link HBox}es with an {@code onMouseClicked}, not
 * {@code Button}s. A button brings Modena's focus ring, its own hover fill and
 * its own pressed state, all of which have to be overridden to get a flat nav
 * row, and the result is more CSS than the plain node needs. The cost is that
 * these rows are not keyboard-focusable, which is a real accessibility gap and
 * is noted as such rather than hidden.
 */
final class Sidebar {

    private static final double ICON_SIZE = 17;

    private final Navigation navigation;
    private final Map<PageId, HBox> rows = new EnumMap<>(PageId.class);
    private final VBox root = new VBox();

    Sidebar(Navigation navigation) {
        this.navigation = navigation;
        build();
        navigation.onChange(page -> highlight(page));
        highlight(navigation.current());
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
            Tooltip tip = new Tooltip(page.subtitle());
            tip.setWrapText(true);
            tip.setMaxWidth(280);
            Tooltip.install(row, tip);
        }
        return row;
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
