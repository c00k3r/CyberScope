package com.cyberscope.ui;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Label;
import javafx.scene.layout.VBox;

/**
 * A page that is not built yet, saying so plainly.
 *
 * <p>The alternative -- leaving Dashboard and Vulnerabilities out of the sidebar
 * until they exist -- would mean the shell is exercised by four pages and then
 * has two more bolted on later, which is how a navigation model that seemed fine
 * turns out not to fit. Better to route to all six now and fill two of them in.
 *
 * <p>It says what will be here and which version does it, because a blank panel
 * with no explanation reads as a bug to anyone who did not write it.
 */
final class PlaceholderPage implements Page {

    private final PageId id;
    private final Node node;

    PlaceholderPage(PageId id, String coming) {
        this.id = id;

        Label headline = new Label("Not built yet");
        headline.getStyleClass().add(Styles.SUMMARY);

        Label detail = new Label(coming);
        detail.setWrapText(true);
        detail.setMaxWidth(460);
        detail.getStyleClass().add(Styles.MUTED);

        VBox box = new VBox(6, headline, detail);
        box.setAlignment(Pos.CENTER);
        box.setPadding(new Insets(40));
        this.node = PageFrame.wrap(id, box);
    }

    @Override
    public PageId id() {
        return id;
    }

    @Override
    public Node node() {
        return node;
    }
}
