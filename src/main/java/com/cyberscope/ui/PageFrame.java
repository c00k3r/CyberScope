package com.cyberscope.ui;

import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.control.Label;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

/**
 * The header every page wears: title, one line saying what the page is for, and
 * the page's own content underneath.
 *
 * <p>Written once here rather than in each page because a sidebar is a weak
 * signal of location on its own -- the highlighted row is 190px away in the
 * corner of the eye. Repeating the page name at the top of the content is what
 * actually answers "where am I".
 */
final class PageFrame {

    private PageFrame() {
    }

    /** @param content stretched to fill everything under the header */
    static Region wrap(PageId page, Node content) {
        Label title = new Label(page.title());
        title.getStyleClass().add(Styles.PAGE_TITLE);

        Label subtitle = new Label(page.subtitle());
        subtitle.setWrapText(true);
        subtitle.getStyleClass().add(Styles.MUTED);

        VBox header = new VBox(2, title, subtitle);
        header.setPadding(new Insets(18, 20, 14, 20));
        header.getStyleClass().add(Styles.PAGE_HEADER);

        BorderPane frame = new BorderPane();
        frame.getStyleClass().add(Styles.PAGE);
        frame.setTop(header);
        frame.setCenter(content);
        return frame;
    }
}
