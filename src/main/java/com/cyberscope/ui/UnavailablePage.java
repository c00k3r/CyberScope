package com.cyberscope.ui;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Label;
import javafx.scene.layout.VBox;

/**
 * What stands in for a page whose data source could not be opened.
 *
 * <h2>The sentence this class used to say</h2>
 *
 * It was called {@code PlaceholderPage} and its headline was <b>"Not built
 * yet"</b>, which was true in v0.6.0 when Dashboard and Vulnerabilities were
 * genuinely empty. Both were built in that same release, and the class survived
 * because it had acquired a second job: it is what
 * {@link AppShell} registers for the three database-backed pages when the
 * database cannot be opened.
 *
 * <p>So from v0.6.0 the only way to reach this page was to have a read-only home
 * directory or a corrupt scan file -- and what it told you was that the feature
 * had not been written. A user with a permissions problem was being sent to look
 * for a release that would fix it. The reason was on screen the whole time, in
 * the line underneath; the headline above it contradicted it.
 *
 * <p>No test caught this because there was nothing wrong with the code. The
 * string was correct when it was written and became false when its caller
 * changed, which is the failure mode that only reading the rendered page finds.
 *
 * <h2>What it says now</h2>
 *
 * Three lines, in the order a person needs them: <b>what</b> is unavailable,
 * <b>why</b>, and <b>what still works</b> -- because the answer to that last one
 * is "scanning", and someone who does not know that will close the application.
 */
final class UnavailablePage implements Page {

    /**
     * The part of CyberScope that needs nothing on disk.
     *
     * <p>Worth saying explicitly. Losing the database costs history, comparison
     * and the dashboard; it does not cost scanning, and a user who assumes
     * otherwise has lost the whole tool to a permissions error.
     */
    private static final String STILL_WORKS =
            "Network scan does not use the database, so scanning still works -- "
          + "results are shown but not saved.";

    private final PageId id;
    private final Node node;

    UnavailablePage(PageId id, String reason) {
        this.id = id;

        Label headline = new Label(id.title() + " is unavailable");
        headline.getStyleClass().add(Styles.SUMMARY);

        // The reason, not a category. "Scan history is unavailable" alone tells
        // the user only what they can already see; the sentence carried up from
        // the RepositoryException names the file and the errno, which is the
        // part they can act on.
        Label detail = new Label(reason == null || reason.isBlank()
                ? "The scan database could not be opened."
                : reason);
        detail.setWrapText(true);
        detail.setMaxWidth(460);
        detail.getStyleClass().add(Styles.MUTED);

        Label workaround = new Label(STILL_WORKS);
        workaround.setWrapText(true);
        workaround.setMaxWidth(460);
        workaround.getStyleClass().add(Styles.HINT);

        VBox box = new VBox(8, headline, detail, workaround);
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
