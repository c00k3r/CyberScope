package com.cyberscope.ui;

import com.cyberscope.service.compare.ScanComparator;
import com.cyberscope.service.compare.ScanDiff;
import com.cyberscope.service.scanner.ScanOutcome;
import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.control.Label;
import javafx.scene.control.SplitPane;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;

/**
 * Past scans, and what changed between two of them.
 *
 * <h2>Promoted from a side pane</h2>
 *
 * Until v0.6.0 history was a {@code SplitPane} region permanently attached to
 * the left of the scan controls, and selecting a saved scan painted it into the
 * same results table the live scan used. That had a real defect: the target
 * field and scan-type box would also be rewritten to match the loaded scan, so
 * the controls said one thing and the button would have run another. The status
 * line was the only thing telling you which of the two you were looking at.
 *
 * <p>Separating the pages removes the ambiguity structurally rather than with a
 * label. A saved scan renders on this page, in this page's table. Nothing on the
 * scan page changes, and the scan page's table always holds the run it just
 * performed.
 *
 * <p>The split pane survives, but only inside this page: the scan list on the
 * left, the selected scan or comparison on the right.
 */
final class HistoryPage implements Page {

    private static final DateTimeFormatter WHEN =
            DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm:ss");

    private final HistoryPane list;
    private final ResultsTable table = new ResultsTable();
    private final DiffView diffView;
    private final Label caption = new Label("Select a scan to see its results.");
    private final BorderPane detail = new BorderPane();
    private final VBox resultsPane;
    private final Node node;

    HistoryPage(AppContext context) {
        caption.setWrapText(true);
        caption.getStyleClass().add(Styles.SUMMARY);

        table.setPlaceholder("Select a scan on the left.");
        resultsPane = new VBox(8, caption, table.node());
        resultsPane.setPadding(new Insets(4, 20, 16, 16));
        VBox.setVgrow(table.node(), Priority.ALWAYS);

        diffView = new DiffView(this::showResults);

        detail.setCenter(resultsPane);
        detail.getStyleClass().add(Styles.SCAN_PANE);

        list = new HistoryPane(context.scans(), context.scansUnavailable(),
                               this::showSavedScan, this::showComparison);

        SplitPane split = new SplitPane(list.root(), detail);
        // A divider position is a fraction of the width, not pixels. Pinning the
        // history pane's minimum width in HistoryPane stops a drag from collapsing
        // it to nothing, which SplitPane will otherwise happily do.
        split.setDividerPositions(0.30);
        SplitPane.setResizableWithParent(list.root(), false);

        this.node = PageFrame.wrap(PageId.HISTORY, split);
    }

    @Override
    public PageId id() {
        return PageId.HISTORY;
    }

    @Override
    public Node node() {
        return node;
    }

    /**
     * Re-reads the scan list every time the page is opened.
     *
     * <p>This is what replaces the old push from {@code ScanView} after a save.
     * A scan finishing while this page is not visible cannot be missed, because
     * the list is not cached between visits -- there is no stale state to
     * invalidate.
     */
    @Override
    public void onShown() {
        list.refresh();
    }

    private void showResults() {
        detail.setCenter(resultsPane);
    }

    private void showSavedScan(ScanOutcome outcome) {
        showResults();
        // A stored scan carries no assessment: the v0.4.0 schema predates them,
        // and re-running the lookup here would stamp an old scan with today's
        // index. Map.of() renders every Vulnerabilities cell as "not checked",
        // which is the true statement about a scan taken before the index existed.
        table.show(outcome, Map.of());
        caption.setText(outcome.run().target().value() + "  -  "
                + WHEN.format(outcome.run().startedAt().atZone(ZoneId.systemDefault()))
                + "  -  " + outcome.totalOpenPorts() + " open port(s)");
    }

    private void showComparison(ScanOutcome first, ScanOutcome second) {
        ScanDiff diff = ScanComparator.compare(first, second);
        diffView.show(diff);
        detail.setCenter(diffView.root());
    }

    // Package-private accessors, for tests and harnesses.
    HistoryPane list()   { return list; }
    ResultsTable table() { return table; }
    DiffView diff()      { return diffView; }
}
