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

    private final AppContext context;
    private final ReportExporter exporter;
    private final javafx.scene.control.Button exportButton =
            new javafx.scene.control.Button("Export report");
    private ScanOutcome selected;
    private java.util.Map<com.cyberscope.model.Port, com.cyberscope.model.VulnAssessment>
            selectedAssessments = Map.of();
    private ScoreScanTask scoring;
    private final HistoryPane list;
    private final ResultsTable table = new ResultsTable();
    private final DiffView diffView;
    private final Label caption = new Label("Select a scan to see its results.");
    private final BorderPane detail = new BorderPane();
    private final VBox resultsPane;
    private final Node node;

    HistoryPage(AppContext context) {
        this.context = context;
        this.exporter = new ReportExporter(context);
        caption.setWrapText(true);
        caption.getStyleClass().add(Styles.SUMMARY);

        table.setPlaceholder("Select a scan on the left.");
        exportButton.setDisable(true);
        exportButton.setTooltip(new javafx.scene.control.Tooltip(
                "Save this stored scan as an HTML report, scored against today's index."));
        exportButton.setOnAction(event -> {
            if (selected != null) {
                exporter.exportScan(ReportExporter.windowOf(exportButton),
                        selected, 0L,
                        com.cyberscope.service.score.PostureScorer.score(selectedAssessments));
            }
        });
        javafx.scene.layout.HBox captionRow =
                new javafx.scene.layout.HBox(12, caption, exportButton);
        captionRow.setAlignment(javafx.geometry.Pos.CENTER_LEFT);
        javafx.scene.layout.HBox.setHgrow(caption, Priority.ALWAYS);

        resultsPane = new VBox(8, captionRow, table.node());
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

    /**
     * Renders a stored scan, then scores it against the current index.
     *
     * <p>Drawn twice on purpose. The ports and service evidence are already in
     * hand and appear immediately; the findings need an index lookup per service
     * and arrive a moment later. Blocking the first paint on the second would
     * make selecting a scan feel broken for no gain, and the interim state is
     * honest -- the column reads "not checked" because, for that instant, it has
     * not been.
     */
    private void showSavedScan(ScanOutcome outcome) {
        showResults();
        selected = outcome;
        selectedAssessments = Map.of();
        exportButton.setDisable(false);
        table.show(outcome, Map.of());
        String summary = outcome.run().target().value() + "  -  "
                + WHEN.format(outcome.run().startedAt().atZone(ZoneId.systemDefault()))
                + "  -  " + outcome.totalOpenPorts() + " open port(s)";
        caption.setText(summary);

        if (scoring != null) {
            // Selecting a second scan while the first is still being scored must
            // not let the first one's findings land on the second one's ports.
            scoring.cancel(true);
        }
        if (context.cveIndex() == null) {
            return;
        }
        caption.setText(summary + "  -  scoring...");

        ScoreScanTask task = new ScoreScanTask(context, outcome);
        scoring = task;
        task.setOnSucceeded(event -> {
            scoring = null;
            selectedAssessments = task.getValue();
            table.show(outcome, task.getValue());
            caption.setText(summary + "  -  scored against today's CVE index");
        });
        task.setOnFailed(event -> {
            scoring = null;
            Throwable error = task.getException();
            caption.setText(summary + "  -  could not score: "
                    + (error == null ? "unknown error" : error.getMessage()));
        });
        task.setOnCancelled(event -> scoring = null);
        context.worker().submit(task);
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
