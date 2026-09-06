package com.cyberscope.ui;

import com.cyberscope.model.DetectionMethod;
import com.cyberscope.model.Host;
import com.cyberscope.model.Port;
import com.cyberscope.model.ScanType;
import com.cyberscope.model.VulnAssessment;
import com.cyberscope.repository.IndexMetadata;
import com.cyberscope.repository.RepositoryException;
import com.cyberscope.service.scanner.ScanOutcome;
import com.cyberscope.util.InvalidTargetException;
import com.cyberscope.util.TargetValidator;
import com.cyberscope.util.ValidatedTarget;
import javafx.beans.binding.Bindings;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.util.StringConverter;

import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;

/**
 * Run a scan, and show what came back.
 *
 * <p>Formerly {@code ScanView}, which was the whole window: it owned the history
 * pane, the split, the comparison view, the CVE index handle and the background
 * executor. In v0.6.0 it owns one page. History moved to {@link HistoryPage},
 * the table to {@link ResultsTable}, and the shared handles to
 * {@link AppContext} -- so what is left here is the scan form, its state
 * machine, and the index bar.
 *
 * <p>That is a real reduction, not a reshuffle: this class no longer knows a
 * saved scan exists.
 */
final class ScanPage implements Page {

    private final AppContext context;

    private final TextField targetField = new TextField();
    private final ComboBox<ScanType> scanTypeBox = new ComboBox<>();
    private final CheckBox authorisedBox = new CheckBox("I am authorised to scan this target");
    private final Button scanButton = new Button("Scan");
    private final Button stopButton = new Button("Stop");
    private final ProgressBar progressBar = new ProgressBar();
    private final Label statusLabel = new Label("Ready");

    private final Label indexLabel = new Label();
    private final Button updateIndexButton = new Button("Update CVE index");
    private final ProgressBar indexProgress = new ProgressBar();

    private final Label rangeHintLabel = new Label();
    private final Label summaryLabel = new Label();
    private final Label warningLabel = new Label();
    private final ResultsTable results = new ResultsTable();

    private Map<Port, VulnAssessment> lastAssessments = Map.of();
    private ScanTask runningTask;
    private final Node node;

    ScanPage(AppContext context) {
        this.context = context;
        buildControls();

        VBox top = new VBox(10, targetRow(), rangeHintLabel, authorisedBox, actionRow());
        top.setPadding(new Insets(4, 20, 12, 20));

        VBox centre = new VBox(6, summaryLabel, warningLabel, results.node());
        centre.setPadding(new Insets(0, 20, 8, 20));
        VBox.setVgrow(results.node(), Priority.ALWAYS);

        HBox statusBar = new HBox(statusLabel);
        statusBar.setPadding(new Insets(8, 20, 4, 20));
        statusBar.getStyleClass().add(Styles.STATUS_BAR);

        BorderPane body = new BorderPane();
        body.getStyleClass().add(Styles.SCAN_PANE);
        body.setTop(top);
        body.setCenter(centre);
        body.setBottom(new VBox(statusBar, buildIndexBar()));

        this.node = PageFrame.wrap(PageId.SCAN, body);
    }

    @Override
    public PageId id() {
        return PageId.SCAN;
    }

    @Override
    public Node node() {
        return node;
    }

    void shutdown() {
        if (runningTask != null) {
            runningTask.cancel(true);
        }
    }

    private void buildControls() {
        targetField.setPromptText("IPv4 address, hostname, or CIDR range, e.g. 192.168.1.0/24");
        targetField.getStyleClass().add(Styles.TARGET_FIELD);
        HBox.setHgrow(targetField, Priority.ALWAYS);
        targetField.textProperty().addListener((obs, old, now) -> updateRangeHint(now));

        scanTypeBox.getItems().setAll(ScanType.values());
        scanTypeBox.getSelectionModel().select(ScanType.QUICK);
        scanTypeBox.setPrefWidth(140);
        scanTypeBox.setConverter(new StringConverter<>() {
            @Override public String toString(ScanType type) {
                return type == null ? "" : type.displayName();
            }
            @Override public ScanType fromString(String text) {
                return scanTypeBox.getValue();
            }
        });
        scanTypeBox.setTooltip(new Tooltip(ScanType.QUICK.description()));
        scanTypeBox.valueProperty().addListener((obs, old, now) -> {
            if (now != null) {
                scanTypeBox.setTooltip(new Tooltip(now.description()));
            }
            updateRangeHint(targetField.getText());
        });

        scanButton.setDefaultButton(true);
        scanButton.getStyleClass().add(Styles.PRIMARY);
        scanButton.setOnAction(event -> startScan());
        restoreScanButtonBinding();

        stopButton.setDisable(true);
        stopButton.getStyleClass().add(Styles.DESTRUCTIVE);
        stopButton.setOnAction(event -> stopScan());
        stopButton.setTooltip(new Tooltip("Cancel the running scan and terminate Nmap"));

        progressBar.setVisible(false);
        progressBar.setManaged(false);
        progressBar.setPrefWidth(160);

        rangeHintLabel.setVisible(false);
        rangeHintLabel.setManaged(false);
        rangeHintLabel.getStyleClass().add(Styles.HINT);

        summaryLabel.getStyleClass().add(Styles.SUMMARY);

        warningLabel.setVisible(false);
        warningLabel.setManaged(false);
        warningLabel.setWrapText(true);
        warningLabel.setMaxWidth(Double.MAX_VALUE);
        warningLabel.getStyleClass().add(Styles.WARNING);
    }

    /**
     * Shows how many addresses a range covers, and the timeout it will be given,
     * before the user commits to it. Silent for a single host, and silent while the
     * input is still incomplete -- nagging someone mid-keystroke is worse than
     * saying nothing.
     */
    private void updateRangeHint(String raw) {
        String hint = "";
        if (raw != null && raw.contains("/")) {
            try {
                ValidatedTarget target = TargetValidator.validate(raw);
                if (target.isRange()) {
                    hint = target.describe() + "  -  timeout budget "
                         + scanTypeBox.getValue().timeoutFor(target.addressCount()).toSeconds()
                         + " s";
                }
            } catch (InvalidTargetException e) {
                hint = e.getMessage();
            }
        }
        rangeHintLabel.setText(hint);
        rangeHintLabel.setVisible(!hint.isEmpty());
        rangeHintLabel.setManaged(!hint.isEmpty());
    }

    private HBox targetRow() {
        Label label = new Label("Target:");
        label.setMinWidth(60);
        HBox row = new HBox(8, label, targetField, scanTypeBox);
        row.setAlignment(Pos.CENTER_LEFT);
        return row;
    }

    private HBox actionRow() {
        HBox row = new HBox(12, scanButton, stopButton, progressBar);
        row.setAlignment(Pos.CENTER_LEFT);
        return row;
    }

    // ------------------------------------------------------------ CVE index

    private HBox buildIndexBar() {
        indexProgress.setVisible(false);
        indexProgress.setManaged(false);
        indexProgress.setPrefWidth(160);

        updateIndexButton.setOnAction(event -> refreshCveIndex());
        updateIndexButton.setDisable(context.indexManager() == null);
        updateIndexButton.setTooltip(new Tooltip(
                "Downloads about 100 MB of public NVD data and rebuilds the local"
                + " index.\nTakes roughly a minute. Nothing about your network"
                + " leaves this machine."));

        indexLabel.setMaxWidth(Double.MAX_VALUE);
        HBox.setHgrow(indexLabel, Priority.ALWAYS);

        HBox bar = new HBox(10, indexLabel, indexProgress, updateIndexButton);
        bar.setAlignment(Pos.CENTER_LEFT);
        bar.getStyleClass().add(Styles.INDEX_BAR);
        refreshIndexLabel();
        return bar;
    }

    /** One line saying what the index holds and how old it is. */
    private void refreshIndexLabel() {
        indexLabel.getStyleClass().remove(Styles.INDEX_STALE);
        if (context.cveIndex() == null) {
            indexLabel.setText("CVE index unavailable - vulnerability lookup is off.");
            indexLabel.getStyleClass().add(Styles.INDEX_STALE);
            return;
        }
        try {
            IndexMetadata metadata = context.cveIndex().metadata().orElse(null);
            if (metadata == null) {
                indexLabel.setText("No CVE index yet. Services will be reported as"
                                 + " unchecked until you build one.");
                indexLabel.getStyleClass().add(Styles.INDEX_STALE);
                return;
            }
            Instant now = Instant.now();
            indexLabel.setText(metadata.describe(now, ZoneId.systemDefault()));
            if (metadata.isStale(now)) {
                indexLabel.getStyleClass().add(Styles.INDEX_STALE);
            }
        } catch (RepositoryException e) {
            indexLabel.setText("CVE index could not be read: " + e.getMessage());
            indexLabel.getStyleClass().add(Styles.INDEX_STALE);
        }
    }

    private void refreshCveIndex() {
        if (context.indexManager() == null) {
            return;
        }
        CveIndexTask task = new CveIndexTask(context.indexManager());

        indexProgress.setVisible(true);
        indexProgress.setManaged(true);
        indexProgress.progressProperty().bind(task.progressProperty());
        indexLabel.textProperty().bind(task.messageProperty());
        updateIndexButton.setText("Cancel");
        updateIndexButton.setOnAction(event -> task.cancel(true));

        Runnable finish = () -> {
            indexProgress.progressProperty().unbind();
            indexLabel.textProperty().unbind();
            indexProgress.setVisible(false);
            indexProgress.setManaged(false);
            updateIndexButton.setText("Update CVE index");
            updateIndexButton.setOnAction(e -> refreshCveIndex());
            refreshIndexLabel();
        };

        task.setOnSucceeded(event -> finish.run());
        task.setOnCancelled(event -> finish.run());
        task.setOnFailed(event -> {
            finish.run();
            Throwable error = task.getException();
            indexLabel.setText("Index refresh failed: "
                    + (error == null ? "unknown error" : error.getMessage()));
            indexLabel.getStyleClass().add(Styles.INDEX_STALE);
        });
        context.worker().submit(task);
    }

    // ---------------------------------------------------------------- scanning

    void startScan() {
        ScanTask task = new ScanTask(scanTypeBox.getValue(), targetField.getText(),
                                     context.scans(), context.cveIndex());
        runningTask = task;

        scanButton.disableProperty().unbind();
        scanButton.setDisable(true);
        stopButton.setDisable(false);
        targetField.setDisable(true);
        scanTypeBox.setDisable(true);

        setBusy(true);
        progressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);

        statusLabel.textProperty().bind(
                Bindings.when(task.messageProperty().isEmpty())
                        .then("Starting scan...")
                        .otherwise(task.messageProperty()));

        task.setOnSucceeded(event -> {
            statusLabel.textProperty().unbind();
            finishScan();
            // Read before showOutcome: the row factory consults this map while
            // building the table, so populating it afterwards would render one
            // table with no vulnerability data and never refresh it.
            lastAssessments = task.assessments();
            showOutcome(task.getValue());
            reportSave(task);
        });

        task.setOnFailed(event -> {
            statusLabel.textProperty().unbind();
            finishScan();
            statusLabel.setText("Scan failed.");
            showError(task.getException());
        });

        // Cancellation is not a failure: no dialog, and whatever was on screen stays.
        task.setOnCancelled(event -> {
            statusLabel.textProperty().unbind();
            finishScan();
            statusLabel.setText("Scan cancelled. Nmap was terminated.");
        });

        context.worker().execute(task);
    }

    void stopScan() {
        if (runningTask != null) {
            stopButton.setDisable(true);
            statusLabel.textProperty().unbind();
            statusLabel.setText("Cancelling...");
            // true = interrupt the worker thread. The interrupt unblocks
            // Process.waitFor, and ProcessRunner's finally block kills Nmap.
            runningTask.cancel(true);
        }
    }

    private void finishScan() {
        runningTask = null;
        targetField.setDisable(false);
        scanTypeBox.setDisable(false);
        stopButton.setDisable(true);
        restoreScanButtonBinding();
        setBusy(false);
    }

    private void restoreScanButtonBinding() {
        scanButton.setDisable(false);
        scanButton.disableProperty().bind(
                authorisedBox.selectedProperty().not()
                        .or(targetField.textProperty().isEmpty()));
    }

    private void setBusy(boolean busy) {
        progressBar.setVisible(busy);
        progressBar.setManaged(busy);
    }

    /**
     * Says so in the status line if the scan could not be saved.
     *
     * <p>Appended rather than raised as a dialog. A modal error box on top of
     * results the user is reading, for a failure that cost them nothing, is a
     * punishment for using the program.
     *
     * <p>No longer refreshes the history list: {@link HistoryPage} re-reads it
     * whenever it is opened, so there is nothing to push.
     */
    private void reportSave(ScanTask task) {
        if (context.hasScans() && task.saveError() != null) {
            statusLabel.setText(statusLabel.getText()
                    + "   [not saved: " + task.saveError() + "]");
        }
    }

    void showOutcome(ScanOutcome outcome) {
        List<PortRow> newRows = results.show(outcome, lastAssessments);

        if (outcome.hosts().isEmpty()) {
            summaryLabel.setText("No hosts found. The target may be down, filtered,"
                               + " or unresolvable.");
        } else if (outcome.run().target().isRange()) {
            long up = outcome.hosts().stream().filter(Host::isUp).count();
            summaryLabel.setText(outcome.run().target().describe() + "  -  "
                    + outcome.hosts().size() + " responded, " + up + " up, "
                    + outcome.totalOpenPorts() + " open port(s)");
        } else {
            Host first = outcome.hosts().get(0);
            summaryLabel.setText(first.displayName() + "  [" + first.state() + "]  -  "
                    + outcome.totalOpenPorts() + " open port(s)");
        }

        boolean guessed = newRows.stream()
                .anyMatch(r -> r.port().service().method() == DetectionMethod.TABLE);

        StringBuilder note = new StringBuilder();
        if (outcome.run().hasWarnings()) {
            note.append("Nmap: ").append(outcome.run().warnings().replace("\n", "  "));
        }
        if (guessed) {
            if (note.length() > 0) {
                note.append('\n');
            }
            note.append("Some services were inferred from the port number, not probed."
                      + " Treat those as unconfirmed.");
        }
        warningLabel.setText(note.toString());
        warningLabel.setVisible(note.length() > 0);
        warningLabel.setManaged(note.length() > 0);

        statusLabel.setText(String.format("Done in %.1f s  -  %s",
                outcome.run().elapsed().toMillis() / 1000.0,
                String.join(" ", outcome.run().command())));
    }

    private void showError(Throwable error) {
        results.clear();
        summaryLabel.setText("");
        warningLabel.setVisible(false);
        warningLabel.setManaged(false);

        String message = error == null ? "Unknown error"
                : (error.getMessage() == null ? error.toString() : error.getMessage());

        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Scan failed");
        alert.setHeaderText(error == null ? "Scan failed"
                : error.getClass().getSimpleName().replaceAll("Exception$", ""));
        TextArea detail = new TextArea(message);
        detail.setEditable(false);
        detail.setWrapText(true);
        detail.setPrefRowCount(6);
        alert.getDialogPane().setContent(detail);
        alert.showAndWait();
    }

    // Package-private accessors, for tests and harnesses.
    ResultsTable results()      { return results; }
    Button button()             { return scanButton; }
    Button stop()               { return stopButton; }
    CheckBox authorised()       { return authorisedBox; }
    TextField target()          { return targetField; }
    Label status()              { return statusLabel; }
    Label summary()             { return summaryLabel; }
    Label warning()             { return warningLabel; }
    Label rangeHint()           { return rangeHintLabel; }
    ProgressBar progress()      { return progressBar; }
    String scanTypeBoxValue()   { return scanTypeBox.getValue().displayName(); }
    Executor executor()         { return context.worker(); }
}
