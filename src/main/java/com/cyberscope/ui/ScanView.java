package com.cyberscope.ui;
 
import com.cyberscope.model.DetectionMethod;
import com.cyberscope.model.Host;
import com.cyberscope.model.Port;
import com.cyberscope.model.ScanType;
import com.cyberscope.model.Service;
import com.cyberscope.repository.ScanRepository;
import com.cyberscope.service.scanner.ScanOutcome;
import com.cyberscope.util.InvalidTargetException;
import com.cyberscope.util.TargetValidator;
import com.cyberscope.util.ValidatedTarget;
import javafx.beans.binding.Bindings;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.SplitPane;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.util.StringConverter;
 
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Function;
 
/** The scan window's scene graph, wired to the real scanner. */
public final class ScanView {
 
    private final TextField targetField = new TextField();
    private final ComboBox<ScanType> scanTypeBox = new ComboBox<>();
    private final CheckBox authorisedBox = new CheckBox("I am authorised to scan this target");
    private final Button scanButton = new Button("Scan");
    private final Button stopButton = new Button("Stop");
    private final ProgressBar progressBar = new ProgressBar();
    private final Label statusLabel = new Label("Ready");
    private final Label rangeHintLabel = new Label();
    private final Label summaryLabel = new Label();
    private final Label warningLabel = new Label();
    private final TableView<PortRow> resultsTable = new TableView<>();
    private final ObservableList<PortRow> rows = FXCollections.observableArrayList();
 
    private TableColumn<PortRow, String> hostColumn;
    private ScanTask runningTask;
 
    private final ScanRepository repository;      // null when history is unavailable
    private final HistoryPane history;
    private final SplitPane root = new SplitPane();
    private final BorderPane scanPane = new BorderPane();
 
    private static final DateTimeFormatter WHEN =
            DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm:ss");
 
    /** One background thread for scans. Daemon, named, single. */
    private final ExecutorService scanExecutor = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "cyberscope-scan");
        thread.setDaemon(true);
        return thread;
    });
 
    /**
     * @param repository        may be null; the window still scans, history degrades
     * @param unavailableReason shown in the history pane when repository is null
     */
    public ScanView(ScanRepository repository, String unavailableReason) {
        this.repository = repository;
        buildControls();
        buildTable();
 
        VBox top = new VBox(10, targetRow(), rangeHintLabel, authorisedBox, actionRow());
        top.setPadding(new Insets(16));
 
        VBox centre = new VBox(6, summaryLabel, warningLabel, resultsTable);
        centre.setPadding(new Insets(0, 16, 8, 16));
        VBox.setVgrow(resultsTable, Priority.ALWAYS);
 
        HBox statusBar = new HBox(statusLabel);
        statusBar.setPadding(new Insets(8, 16, 12, 16));
 
        top.getStyleClass().add(Styles.SCAN_PANE);
        centre.getStyleClass().add(Styles.SCAN_PANE);
        statusBar.getStyleClass().add(Styles.STATUS_BAR);
        scanPane.getStyleClass().add(Styles.SCAN_PANE);
 
        scanPane.setTop(top);
        scanPane.setCenter(centre);
        scanPane.setBottom(statusBar);
 
        history = new HistoryPane(repository, unavailableReason, this::showSavedScan);
 
        root.getItems().setAll(history.root(), scanPane);
        // A divider position is a fraction of the width, not pixels. Pinning the
        // history pane's minimum width in HistoryPane stops a drag from collapsing
        // it to nothing, which SplitPane will otherwise happily do.
        root.setDividerPositions(0.28);
        SplitPane.setResizableWithParent(history.root(), false);
 
        // Attached to the root Parent rather than the Scene, so this view is
        // styled wherever it is used -- including the headless snapshot harness.
        Styles.apply(root);
    }
 
    public SplitPane root() {
        return root;
    }
 
    public void shutdown() {
        if (runningTask != null) {
            runningTask.cancel(true);
        }
        scanExecutor.shutdownNow();
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
 
    private void buildTable() {
        resultsTable.setItems(rows);
        resultsTable.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        resultsTable.setPlaceholder(new Label("No results yet."));
 
        hostColumn = column("Host", 130, r -> r.host());
        hostColumn.setVisible(false);       // shown only for multi-host results
 
        TableColumn<PortRow, String> portColumn =
                column("Port", 85, r -> r.port().number() + "/" + r.port().protocol());
        styleCells(portColumn, row -> Styles.PORT_CELL);
 
        // The Detection column is the one place colour carries meaning: green for
        // a service that was probed and confirmed, amber for one inferred from the
        // port number. The text still says which, so the colour is redundant
        // coding -- nothing is lost in greyscale or to a colour-blind reader.
        TableColumn<PortRow, String> detectionColumn =
                column("Detection", 150, r -> describeDetection(r.port().service()));
        styleCells(detectionColumn, row -> switch (row.port().service().method()) {
            case PROBED -> Styles.PROBED;
            case TABLE  -> Styles.INFERRED;
            case NONE   -> null;
        });
 
        resultsTable.getColumns().setAll(List.of(
                hostColumn,
                portColumn,
                column("State",     70,  r -> r.port().state().toString()),
                column("Service",   105, r -> r.port().service().name().isBlank()
                                              ? "unknown" : r.port().service().name()),
                column("Version",   190, r -> r.port().service().product().isBlank()
                                              ? "-" : r.port().service().describe()),
                detectionColumn));
    }
 
    /** Lambda, not PropertyValueFactory: records expose number(), not getNumber(). */
    private static TableColumn<PortRow, String> column(String title, double width,
                                                       Function<PortRow, String> value) {
        TableColumn<PortRow, String> col = new TableColumn<>(title);
        col.setPrefWidth(width);
        col.setCellValueFactory(cell -> {
            ObservableValue<String> v = new SimpleStringProperty(value.apply(cell.getValue()));
            return v;
        });
        return col;
    }
 
    /**
     * Gives each cell in a column a style class derived from its row.
     *
     * <p>The {@code removeAll} is the part that matters. JavaFX recycles table
     * cells as the view scrolls: the same TableCell object is reused for a
     * different row, keeping whatever style classes it was given last time. Add
     * without removing and a scrolled table ends up with green and amber applied
     * to rows they do not belong to -- which, in a tool whose entire point is
     * distinguishing verified from inferred, would be worse than no colour at all.
     */
    private static void styleCells(TableColumn<PortRow, String> column,
                                   Function<PortRow, String> styleClass) {
        column.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(String value, boolean empty) {
                super.updateItem(value, empty);
                getStyleClass().removeAll(Styles.PORT_CELL, Styles.PROBED, Styles.INFERRED);
                if (empty || value == null) {
                    setText(null);
                    return;
                }
                setText(value);
                PortRow row = getTableView().getItems().get(getIndex());
                String applied = styleClass.apply(row);
                if (applied != null) {
                    getStyleClass().add(applied);
                }
            }
        });
    }
 
    private static String describeDetection(Service service) {
        return switch (service.method()) {
            case PROBED -> "probed (" + service.confidence() + "/10)";
            case TABLE  -> "table ("  + service.confidence() + "/10)";
            case NONE   -> "-";
        };
    }
 
    // ---------------------------------------------------------------- scanning
 
    void startScan() {
        ScanTask task = new ScanTask(scanTypeBox.getValue(), targetField.getText(), repository);
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
            showOutcome(task.getValue());
            recordInHistory(task);
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
 
        scanExecutor.execute(task);
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
 
    void showOutcome(ScanOutcome outcome) {
        List<Host> withOpenPorts = outcome.hosts().stream()
                .filter(h -> !h.openPorts().isEmpty())
                .toList();
 
        List<PortRow> newRows = new ArrayList<>();
        for (Host host : outcome.hosts()) {
            for (Port port : host.openPorts()) {
                newRows.add(new PortRow(host.displayName(), port));
            }
        }
        rows.setAll(newRows);
 
        // The Host column is noise when every row says the same thing.
        hostColumn.setVisible(withOpenPorts.size() > 1);
 
        resultsTable.setPlaceholder(new Label("No open ports found on this target."));
 
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
 
    // ----------------------------------------------------------------- history
 
    /**
     * Refreshes the history list after a scan and reports whether the save worked.
     *
     * <p>Appended to the status line rather than raised as a dialog. A modal error
     * box on top of results the user is reading, for a failure that cost them
     * nothing, is a punishment for using the program.
     */
    private void recordInHistory(ScanTask task) {
        if (repository == null) {
            return;
        }
        if (task.saveError() != null) {
            statusLabel.setText(statusLabel.getText()
                    + "   [not saved: " + task.saveError() + "]");
            return;
        }
        history.refresh();
        if (task.savedId() > 0) {
            history.selectById(task.savedId());
        }
    }
 
    /**
     * Renders a scan loaded from the database.
     *
     * <p>Deliberately reuses {@code showOutcome}: a saved scan and a fresh one are
     * the same type, so they render through the same code. Only the status line
     * differs, because the one thing the user must not be confused about is whether
     * they are looking at something that just happened or something from last week.
     */
    void showSavedScan(ScanOutcome outcome) {
        if (runningTask != null) {
            return;                     // never stamp on a scan in progress
        }
        showOutcome(outcome);
        targetField.setText(outcome.run().target().value());
        scanTypeBox.getSelectionModel().select(outcome.run().scanType());
        statusLabel.setText("Saved scan from "
                + WHEN.format(outcome.run().startedAt().atZone(ZoneId.systemDefault()))
                + "  -  " + String.join(" ", outcome.run().command()));
    }
 
    private void showError(Throwable error) {
        rows.clear();
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
    TableView<PortRow> table()  { return resultsTable; }
    Button button()             { return scanButton; }
    Button stop()               { return stopButton; }
    CheckBox authorised()       { return authorisedBox; }
    TextField target()          { return targetField; }
    Label status()              { return statusLabel; }
    Label summary()             { return summaryLabel; }
    Label warning()             { return warningLabel; }
    Label rangeHint()           { return rangeHintLabel; }
    ProgressBar progress()      { return progressBar; }
    TableColumn<PortRow, String> hostColumn() { return hostColumn; }
    HistoryPane history()       { return history; }
    String scanTypeBoxValue()   { return scanTypeBox.getValue().displayName(); }
    Executor executor()         { return scanExecutor; }
}
 

