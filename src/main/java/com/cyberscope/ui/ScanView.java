package com.cyberscope.ui;

import com.cyberscope.model.DetectionMethod;
import com.cyberscope.model.Host;
import com.cyberscope.model.Port;
import com.cyberscope.model.ScanType;
import com.cyberscope.model.Service;
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
    private final ProgressBar progressBar = new ProgressBar();
    private final Label statusLabel = new Label("Ready");
    private final Label summaryLabel = new Label();
    private final Label warningLabel = new Label();
    private final TableView<Port> resultsTable = new TableView<>();
    private final ObservableList<Port> rows = FXCollections.observableArrayList();

    private final BorderPane root = new BorderPane();

    /**
     * One background thread for scans. Daemon, so a scan in flight can never keep
     * the JVM alive after the window closes. Named, so it is identifiable in a
     * thread dump. Single, so two scans can never run concurrently.
     */
    private final ExecutorService scanExecutor = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "cyberscope-scan");
        thread.setDaemon(true);
        return thread;
    });

    public ScanView() {
        buildControls();
        buildTable();

        VBox top = new VBox(10, targetRow(), authorisedBox, actionRow());
        top.setPadding(new Insets(16));

        VBox centre = new VBox(6, summaryLabel, warningLabel, resultsTable);
        centre.setPadding(new Insets(0, 16, 8, 16));
        VBox.setVgrow(resultsTable, Priority.ALWAYS);

        HBox statusBar = new HBox(statusLabel);
        statusBar.setPadding(new Insets(8, 16, 12, 16));

        root.setTop(top);
        root.setCenter(centre);
        root.setBottom(statusBar);
    }

    public BorderPane root() {
        return root;
    }

    /** Called from Application.stop() so the executor does not outlive the window. */
    public void shutdown() {
        scanExecutor.shutdownNow();
    }

    private void buildControls() {
        targetField.setPromptText("IPv4 address or hostname, e.g. 127.0.0.1");
        HBox.setHgrow(targetField, Priority.ALWAYS);

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
        });

        scanButton.setDefaultButton(true);
        scanButton.setOnAction(event -> startScan());
        restoreScanButtonBinding();

        progressBar.setVisible(false);
        progressBar.setManaged(false);
        progressBar.setPrefWidth(160);

        warningLabel.setVisible(false);
        warningLabel.setManaged(false);
        warningLabel.setWrapText(true);
        warningLabel.setStyle("-fx-text-fill: #8a6d00;");
    }

    private HBox targetRow() {
        Label label = new Label("Target:");
        label.setMinWidth(60);
        HBox row = new HBox(8, label, targetField, scanTypeBox);
        row.setAlignment(Pos.CENTER_LEFT);
        return row;
    }

    private HBox actionRow() {
        HBox row = new HBox(12, scanButton, progressBar);
        row.setAlignment(Pos.CENTER_LEFT);
        return row;
    }

    private void buildTable() {
        resultsTable.setItems(rows);
        resultsTable.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        resultsTable.setPlaceholder(new Label("No results yet."));

        resultsTable.getColumns().setAll(List.of(
                column("Port",      90,  p -> p.number() + "/" + p.protocol()),
                column("State",     80,  p -> p.state().toString()),
                column("Service",   120, p -> p.service().name().isBlank()
                                              ? "unknown" : p.service().name()),
                column("Version",   260, p -> p.service().product().isBlank()
                                              ? "-" : p.service().describe()),
                column("Detection", 130, p -> describeDetection(p.service()))));
    }

    /** Lambda, not PropertyValueFactory: records expose number(), not getNumber(). */
    private static TableColumn<Port, String> column(String title, double width,
                                                    Function<Port, String> value) {
        TableColumn<Port, String> col = new TableColumn<>(title);
        col.setPrefWidth(width);
        col.setCellValueFactory(cell -> {
            ObservableValue<String> v = new SimpleStringProperty(value.apply(cell.getValue()));
            return v;
        });
        return col;
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
        ScanTask task = new ScanTask(scanTypeBox.getValue(), targetField.getText());

        // A bound property cannot be assigned, so the authorisation binding is
        // released for the duration of the scan and restored in finishScan().
        scanButton.disableProperty().unbind();
        scanButton.setDisable(true);
        targetField.setDisable(true);
        scanTypeBox.setDisable(true);

        setBusy(true);

        // Nmap reports no machine-readable progress by default, so the bar is
        // indeterminate rather than pretending to know a percentage.
        progressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);

        // A Task's message starts empty, which would blank the label for an instant.
        statusLabel.textProperty().bind(
                Bindings.when(task.messageProperty().isEmpty())
                        .then("Starting scan...")
                        .otherwise(task.messageProperty()));

        // Both handlers are invoked by JavaFX on the FX Application Thread.
        task.setOnSucceeded(event -> {
            statusLabel.textProperty().unbind();
            finishScan();
            showOutcome(task.getValue());
        });

        task.setOnFailed(event -> {
            statusLabel.textProperty().unbind();
            finishScan();
            statusLabel.setText("Scan failed.");
            showError(task.getException());
        });

        scanExecutor.execute(task);
    }

    private void finishScan() {
        // Re-enable the inputs before hiding the progress bar, so the window is
        // never briefly idle-looking but unusable.
        targetField.setDisable(false);
        scanTypeBox.setDisable(false);
        restoreScanButtonBinding();
        setBusy(false);
    }

    /** The v0.0.9 rule: a target must be present and authorisation ticked. */
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
        rows.setAll(outcome.hosts().stream().flatMap(h -> h.openPorts().stream()).toList());

        // "No results yet" is wrong once a scan has run and found nothing.
        resultsTable.setPlaceholder(new Label("No open ports found on this target."));

        if (outcome.hosts().isEmpty()) {
            summaryLabel.setText("No hosts found. The target may be down, filtered,"
                               + " or unresolvable.");
        } else {
            Host first = outcome.hosts().get(0);
            String who = outcome.hosts().size() == 1
                    ? first.displayName() + "  [" + first.state() + "]"
                    : outcome.hosts().size() + " hosts";
            summaryLabel.setText(who + "  -  " + outcome.totalOpenPorts() + " open port(s)");
        }

        boolean guessed = outcome.hosts().stream()
                .flatMap(h -> h.openPorts().stream())
                .anyMatch(p -> p.service().method() == DetectionMethod.TABLE);

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

    // Package-private accessors, for tests and manual harnesses.
    TableView<Port> table()   { return resultsTable; }
    Button button()           { return scanButton; }
    CheckBox authorised()     { return authorisedBox; }
    TextField target()        { return targetField; }
    Label status()            { return statusLabel; }
    Label summary()           { return summaryLabel; }
    Label warning()           { return warningLabel; }
    ProgressBar progress()    { return progressBar; }
    Executor executor()       { return scanExecutor; }
}
