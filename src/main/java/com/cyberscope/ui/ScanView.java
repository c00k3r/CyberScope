package com.cyberscope.ui;

import com.cyberscope.model.Host;
import com.cyberscope.model.Port;
import com.cyberscope.model.ScanType;
import com.cyberscope.model.Service;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.util.StringConverter;

import java.util.List;
import java.util.function.Function;

/**
 * The scan window's scene graph.
 *
 * <p>A plain class rather than an {@code Application}, so it can be constructed
 * and inspected in a test. At v0.0.9 the Scan button loads static sample data;
 * at v0.1.0 it launches a real scan on a background {@code Task}.
 */
public final class ScanView {

    private final TextField targetField = new TextField();
    private final ComboBox<ScanType> scanTypeBox = new ComboBox<>();
    private final CheckBox authorisedBox = new CheckBox("I am authorised to scan this target");
    private final Button scanButton = new Button("Scan");
    private final Label statusLabel = new Label("Ready");
    private final Label hostLabel = new Label();
    private final TableView<Port> resultsTable = new TableView<>();
    private final ObservableList<Port> rows = FXCollections.observableArrayList();

    private final BorderPane root = new BorderPane();

    public ScanView() {
        buildControls();
        buildTable();

        VBox top = new VBox(10, targetRow(), authorisedBox, buttonRow());
        top.setPadding(new Insets(16));

        VBox centre = new VBox(6, hostLabel, resultsTable);
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

    private void buildControls() {
        targetField.setPromptText("IPv4 address or hostname, e.g. 127.0.0.1");
        HBox.setHgrow(targetField, Priority.ALWAYS);

        scanTypeBox.getItems().setAll(ScanType.values());
        scanTypeBox.getSelectionModel().select(ScanType.QUICK);
        scanTypeBox.setPrefWidth(140);

        // Presentation belongs to the UI, not the model: an enum should not
        // override toString() just to look right in a dropdown.
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

        // The rule -- a target must be present AND authorisation ticked -- is
        // stated once, declaratively. JavaFX keeps it true from then on.
        scanButton.setDefaultButton(true);
        scanButton.disableProperty().bind(
                authorisedBox.selectedProperty().not()
                        .or(targetField.textProperty().isEmpty()));

        scanButton.setOnAction(event -> loadSampleData());
    }

    private HBox targetRow() {
        Label label = new Label("Target:");
        label.setMinWidth(60);
        HBox row = new HBox(8, label, targetField, scanTypeBox);
        row.setAlignment(Pos.CENTER_LEFT);
        return row;
    }

    private HBox buttonRow() {
        HBox row = new HBox(8, scanButton);
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

    /**
     * Builds a column from a plain function.
     *
     * <p>{@code PropertyValueFactory} cannot be used here. It reflects for JavaBean
     * getters such as {@code getNumber()}, and a record exposes {@code number()}.
     * The lookup fails, the exception is logged rather than thrown, and the column
     * renders blank with no visible error. A lambda is checked at compile time.
     */
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

    /** v0.0.9 only: proves the table renders. Replaced by a real scan at v0.1.0. */
    private void loadSampleData() {
        statusLabel.setText("Loaded sample data - no scan was performed");
        showHost(SampleData.host());
    }

    /** Populates the table from a host. Must be called on the FX Application Thread. */
    void showHost(Host host) {
        hostLabel.setText(host.displayName() + "  [" + host.state() + "]  -  "
                        + host.openPorts().size() + " open port(s)");
        rows.setAll(host.openPorts());
    }

    // Package-private accessors, for tests.
    TableView<Port> table()  { return resultsTable; }
    Button button()          { return scanButton; }
    CheckBox authorised()    { return authorisedBox; }
    TextField target()       { return targetField; }
    Label status()           { return statusLabel; }
}
