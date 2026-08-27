package com.cyberscope.ui;
 
import com.cyberscope.service.compare.ChangeKind;
import com.cyberscope.service.compare.DiffWarning;
import com.cyberscope.service.compare.HostDiff;
import com.cyberscope.service.compare.PortChange;
import com.cyberscope.service.compare.ScanDiff;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
 
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.function.Function;
 
/**
 * Shows one comparison.
 *
 * <p>The layout carries the argument, exactly as the text formatter does:
 * warnings above the table rather than below it, and a column that says whether
 * a row describes <em>the host</em> or <em>what we know about the host</em>.
 * A single undifferentiated list of "changes" would undo the whole of Part 3.
 */
public final class DiffView {
 
    private static final DateTimeFormatter WHEN =
            DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm:ss");
 
    private final Label headingLabel = new Label();
    private final Label subheadingLabel = new Label();
    private final Label warningLabel = new Label();
    private final Label coverageLabel = new Label();
    private final Button closeButton = new Button("Back to results");
    private final TableView<PortChange> table = new TableView<>();
    private final ObservableList<PortChange> rows = FXCollections.observableArrayList();
    private final VBox root = new VBox(8);
 
    public DiffView(Runnable onClose) {
        headingLabel.getStyleClass().add(Styles.SUMMARY);
        subheadingLabel.getStyleClass().add(Styles.MUTED);
        coverageLabel.getStyleClass().add(Styles.MUTED);
        coverageLabel.setWrapText(true);
 
        warningLabel.getStyleClass().add(Styles.WARNING);
        warningLabel.setWrapText(true);
        warningLabel.setMaxWidth(Double.MAX_VALUE);
        warningLabel.setVisible(false);
        warningLabel.setManaged(false);
 
        closeButton.setOnAction(event -> onClose.run());
 
        buildTable();
 
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        HBox header = new HBox(8, headingLabel, spacer, closeButton);
        header.setAlignment(Pos.CENTER_LEFT);
 
        VBox.setVgrow(table, Priority.ALWAYS);
        root.getChildren().setAll(header, subheadingLabel, warningLabel, table, coverageLabel);
        root.setPadding(new Insets(16));
        root.getStyleClass().add(Styles.SCAN_PANE);
    }
 
    public Region root() {
        return root;
    }
 
    private void buildTable() {
        table.setItems(rows);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        table.setPlaceholder(new Label("No differences at any port both scans examined."));
 
        TableColumn<PortChange, String> portColumn =
                column("Port", 95, c -> c.port() + "/" + c.protocol());
        styleCells(portColumn, c -> Styles.PORT_CELL);
 
        // The column that keeps Part 3's distinction visible. Without it a
        // reader has to know that EVIDENCE_LOST is not a host change.
        TableColumn<PortChange, String> kindColumn =
                column("Kind", 140, c -> c.isHostChange() ? "host change" : "evidence");
        styleCells(kindColumn, c -> severityClass(c.kind()));
 
        TableColumn<PortChange, String> whatColumn =
                column("What changed", 520, PortChange::describe);
        styleCells(whatColumn, c -> severityClass(c.kind()));
 
        table.getColumns().setAll(List.of(portColumn, kindColumn, whatColumn));
    }
 
    /**
     * Colour by what the change means for exposure, not by change type.
     *
     * <p>Red for a port that opened, green for one that closed, amber for a
     * change in evidence, neutral for everything else. The Kind column already
     * says which is which in words, so the colour is redundant coding and
     * nothing is lost in greyscale.
     */
    private static String severityClass(ChangeKind kind) {
        return switch (kind) {
            case PORT_OPENED -> Styles.CHANGE_WORSE;
            case PORT_CLOSED -> Styles.CHANGE_BETTER;
            case EVIDENCE_GAINED, EVIDENCE_LOST -> Styles.INFERRED;
            case STATE_CHANGED, SERVICE_CHANGED, VERSION_CHANGED -> null;
        };
    }
 
    public void show(ScanDiff diff) {
        rows.setAll(diff.hostChanges());
        rows.addAll(diff.evidenceChanges());
 
        headingLabel.setText("Comparing " + diff.after().run().target().value());
        subheadingLabel.setText(
                WHEN.format(diff.before().run().startedAt().atZone(ZoneId.systemDefault()))
                + "   →   "
                + WHEN.format(diff.after().run().startedAt().atZone(ZoneId.systemDefault()))
                + "      " + diff.hostChanges().size() + " host change(s), "
                + diff.evidenceChanges().size() + " evidence change(s)");
 
        StringBuilder note = new StringBuilder();
        for (DiffWarning warning : diff.warnings()) {
            if (note.length() > 0) {
                note.append('\n');
            }
            note.append(warning.invalidatesComparison() ? "⚠  " : "•  ")
                .append(warning.detail());
        }
        if (!diff.isTrustworthy()) {
            note.append("\n\nThe differences below are shown for completeness. Do not read them")
                .append(" as changes to one machine until the routes are accounted for.");
        }
        warningLabel.setText(note.toString());
        warningLabel.setVisible(note.length() > 0);
        warningLabel.setManaged(note.length() > 0);
 
        int uncompared = diff.hosts().stream()
                .mapToInt(host -> host.uncomparedPorts().size()).sum();
        boolean gap = diff.hosts().stream().anyMatch(HostDiff::hasCoverageGap);
        if (uncompared > 0 || gap) {
            coverageLabel.setText(uncompared + " port(s) were examined by only one of the two"
                    + " scans and were not compared. Nothing can be said about them.");
        } else {
            coverageLabel.setText("Every port either scan examined was covered by both.");
        }
    }
 
    // ------------------------------------------------- table plumbing
 
    private static TableColumn<PortChange, String> column(String title, double width,
                                                          Function<PortChange, String> value) {
        TableColumn<PortChange, String> col = new TableColumn<>(title);
        col.setPrefWidth(width);
        col.setCellValueFactory(cell -> {
            ObservableValue<String> v = new SimpleStringProperty(value.apply(cell.getValue()));
            return v;
        });
        return col;
    }
 
    /** Same recycling discipline as the results table: remove, then add. */
    private static void styleCells(TableColumn<PortChange, String> column,
                                   Function<PortChange, String> styleClass) {
        column.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(String value, boolean empty) {
                super.updateItem(value, empty);
                getStyleClass().removeAll(Styles.PORT_CELL, Styles.INFERRED,
                                          Styles.CHANGE_WORSE, Styles.CHANGE_BETTER);
                if (empty || value == null) {
                    setText(null);
                    return;
                }
                setText(value);
                // Column widths are finite and a describe() line is not; the
                // tooltip is the escape hatch rather than truncating text the
                // reader cannot recover.
                setTooltip(new javafx.scene.control.Tooltip(value));
                PortChange row = getTableView().getItems().get(getIndex());
                String applied = styleClass.apply(row);
                if (applied != null) {
                    getStyleClass().add(applied);
                }
            }
        });
    }
 
    // Package-private, for the headless harness.
    TableView<PortChange> table() { return table; }
    Label heading()               { return headingLabel; }
    Label warning()               { return warningLabel; }
    Label coverage()              { return coverageLabel; }
}
 

