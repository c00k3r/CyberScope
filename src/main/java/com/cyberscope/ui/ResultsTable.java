package com.cyberscope.ui;

import com.cyberscope.model.Host;
import com.cyberscope.model.MappingOutcome;
import com.cyberscope.model.Port;
import com.cyberscope.model.Service;
import com.cyberscope.model.VulnAssessment;
import com.cyberscope.service.scanner.ScanOutcome;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.Label;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * The open-ports table.
 *
 * <p>Lifted out of {@code ScanView} in v0.6.0 because two pages now render the
 * same thing: the scan page shows the run that just finished, and the history
 * page shows a run loaded from the database. Before the split those were the
 * same table because there was only one page. Duplicating 90 lines of column
 * definitions to get a second one would have meant two places to fix the next
 * time a column's meaning changes -- and the columns here are the whole product,
 * so that is not a risk worth taking to save a file.
 *
 * <p>Stateless with respect to scanning: hand it a {@link ScanOutcome} and a map
 * of assessments and it renders them. It does not know what a scan is, where the
 * outcome came from, or whether it is current.
 */
final class ResultsTable {

    private final TableView<PortRow> table = new TableView<>();
    private final ObservableList<PortRow> rows = FXCollections.observableArrayList();
    private TableColumn<PortRow, String> hostColumn;

    ResultsTable() {
        table.setItems(rows);
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        table.setPlaceholder(new Label("No results yet."));
        buildColumns();
    }

    TableView<PortRow> node() {
        return table;
    }

    ObservableList<PortRow> rows() {
        return rows;
    }

    TableColumn<PortRow, String> hostColumn() {
        return hostColumn;
    }

    void setPlaceholder(String text) {
        table.setPlaceholder(new Label(text));
    }

    void clear() {
        rows.clear();
    }

    /**
     * Renders one scan.
     *
     * @param assessments per-port vulnerability results; {@link Map#of()} for a
     *                    scan that was never assessed, never null -- a null map
     *                    here and an empty one mean different things in the
     *                    Vulnerabilities column and only one of them is "not
     *                    checked"
     * @return the rows now showing, so the caller can summarise them without
     *         reaching back into the table's model
     */
    List<PortRow> show(ScanOutcome outcome, Map<Port, VulnAssessment> assessments) {
        List<PortRow> newRows = new ArrayList<>();
        for (Host host : outcome.hosts()) {
            for (Port port : host.openPorts()) {
                newRows.add(new PortRow(host.displayName(), port, assessments.get(port)));
            }
        }
        rows.setAll(newRows);

        // The Host column is noise when every row says the same thing.
        long hostsWithPorts = outcome.hosts().stream()
                .filter(h -> !h.openPorts().isEmpty())
                .count();
        hostColumn.setVisible(hostsWithPorts > 1);

        setPlaceholder("No open ports found on this target.");
        return newRows;
    }

    private void buildColumns() {
        hostColumn = column("Host", 130, PortRow::host);
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

        // The column the whole of v0.5.0 exists to fill. Note that it never
        // renders an empty cell: "not looked up" and "none filed" are different
        // answers and both are printed, because a blank cell is read as "fine".
        TableColumn<PortRow, String> vulnColumn =
                column("Vulnerabilities", 165, ResultsTable::describeVulns);
        styleCells(vulnColumn, ResultsTable::vulnStyle);

        table.getColumns().setAll(List.of(
                hostColumn,
                portColumn,
                column("State",     70,  r -> r.port().state().toString()),
                column("Service",   105, r -> r.port().service().name().isBlank()
                                              ? "unknown" : r.port().service().name()),
                column("Version",   190, r -> r.port().service().product().isBlank()
                                              ? "-" : r.port().service().describe()),
                detectionColumn,
                vulnColumn));
    }

    /**
     * What the Vulnerabilities cell says.
     *
     * <p>Every branch produces text. There is no path to an empty cell, because a
     * blank in a column headed "Vulnerabilities" is read as "none" by every user
     * who has ever seen a spreadsheet -- which is exactly the false negative the
     * four {@code MappingOutcome} values exist to prevent.
     */
    static String describeVulns(PortRow row) {
        VulnAssessment assessment = row.vulns();
        if (assessment == null) {
            return "not checked";
        }
        return switch (assessment.outcome()) {
            case MAPPED -> assessment.vulnerabilities().isEmpty()
                    ? "none filed"
                    : assessment.vulnerabilities().size() + "  ("
                      + assessment.worstSeverity() + ")";
            case UNRESOLVED        -> "not in the index";
            case NOT_APPLICABLE    -> "no version";
            case INDEX_UNAVAILABLE -> "no index";
        };
    }

    /**
     * Amber for every kind of not-knowing, and deliberately the same amber the
     * Detection column uses for a table guess. Both cells are telling the reader
     * the same thing: this is not evidence.
     */
    static String vulnStyle(PortRow row) {
        VulnAssessment assessment = row.vulns();
        if (assessment == null) {
            return Styles.INFERRED;
        }
        if (assessment.outcome() != MappingOutcome.MAPPED) {
            return Styles.INFERRED;
        }
        if (assessment.vulnerabilities().isEmpty()) {
            return Styles.VULN_CLEAN;
        }
        return assessment.worstSeverity().isAtLeastHigh() ? Styles.VULN_SEVERE : null;
    }

    static String describeDetection(Service service) {
        return switch (service.method()) {
            case PROBED -> "probed (" + service.confidence() + "/10)";
            case TABLE  -> "table ("  + service.confidence() + "/10)";
            case NONE   -> "-";
        };
    }

    /** Lambda, not PropertyValueFactory: records expose number(), not getNumber(). */
    private static TableColumn<PortRow, String> column(String title, double width,
                                                       Function<PortRow, String> value) {
        TableColumn<PortRow, String> col = new TableColumn<>(title);
        col.setPrefWidth(width);
        col.setCellValueFactory(cell ->
                new SimpleStringProperty(value.apply(cell.getValue())));
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
     *
     * <p><b>The list was incomplete.</b> v0.5.0 added {@code vuln-severe} and
     * {@code vuln-clean} to the Vulnerabilities column and did not add them here,
     * so those two classes accumulated on recycled cells exactly as this comment
     * warns. It was invisible for a reason worth writing down: both classes
     * resolved to {@code -cs-worse} and {@code -cs-better}, which were never
     * defined, so JavaFX dropped their only declaration and a stale class painted
     * nothing. Two defects cancelled. Defining the colours -- the obvious fix,
     * taken on its own -- would have made a scrolled table start reporting one
     * port's severity on another port's row.
     */
    private static void styleCells(TableColumn<PortRow, String> column,
                                   Function<PortRow, String> styleClass) {
        column.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(String value, boolean empty) {
                super.updateItem(value, empty);
                getStyleClass().removeAll(Styles.PORT_CELL, Styles.PROBED, Styles.INFERRED,
                                          Styles.VULN_SEVERE, Styles.VULN_CLEAN);
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
}
