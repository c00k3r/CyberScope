package com.cyberscope.ui;

import com.cyberscope.model.ExploitSignal;
import com.cyberscope.model.ExposureBand;
import com.cyberscope.model.FindingFilter;
import com.cyberscope.model.MatchPrecision;
import com.cyberscope.model.NetworkPosture;
import javafx.beans.property.SimpleObjectProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TableCell;
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
import java.util.Locale;
import java.util.function.Function;

/**
 * Every finding on every target, in one ranked list.
 *
 * <p>The Dashboard answers "where do I stand and what do I do first". This page
 * answers "show me everything", which is a different question and needs a
 * different control: the Dashboard's list is capped at five and cannot be
 * filtered, this one is complete and can.
 *
 * <h2>A filter in a security tool is a loaded gun</h2>
 *
 * Hiding rows is the whole point of a filter and it is also how a scanner
 * produces a false negative with no bug in it: someone narrows the list, moves
 * on, and later reads "3 findings" as "there are 3 findings". So this page never
 * shows a bare count. It shows <b>showing 12 of 211</b>, and when a filter is
 * active it names the filter in the same sentence. The rule lives in
 * {@link FindingFilter#describe}, which is unit-tested, rather than in a label
 * somebody might forget to update.
 *
 * <p>The default sort is the same {@code ACTION_ORDER} the Dashboard uses -- by
 * exploitation, not by CVSS. The columns are sortable, so a reader who wants
 * CVSS order can have it; they just do not get it by accident.
 */
final class VulnerabilitiesPage implements Page {

    private final AppContext context;

    private final TextField search = new TextField();
    private final CheckBox exploitedOnly = new CheckBox("Exploited only (CISA KEV)");
    private final ComboBox<ExposureBand> minUrgency = new ComboBox<>();
    private final Label countLabel = new Label();
    private final Label statusLabel = new Label();
    private final ProgressBar progress = new ProgressBar();
    private final TableView<NetworkPosture.Action> table = new TableView<>();
    private final Node node;

    private NetworkPosture posture = NetworkPosture.empty();
    private FindingFilter filter = FindingFilter.none();
    private PostureTask running;

    VulnerabilitiesPage(AppContext context) {
        this.context = context;
        buildControls();
        buildTable();

        HBox filters = new HBox(10, search, exploitedOnly, minUrgency);
        filters.setAlignment(Pos.CENTER_LEFT);

        progress.setVisible(false);
        progress.setManaged(false);
        progress.setPrefWidth(140);
        statusLabel.getStyleClass().add(Styles.MUTED);
        countLabel.getStyleClass().add(Styles.MUTED);
        HBox status = new HBox(10, countLabel, progress, statusLabel);
        status.setAlignment(Pos.CENTER_LEFT);

        VBox top = new VBox(8, filters, status);
        top.setPadding(new Insets(12, 20, 10, 20));

        BorderPane body = new BorderPane();
        body.getStyleClass().add(Styles.SCAN_PANE);
        body.setTop(top);
        body.setCenter(table);
        BorderPane.setMargin(table, new Insets(0, 20, 16, 20));

        this.node = PageFrame.wrap(PageId.VULNERABILITIES, body);
        refreshTable();
    }

    @Override
    public PageId id() {
        return PageId.VULNERABILITIES;
    }

    @Override
    public Node node() {
        return node;
    }

    /**
     * Re-scores on every visit, exactly as the Dashboard does.
     *
     * <p>The filter is deliberately <b>not</b> reset. Someone who narrowed to
     * "openssh", left to run a scan and came back is still working on openssh,
     * and clearing their filter without telling them is worse than keeping it --
     * the count line says what is hidden either way.
     */
    @Override
    public void onShown() {
        if (!context.hasScans() || running != null) {
            return;
        }
        PostureTask task = new PostureTask(context);
        running = task;

        progress.setVisible(true);
        progress.setManaged(true);
        progress.progressProperty().bind(task.progressProperty());
        statusLabel.textProperty().bind(task.messageProperty());

        Runnable finish = () -> {
            progress.progressProperty().unbind();
            statusLabel.textProperty().unbind();
            progress.setVisible(false);
            progress.setManaged(false);
            statusLabel.setText("");
            running = null;
        };

        task.setOnSucceeded(event -> {
            finish.run();
            posture = task.getValue();
            refreshTable();
        });
        task.setOnFailed(event -> {
            finish.run();
            Throwable error = task.getException();
            statusLabel.setText("Could not load findings: "
                    + (error == null ? "unknown error" : error.getMessage()));
            statusLabel.getStyleClass().add(Styles.INDEX_STALE);
        });
        task.setOnCancelled(event -> finish.run());

        context.worker().submit(task);
    }

    // ---------------------------------------------------------------- filters

    private void buildControls() {
        search.setPromptText("Filter by target, service, port or CVE id");
        search.setPrefWidth(300);
        search.textProperty().addListener((obs, old, now) -> {
            filter = filter.withText(now);
            refreshTable();
        });

        exploitedOnly.setTooltip(new Tooltip(
                "Only findings CISA lists as actively exploited in the wild.\n"
                + "Measured against the real index: about 1% of a typical host's "
                + "findings qualify."));
        exploitedOnly.selectedProperty().addListener((obs, old, now) -> {
            filter = filter.withExploitedOnly(now);
            refreshTable();
        });

        // CLEAR is the "no minimum" option: nothing ranks below it, so selecting
        // it excludes nothing. Naming it "Any urgency" rather than "Clear" keeps
        // the control readable without inventing a seventh band.
        minUrgency.getItems().setAll(ExposureBand.CLEAR, ExposureBand.LOW,
                ExposureBand.ELEVATED, ExposureBand.HIGH, ExposureBand.CRITICAL);
        minUrgency.getSelectionModel().select(ExposureBand.CLEAR);
        minUrgency.setConverter(new StringConverter<>() {
            @Override public String toString(ExposureBand band) {
                return band == null || band == ExposureBand.CLEAR
                        ? "Any urgency" : band.label() + " and above";
            }
            @Override public ExposureBand fromString(String text) {
                return minUrgency.getValue();
            }
        });
        minUrgency.valueProperty().addListener((obs, old, now) -> {
            filter = filter.withMinUrgency(now);
            refreshTable();
        });
    }

    private void refreshTable() {
        List<NetworkPosture.Action> all = posture.actions();
        List<NetworkPosture.Action> shown = filter.apply(all);
        table.getItems().setAll(shown);
        countLabel.setText(filter.describe(shown.size(), all.size()));

        table.setPlaceholder(new Label(placeholderFor(all, shown)));
    }

    private String placeholderFor(List<NetworkPosture.Action> all,
                                  List<NetworkPosture.Action> shown) {
        if (!context.hasScans()) {
            return "Scan history is unavailable, so there is nothing to list.";
        }
        if (context.cveIndex() == null) {
            return "No CVE index. Build one from the scan page and findings appear here.";
        }
        if (all.isEmpty()) {
            return posture.isEmpty()
                    ? "No scans yet. Run one from Network scan."
                    : "Nothing matched the index. That is not the same as nothing being"
                      + " wrong - check the coverage figure on the Dashboard.";
        }
        return shown.isEmpty() ? "No finding matches this filter." : "";
    }

    // ------------------------------------------------------------------ table

    private void buildTable() {
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);

        TableColumn<NetworkPosture.Action, NetworkPosture.Action> urgency =
                new TableColumn<>("Urgency");
        urgency.setPrefWidth(96);
        urgency.setMinWidth(96);
        urgency.setCellValueFactory(cell -> new SimpleObjectProperty<>(cell.getValue()));
        urgency.setCellFactory(column -> new TableCell<>() {
            @Override protected void updateItem(NetworkPosture.Action value, boolean empty) {
                super.updateItem(value, empty);
                setText(null);
                setGraphic(empty || value == null
                        ? null : DashboardPage.bandChip(value.finding().urgency()));
            }
        });
        // Sorting a graphic column needs an explicit comparator, or JavaFX sorts
        // by the cell VALUE's natural order -- which for a record is none, and
        // clicking the header throws.
        urgency.setComparator((a, b) ->
                Integer.compare(a.finding().urgency().rank(), b.finding().urgency().rank()));

        TableColumn<NetworkPosture.Action, String> exploited =
                text("KEV", 78, action -> {
                    ExploitSignal signal = action.finding().vulnerability().signal();
                    if (signal.isRansomware()) {
                        return "ransomware";
                    }
                    return signal.isKnownExploited() ? "in KEV" : "-";
                });
        exploited.setMinWidth(78);
        exploited.setCellFactory(column -> new TableCell<>() {
            @Override protected void updateItem(String value, boolean empty) {
                super.updateItem(value, empty);
                getStyleClass().removeAll(Styles.VULN_SEVERE, Styles.MUTED);
                setText(empty ? null : value);
                if (!empty && value != null && !value.equals("-")) {
                    getStyleClass().add(Styles.VULN_SEVERE);
                }
            }
        });

        // EPSS is printed to two places and "-" when absent. 4.7% of the index has
        // no score at all, and rendering that as 0.00 would be a claim of safety
        // the data does not make.
        TableColumn<NetworkPosture.Action, String> epss = fixed("EPSS", 58, action -> {
            ExploitSignal signal = action.finding().vulnerability().signal();
            return signal.hasEpss() ? String.format("%.2f", signal.epssScore()) : "-";
        });

        // Widths add up to just under the space available at the default window
        // size. They were not guessed: the first attempt truncated the CVE column
        // to "CVE-2023-444..." and the port column to "443/t...", and a table
        // whose identifiers are elided is a table you cannot act on.
        table.getColumns().setAll(List.of(
                text("Target", 130, NetworkPosture.Action::target),
                fixed("Port", 72, action -> action.finding().where()),
                text("Service", 150, action -> action.finding().product()),
                fixed("CVE", 126, action -> action.finding().vulnerability().cveId()),
                fixed("CVSS", 74, action -> action.finding().vulnerability().severity()
                        .toString().toLowerCase(Locale.ROOT)),
                urgency, exploited, epss,
                text("Matched", 96, action -> shortPrecision(
                        action.finding().vulnerability().precision()))));

        table.setRowFactory(view -> {
            var row = new javafx.scene.control.TableRow<NetworkPosture.Action>();
            row.itemProperty().addListener((obs, old, action) ->
                    row.setTooltip(action == null ? null : longTooltip(action)));
            return row;
        });
    }

    /**
     * The match precision in one or two words.
     *
     * <p>{@code MatchPrecision.description()} is a sentence fragment written for
     * a tooltip -- "version in affected range" -- and it does not fit a column.
     * Shortened here rather than in the model, because the model's phrasing is
     * right everywhere else it is used and a column width is a UI concern.
     */
    private static String shortPrecision(MatchPrecision precision) {
        return switch (precision) {
            case VERSION_EXACT -> "exact";
            case VERSION_RANGE -> "range";
            case ALL_VERSIONS  -> "all versions";
        };
    }

    /** The full description, which is the part that does not fit in a column. */
    private static Tooltip longTooltip(NetworkPosture.Action action) {
        String description = action.finding().vulnerability().description();
        Tooltip tip = new Tooltip(action.describe()
                + (description.isBlank() ? "" : "\n\n" + description));
        tip.setWrapText(true);
        tip.setMaxWidth(520);
        return tip;
    }

    private static TableColumn<NetworkPosture.Action, String> text(
            String title, double width, Function<NetworkPosture.Action, String> value) {
        TableColumn<NetworkPosture.Action, String> column = new TableColumn<>(title);
        column.setPrefWidth(width);
        column.setCellValueFactory(cell ->
                new SimpleStringProperty(value.apply(cell.getValue())));
        return column;
    }

    /**
     * A column that must not be squeezed below the width of its own content.
     *
     * <p>{@code CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN} makes the columns
     * always sum to the table's width, so a preferred width is a <i>hint</i> --
     * every column shrinks proportionally when the total does not fit. Nine
     * columns of hints produced "CVE-2023-44...", "medi..." and "ELEVA...", which
     * for identifiers is not a display detail: a truncated CVE id cannot be
     * searched, quoted or looked up.
     *
     * <p>A minimum width is the floor the policy cannot go below. Only the
     * columns whose values are identifiers get one; Target and Service are free
     * to truncate because they repeat down the page and carry a row tooltip.
     */
    private static TableColumn<NetworkPosture.Action, String> fixed(
            String title, double width, Function<NetworkPosture.Action, String> value) {
        TableColumn<NetworkPosture.Action, String> column = text(title, width, value);
        column.setMinWidth(width);
        return column;
    }

    // Package-private accessors, for tests and harnesses.
    TableView<NetworkPosture.Action> table() { return table; }
    Label count()                            { return countLabel; }
}
