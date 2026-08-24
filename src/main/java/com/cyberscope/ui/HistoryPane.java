package com.cyberscope.ui;
 
import com.cyberscope.repository.RepositoryException;
import com.cyberscope.repository.ScanRepository;
import com.cyberscope.repository.ScanSummary;
import com.cyberscope.service.scanner.ScanOutcome;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.SelectionMode;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
 
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
 
/**
 * The scan history list.
 *
 * <p>Owns nothing but the view of history: it reads through a {@link ScanRepository}
 * and hands a loaded {@link ScanOutcome} back to whoever asked, through a callback.
 * It does not know what the results table looks like, and {@code ScanView} does not
 * know any SQL. That separation is the reason this pane could be dropped into a
 * different window without changes.
 *
 * <p>If the database could not be opened the pane still renders, showing why. A scan
 * is the product; history is a convenience. Losing the convenience must not cost the
 * product -- so the failure is reported, not thrown.
 */
public final class HistoryPane {
 
    private static final DateTimeFormatter WHEN =
            DateTimeFormatter.ofPattern("dd MMM  HH:mm");
    private static final int LIST_LIMIT = 50;
 
    private final ScanRepository repository;      // null when history is unavailable
    private final String unavailableReason;
 
    private final ListView<ScanSummary> list = new ListView<>();
    private final ObservableList<ScanSummary> items = FXCollections.observableArrayList();
    private final Button deleteButton = new Button("Delete");
    private final Label countLabel = new Label();
    private final VBox root = new VBox(8);
 
    private final Consumer<ScanOutcome> onSelected;
 
    /**
     * @param repository        may be null; the pane degrades to a message
     * @param unavailableReason shown when {@code repository} is null
     * @param onSelected        called on the FX thread when a past scan is chosen
     */
    public HistoryPane(ScanRepository repository, String unavailableReason,
                       Consumer<ScanOutcome> onSelected) {
        this.repository = repository;
        this.unavailableReason = unavailableReason;
        this.onSelected = onSelected;
        build();
        refresh();
    }
 
    public Region root() {
        return root;
    }
 
    private void build() {
        Label title = new Label("History");
        title.getStyleClass().add(Styles.SECTION_TITLE);
 
        countLabel.getStyleClass().add(Styles.MUTED);
 
        HBox header = new HBox(8, title, spacer(), countLabel);
        header.setAlignment(Pos.CENTER_LEFT);
 
        list.setItems(items);
        list.getSelectionModel().setSelectionMode(SelectionMode.SINGLE);
        list.setPlaceholder(new Label(repository == null
                ? "History unavailable.\n" + unavailableReason
                : "No scans saved yet."));
 
        // A custom cell, not toString(): the summary is a data object and should not
        // carry a presentation format. Cells are recycled as the list scrolls, so
        // updateItem must handle the empty case or a stale row is left behind.
        list.setCellFactory(view -> new ListCell<>() {
            @Override
            protected void updateItem(ScanSummary summary, boolean empty) {
                super.updateItem(summary, empty);
                if (empty || summary == null) {
                    setText(null);
                    return;
                }
                String detail = summary.scanType().displayName()
                        + " - " + summary.hostCount()
                        + (summary.hostCount() == 1 ? " host, " : " hosts, ")
                        + summary.openPortCount() + " open"
                        + String.format(" - %.1fs", summary.elapsed().toMillis() / 1000.0);
                setText(WHEN.format(summary.startedAt().atZone(ZoneId.systemDefault()))
                        + "  " + summary.target() + "\n   " + detail);
                // A long hostname still overflows a narrow pane; the tooltip is the
                // escape hatch rather than truncating with an ellipsis the user
                // cannot expand.
                setTooltip(new Tooltip(summary.target() + "\n" + detail));
            }
        });
 
        list.getSelectionModel().selectedItemProperty().addListener(
                (obs, old, now) -> openSelected(now));
 
        deleteButton.setDisable(true);
        deleteButton.getStyleClass().add(Styles.DESTRUCTIVE);
        deleteButton.setOnAction(event -> deleteSelected());
        list.getSelectionModel().selectedItemProperty().addListener(
                (obs, old, now) -> deleteButton.setDisable(now == null));
 
        VBox.setVgrow(list, Priority.ALWAYS);
        root.getStyleClass().add(Styles.HISTORY_PANE);
        root.getChildren().setAll(header, list, deleteButton);
        deleteButton.setMaxWidth(Double.MAX_VALUE);
        root.setPadding(new Insets(16, 12, 12, 16));
        root.setPrefWidth(300);
        root.setMinWidth(220);
    }
 
    private static Region spacer() {
        Region region = new Region();
        HBox.setHgrow(region, Priority.ALWAYS);
        return region;
    }
 
    /**
     * Re-reads the list from the database.
     *
     * <p>Runs on the FX thread deliberately. Measured against a saved /24 with 254
     * hosts and 2032 ports, {@code listRecent(50)} takes about 2 ms and a full
     * {@code load} about 18 ms -- roughly one dropped frame in the worst case that
     * the current feature set can produce. A background Task here would add two
     * classes and a race between refresh and delete to save one frame. If history
     * ever grows to thousands of scans, or the file moves onto a network share,
     * that trade flips and this becomes a Task.
     */
    public void refresh() {
        if (repository == null) {
            countLabel.setText("unavailable");
            return;
        }
        try {
            List<ScanSummary> recent = repository.listRecent(LIST_LIMIT);
            ScanSummary keep = list.getSelectionModel().getSelectedItem();
            items.setAll(recent);
            countLabel.setText(recent.size() + (recent.size() == 1 ? " scan" : " scans"));
            // Reselecting by id, not by object: the reloaded summaries are new
            // instances, so identity comparison would silently clear the selection.
            if (keep != null) {
                recent.stream().filter(s -> s.id() == keep.id()).findFirst()
                      .ifPresent(s -> list.getSelectionModel().select(s));
            }
        } catch (RepositoryException e) {
            countLabel.setText("error");
            report("Could not read history", e);
        }
    }
 
    /** Selects and shows a scan by id -- used right after one is saved. */
    public void selectById(long id) {
        items.stream().filter(s -> s.id() == id).findFirst()
             .ifPresent(s -> list.getSelectionModel().select(s));
    }
 
    private void openSelected(ScanSummary summary) {
        if (summary == null || repository == null) {
            return;
        }
        try {
            Optional<ScanOutcome> outcome = repository.load(summary.id());
            if (outcome.isEmpty()) {
                // Possible if the row was deleted between the list and the click.
                report("That scan is no longer in the database.", null);
                refresh();
                return;
            }
            onSelected.accept(outcome.get());
        } catch (RepositoryException e) {
            report("Could not load that scan", e);
        }
    }
 
    private void deleteSelected() {
        ScanSummary summary = list.getSelectionModel().getSelectedItem();
        if (summary == null || repository == null) {
            return;
        }
        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION,
                "Delete the scan of " + summary.target() + " from "
                + WHEN.format(summary.startedAt().atZone(ZoneId.systemDefault())) + "?");
        confirm.setHeaderText("Delete this scan?");
        confirm.setTitle("Delete scan");
        if (confirm.showAndWait().filter(b -> b.getButtonData().isDefaultButton()).isEmpty()) {
            return;
        }
        try {
            repository.delete(summary.id());
            list.getSelectionModel().clearSelection();
            refresh();
        } catch (RepositoryException e) {
            report("Could not delete that scan", e);
        }
    }
 
    private static void report(String headline, Exception cause) {
        Alert alert = new Alert(Alert.AlertType.WARNING);
        alert.setTitle("History");
        alert.setHeaderText(headline);
        alert.setContentText(cause == null ? "" : cause.getMessage());
        alert.showAndWait();
    }
 
    // Package-private, for the headless harness.
    ListView<ScanSummary> list() { return list; }
    Button delete()              { return deleteButton; }
    Label count()                { return countLabel; }
}
 

