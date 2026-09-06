package com.cyberscope.ui;

import com.cyberscope.model.ScanType;
import com.cyberscope.repository.CveIndexManager;
import com.cyberscope.repository.DatabaseManager;
import com.cyberscope.repository.ExploitFeedLoader;
import com.cyberscope.repository.FeedMetadata;
import com.cyberscope.repository.IndexMetadata;
import com.cyberscope.repository.Preferences;
import com.cyberscope.repository.RepositoryException;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.util.StringConverter;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;

/**
 * Scan defaults, where the data lives, and manual control of the feeds.
 *
 * <h2>Two feeds, two buttons, on purpose</h2>
 *
 * The CVE index and the exploitation feeds are refreshed separately because they
 * go stale at completely different rates. The corpus grows by roughly 584 CVEs a
 * day; EPSS recomputes <i>every one</i> of its 366,252 scores daily, and a KEV
 * addition can turn a finding you have ignored for a month into the most urgent
 * thing on your network without a byte of NVD changing. One button that always
 * costs a minute would mean people stop pressing it.
 *
 * <h2>What this page does not do</h2>
 *
 * It does not offer a "scan without confirming authorisation" option, and it
 * will not. The checkbox on the scan page cannot verify anything -- it is a
 * prompt, and a prompt you can permanently switch off is decoration. Anything
 * that makes it easier to scan a machine by accident is a feature this project
 * does not want.
 */
final class SettingsPage implements Page {

    private final AppContext context;
    private final Preferences preferences;

    private final ComboBox<ScanType> defaultScanType = new ComboBox<>();
    private final Label saveNote = new Label();

    private final Label indexStatus = new Label();
    private final Label feedStatus = new Label();
    private final Button updateIndex = new Button("Rebuild CVE index");
    private final Button updateFeeds = new Button("Refresh exploit data");
    private final ProgressBar progress = new ProgressBar();
    private final Label taskStatus = new Label();
    private final VBox locations = new VBox(4);
    private final Node node;

    SettingsPage(AppContext context, Preferences preferences) {
        this.context = context;
        this.preferences = preferences;

        VBox body = new VBox(20);
        body.setPadding(new Insets(6, 24, 24, 20));
        body.setMaxWidth(820);
        body.getChildren().addAll(scanDefaults(), dataSection(), feedSection(), scopeSection());

        ScrollPane scroll = new ScrollPane(body);
        scroll.setFitToWidth(true);
        scroll.getStyleClass().add(Styles.PAGE_SCROLL);
        this.node = PageFrame.wrap(PageId.SETTINGS, scroll);
    }

    @Override
    public PageId id() {
        return PageId.SETTINGS;
    }

    @Override
    public Node node() {
        return node;
    }

    /** Re-reads sizes and feed ages, which change while the page is closed. */
    @Override
    public void onShown() {
        refreshStatus();
    }

    // ------------------------------------------------------------- scan defaults

    private VBox scanDefaults() {
        defaultScanType.getItems().setAll(ScanType.values());
        defaultScanType.getSelectionModel().select(preferences.defaultScanType());
        defaultScanType.setPrefWidth(180);
        defaultScanType.setConverter(new StringConverter<>() {
            @Override public String toString(ScanType type) {
                return type == null ? "" : type.displayName();
            }
            @Override public ScanType fromString(String text) {
                return defaultScanType.getValue();
            }
        });
        defaultScanType.valueProperty().addListener((obs, old, now) -> {
            if (now == null) {
                return;
            }
            defaultScanType.setTooltip(new Tooltip(now.description()));
            try {
                preferences.setDefaultScanType(now);
                saveNote.setText("Saved. New windows will open with " + now.displayName() + ".");
                saveNote.getStyleClass().remove(Styles.INDEX_STALE);
            } catch (RepositoryException e) {
                // A click that silently did nothing is worse than an error.
                saveNote.setText("Could not save: " + e.getMessage());
                if (!saveNote.getStyleClass().contains(Styles.INDEX_STALE)) {
                    saveNote.getStyleClass().add(Styles.INDEX_STALE);
                }
            }
        });
        saveNote.getStyleClass().add(Styles.CARD_NOTE);

        HBox row = new HBox(10, label("Default scan type:", 150), defaultScanType);
        row.setAlignment(Pos.CENTER_LEFT);

        return section("Scan defaults",
                "Applies to new windows. The scan page still lets you change it per scan.",
                row, saveNote);
    }

    // --------------------------------------------------------------- data files

    private VBox dataSection() {
        return section("Where your data lives",
                "All of it is on this machine. Nothing about your network is uploaded.",
                locations);
    }

    private void refreshLocations() {
        locations.getChildren().setAll(
                fileRow("Scan history", DatabaseManager.defaultLocation()),
                fileRow("CVE index", CveIndexManager.defaultLocation()),
                fileRow("Settings", preferences.file()));
    }

    private HBox fileRow(String name, Path path) {
        Label value = new Label(path + "   " + describeSize(path));
        value.getStyleClass().add(Styles.CARD_NOTE);
        HBox row = new HBox(10, label(name, 110), value);
        row.setAlignment(Pos.CENTER_LEFT);
        return row;
    }

    /** Size on disk, or why it is not there. Never blank. */
    private static String describeSize(Path path) {
        try {
            if (!Files.exists(path)) {
                return "(not created yet)";
            }
            long bytes = Files.size(path);
            return bytes >= 1_048_576 ? String.format("(%.1f MB)", bytes / 1_048_576.0)
                 : bytes >= 1024      ? String.format("(%.0f KB)", bytes / 1024.0)
                 : "(" + bytes + " bytes)";
        } catch (Exception e) {
            return "(unreadable: " + e.getMessage() + ")";
        }
    }

    // -------------------------------------------------------------------- feeds

    private VBox feedSection() {
        indexStatus.setWrapText(true);
        feedStatus.setWrapText(true);
        indexStatus.getStyleClass().add(Styles.CARD_NOTE);
        feedStatus.getStyleClass().add(Styles.CARD_NOTE);
        taskStatus.getStyleClass().add(Styles.CARD_NOTE);

        progress.setVisible(false);
        progress.setManaged(false);
        progress.setPrefWidth(150);

        updateIndex.setTooltip(new Tooltip(
                "Downloads about 100 MB of public NVD data and rebuilds the local index.\n"
                + "Roughly a minute. Nothing about your network leaves this machine."));
        updateIndex.setOnAction(event -> runIndexRebuild());

        updateFeeds.setTooltip(new Tooltip(
                "Downloads the CISA KEV catalogue (1.7 MB) and today's EPSS scores"
                + " (2.5 MB).\nA few seconds. Do this daily; the full index rebuild"
                + " is only needed weekly."));
        updateFeeds.getStyleClass().add(Styles.PRIMARY);
        updateFeeds.setOnAction(event -> runFeedRefresh());

        HBox buttons = new HBox(10, updateFeeds, updateIndex, progress, taskStatus);
        buttons.setAlignment(Pos.CENTER_LEFT);

        return section("Vulnerability data",
                "Two feeds, refreshed separately. The corpus grows by about 584 CVEs a"
                + " day; EPSS recomputes all 366,252 of its scores daily, and a KEV"
                + " addition can change your dashboard without a byte of NVD moving.",
                indexStatus, feedStatus, buttons);
    }

    private void refreshStatus() {
        refreshLocations();
        boolean available = context.cveIndex() != null;
        updateIndex.setDisable(context.indexManager() == null);
        updateFeeds.setDisable(context.indexManager() == null || !available);

        if (!available) {
            setStale(indexStatus, "CVE index unavailable - " + context.indexUnavailable());
            feedStatus.setText("");
            return;
        }
        Instant now = Instant.now();
        try {
            IndexMetadata metadata = context.cveIndex().metadata().orElse(null);
            if (metadata == null) {
                setStale(indexStatus, "No CVE index yet. Services are reported as"
                                    + " unchecked until you build one.");
            } else {
                indexStatus.setText("Corpus: " + metadata.describe(now, ZoneId.systemDefault()));
                indexStatus.getStyleClass().remove(Styles.INDEX_STALE);
                if (metadata.isStale(now)) {
                    indexStatus.getStyleClass().add(Styles.INDEX_STALE);
                }
            }
            feedStatus.setText(describeFeeds(now));
        } catch (RepositoryException e) {
            setStale(indexStatus, "CVE index could not be read: " + e.getMessage());
        }
    }

    private String describeFeeds(Instant now) throws RepositoryException {
        FeedMetadata kev = context.cveIndex().feedMetadata("kev").orElse(null);
        FeedMetadata epss = context.cveIndex().feedMetadata("epss").orElse(null);
        if (kev == null && epss == null) {
            return "Exploitation data: never loaded. Every finding will read"
                 + " \"not known to be exploited\", which is an absence of data,"
                 + " not evidence of safety.";
        }
        // No "KEV: " prefix here -- FeedMetadata.describe() already opens with the
        // source name, and adding one produced "KEV: KEV: 1,692 records".
        return (kev == null ? "KEV: never loaded" : kev.describe(now, ZoneId.systemDefault()))
             + "\n"
             + (epss == null ? "EPSS: never loaded" : epss.describe(now, ZoneId.systemDefault()));
    }

    private static void setStale(Label label, String text) {
        label.setText(text);
        if (!label.getStyleClass().contains(Styles.INDEX_STALE)) {
            label.getStyleClass().add(Styles.INDEX_STALE);
        }
    }

    private void runIndexRebuild() {
        CveIndexTask task = new CveIndexTask(context.indexManager());
        startTask(task, task.messageProperty(), task.progressProperty(),
                () -> taskStatus.setText("CVE index rebuilt."));
        task.setOnFailed(event -> {
            endTask();
            setStale(taskStatus, "Rebuild failed: " + message(task.getException()));
        });
        context.worker().submit(task);
    }

    private void runFeedRefresh() {
        ExploitFeedTask task = new ExploitFeedTask(context.indexManager());
        startTask(task, task.messageProperty(), task.progressProperty(), () -> {
            ExploitFeedLoader.Result result = task.getValue();
            taskStatus.setText(String.format(
                    "%,d KEV entries (%,d ransomware), %,d EPSS scores, in %.1f s",
                    result.kevCount(), result.kevRansomware(), result.epssCount(),
                    result.elapsed().toMillis() / 1000.0));
        });
        task.setOnFailed(event -> {
            endTask();
            setStale(taskStatus, "Refresh failed: " + message(task.getException()));
        });
        context.worker().submit(task);
    }

    private void startTask(javafx.concurrent.Task<?> task,
                           javafx.beans.value.ObservableValue<String> message,
                           javafx.beans.property.ReadOnlyDoubleProperty progressValue,
                           Runnable onDone) {
        updateIndex.setDisable(true);
        updateFeeds.setDisable(true);
        progress.setVisible(true);
        progress.setManaged(true);
        progress.progressProperty().bind(progressValue);
        taskStatus.textProperty().bind(message);
        taskStatus.getStyleClass().remove(Styles.INDEX_STALE);

        task.setOnSucceeded(event -> {
            endTask();
            onDone.run();
            refreshStatus();
        });
        task.setOnCancelled(event -> endTask());
    }

    private void endTask() {
        // Unbind before setting: a bound property throws if you assign to it, and
        // every completion path below wants to write a result into this label.
        progress.progressProperty().unbind();
        taskStatus.textProperty().unbind();
        progress.setVisible(false);
        progress.setManaged(false);
        updateIndex.setDisable(context.indexManager() == null);
        updateFeeds.setDisable(context.indexManager() == null);
    }

    private static String message(Throwable error) {
        return error == null ? "unknown error"
                : (error.getMessage() == null ? error.toString() : error.getMessage());
    }

    // ------------------------------------------------------------------- scope

    private VBox scopeSection() {
        Label body = new Label(
                "The confirmation checkbox on the scan page is a prompt, not a permission."
                + " It cannot verify anything, and there is deliberately no setting here"
                + " to switch it off.\n\n"
                + "Scan your own machines, a lab you built, a deliberately vulnerable"
                + " target, or a system whose owner has authorised the test in writing"
                + " and in scope. See About for the longer version.");
        body.setWrapText(true);
        body.getStyleClass().add(Styles.PROSE);
        return section("Authorised targets only", "", body);
    }

    // -------------------------------------------------------------- components

    private static Label label(String text, double width) {
        Label label = new Label(text);
        label.setMinWidth(width);
        return label;
    }

    private VBox section(String heading, String note, Node... content) {
        Label title = new Label(heading);
        title.getStyleClass().add(Styles.SECTION_TITLE);

        VBox box = new VBox(8, title);
        if (!note.isBlank()) {
            Label subtitle = new Label(note);
            subtitle.setWrapText(true);
            subtitle.getStyleClass().add(Styles.CARD_NOTE);
            box.getChildren().add(subtitle);
        }
        box.getChildren().addAll(List.of(content));
        box.getStyleClass().add(Styles.CARD);
        Region filler = new Region();
        HBox.setHgrow(filler, Priority.ALWAYS);
        return box;
    }
}
