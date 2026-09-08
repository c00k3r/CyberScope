package com.cyberscope.ui;

import com.cyberscope.model.Coverage;
import com.cyberscope.model.ExposureBand;
import com.cyberscope.model.NetworkPosture;
import com.cyberscope.model.PostureTrend;
import com.cyberscope.model.Severity;
import com.cyberscope.model.TargetPosture;
import javafx.beans.property.SimpleStringProperty;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Group;
import javafx.scene.Node;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.Arc;
import javafx.scene.shape.ArcType;
import javafx.scene.shape.Circle;
import javafx.scene.shape.StrokeLineCap;

import java.time.Instant;
import java.util.List;
import java.util.function.Function;

/**
 * Where this network stands, worst first.
 *
 * <h2>What this page refuses to show</h2>
 *
 * The reference design for this screen had a single number -- "Security score
 * 78, Good" -- in the largest type on the page. It is not here, and the reason
 * is the whole argument of v0.6.0.
 *
 * <p>Measured in Part 1 against the real 384,513-CVE index: the same physical
 * machine scored <b>91/100</b> when nmap reported its web server as
 * {@code f5:nginx} and <b>100/100</b> when it reported {@code igor_sysoev:nginx},
 * because the second CPE matches nothing in NVD and produced zero findings. A
 * single number cannot distinguish "nothing is wrong" from "nothing was
 * checked", and it will always round the difference in the reassuring direction.
 *
 * <p>So the score is split into two figures that cannot be confused:
 *
 * <ul>
 *   <li><b>Exposure</b> -- the worst thing found anywhere, as a band.</li>
 *   <li><b>Coverage</b> -- how much of the network that opinion is based on.</li>
 * </ul>
 *
 * A CLEAR band at 40% coverage is not a good result, and printing the two side
 * by side is what makes that legible. Averaging them into one number is exactly
 * the operation that destroys the information.
 *
 * <h2>And the date</h2>
 *
 * Every figure here is as old as the scan it came from, while the CVE data is as
 * new as the last index update. Those two ages are different, so both are on
 * screen: each target row carries its scan age, and a scan older than a week is
 * marked.
 */
final class DashboardPage implements Page {

    private static final int TOP_ACTIONS = 5;
    private static final double RING_RADIUS = 30;
    private static final double RING_STROKE = 6;
    /**
     * Width of the bar track.
     *
     * <p>Sized against {@code SEVERITY_CARD_WIDTH}, not chosen freely. The row is
     * label + track + count inside the card's padding, and the first attempt made
     * the track wide enough that the count had no room and JavaFX quietly
     * ellipsised it to "...". A chart whose numbers are replaced by dots is worse
     * than no chart, and nothing warns you -- Label truncation is normal
     * behaviour, not an error.
     */
    private static final double BAR_TRACK = 168;

    private static final double BAR_LABEL_WIDTH = 84;
    private static final double BAR_COUNT_WIDTH = 34;
    private static final double SEVERITY_CARD_WIDTH = 368;

    private final AppContext context;

    private final HBox statCards = new HBox(12);
    private final VBox severityBars = new VBox(7);
    private final VBox actionList = new VBox(9);
    private final TableView<TargetPosture> targetTable = new TableView<>();
    private final Label statusLabel = new Label();
    private final ProgressBar progress = new ProgressBar();
    private final VBox body = new VBox(14);
    private final ScrollPane scroll;
    private final Node node;

    private final javafx.scene.control.Button exportButton =
            new javafx.scene.control.Button("Export report");
    private final ReportExporter exporter;
    private NetworkPosture current = NetworkPosture.empty();
    private PostureTask running;

    DashboardPage(AppContext context) {
        this.context = context;
        this.exporter = new ReportExporter(context);

        statCards.setFillHeight(true);

        buildTargetTable();

        // The severity chart is a fixed-width block of five short rows; the
        // action list is the part that benefits from every pixel it can get,
        // because its lines are long and wrapping them costs a row each.
        VBox severityCard = card("FINDINGS BY CVSS SEVERITY", severityBars);
        severityCard.setMinWidth(SEVERITY_CARD_WIDTH);
        severityCard.setPrefWidth(SEVERITY_CARD_WIDTH);
        severityCard.setMaxWidth(SEVERITY_CARD_WIDTH);

        VBox actionCard = card("DO THESE FIRST", actionList);
        HBox.setHgrow(actionCard, Priority.ALWAYS);
        actionCard.setMinWidth(360);
        HBox middle = new HBox(12, severityCard, actionCard);

        VBox targetCard = card("TARGETS", targetTable);
        VBox.setVgrow(targetTable, Priority.ALWAYS);
        targetTable.setPrefHeight(230);

        progress.setVisible(false);
        progress.setManaged(false);
        progress.setPrefWidth(150);
        statusLabel.getStyleClass().add(Styles.MUTED);
        exportButton.setDisable(true);
        exportButton.setTooltip(new Tooltip(
                "Save every target's latest scan as one HTML report."));
        exportButton.setOnAction(event -> exporter.exportNetwork(ReportExporter.windowOf(exportButton), current));

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        HBox statusRow = new HBox(10, progress, statusLabel, spacer, exportButton);
        statusRow.setAlignment(Pos.CENTER_LEFT);
        // No longer collapses when idle: it carries the export button, which has
        // to stay reachable whether or not a refresh is running.

        body.setPadding(new Insets(14, 20, 20, 20));
        body.getChildren().setAll(statusRow, statCards, middle, targetCard);

        this.scroll = new ScrollPane(body);
        scroll.setFitToWidth(true);
        scroll.getStyleClass().add(Styles.PAGE_SCROLL);
        this.node = PageFrame.wrap(PageId.DASHBOARD, scroll);

        render(NetworkPosture.empty(), Instant.now(), false);
    }

    @Override
    public PageId id() {
        return PageId.DASHBOARD;
    }

    @Override
    public Node node() {
        return node;
    }

    /**
     * Re-scores everything whenever the page is opened.
     *
     * <p>Deliberately not cached. The whole point of re-checking stored scans
     * against the live index is that the answer can change without a new scan --
     * a CVE added to KEV this morning should be visible this afternoon. A cache
     * would hide precisely the event this page exists to surface.
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
            running = null;
        };

        task.setOnSucceeded(event -> {
            finish.run();
            render(task.getValue(), Instant.now(), context.cveIndex() != null);
        });
        task.setOnFailed(event -> {
            finish.run();
            Throwable error = task.getException();
            statusLabel.setText("Could not build the dashboard: "
                    + (error == null ? "unknown error" : error.getMessage()));
            statusLabel.getStyleClass().add(Styles.INDEX_STALE);
        });
        task.setOnCancelled(event -> finish.run());

        context.worker().submit(task);
    }

    // ------------------------------------------------------------- rendering

    private void render(NetworkPosture posture, Instant now, boolean indexAvailable) {
        current = posture;
        // Nothing scanned means nothing to put in a report, and an empty document
        // that says "no scans yet" is not worth a file on someone's disk.
        exportButton.setDisable(posture.isEmpty());
        // A TableView inside a ScrollPane pulls the viewport to itself when it
        // takes focus, which lands the user halfway down a page they have not
        // read yet. onShown always re-renders, so pinning to the top here is
        // the whole fix.
        scroll.setVvalue(0);
        renderStatCards(posture, indexAvailable);
        renderSeverityBars(posture);
        renderActions(posture, indexAvailable);
        targetTable.getItems().setAll(posture.targets());
        targetTable.setPlaceholder(new Label(placeholderFor(posture, indexAvailable)));
    }

    private String placeholderFor(NetworkPosture posture, boolean indexAvailable) {
        if (!context.hasScans()) {
            return "Scan history is unavailable, so there is nothing to summarise.";
        }
        if (posture.isEmpty()) {
            return "No scans yet. Run one from Network scan and it will appear here.";
        }
        return indexAvailable ? "No targets." : "No CVE index, so nothing can be scored.";
    }

    private void renderStatCards(NetworkPosture posture, boolean indexAvailable) {
        Coverage coverage = posture.coverage();

        VBox exposure = statCard("EXPOSURE", bandChip(posture.band()),
                posture.isEmpty() ? "no scans yet"
                                  : posture.band().meaning());

        // Order matters. Telling someone their CVE index is missing when they
        // have not scanned anything sends them to fix the wrong thing.
        VBox cover = statCard("COVERAGE", coverageRing(coverage),
                posture.isEmpty() ? "no scans yet - nothing to cover"
                        : indexAvailable ? coverage.describe()
                        : "no CVE index - nothing could be checked");

        VBox targets = statCard("TARGETS", bigNumber(String.valueOf(posture.targets().size())),
                posture.targetsNeedingAction() + " need attention");

        VBox findings = statCard("FINDINGS", bigNumber(String.valueOf(posture.findingCount())),
                posture.count(Severity.CRITICAL) + " critical  ·  "
                + posture.openPorts() + " open services");

        for (VBox card : List.of(exposure, cover, targets, findings)) {
            HBox.setHgrow(card, Priority.ALWAYS);
            card.setMinWidth(150);
        }
        statCards.getChildren().setAll(exposure, cover, targets, findings);
    }

    /**
     * The severity histogram, with a fifth bar that is not a severity.
     *
     * <p>"Not checked" sits at the bottom in grey. It is the count of open
     * services no lookup could be performed for, and it belongs on this chart
     * for the same reason the Vulnerabilities column never renders an empty
     * cell: a four-bar chart quietly implies the four bars account for
     * everything, and they do not.
     */
    private void renderSeverityBars(NetworkPosture posture) {
        int unchecked = posture.unchecked();
        int max = Math.max(1, Math.max(unchecked, List.of(Severity.values()).stream()
                .mapToInt(posture::count).max().orElse(0)));

        // The chart and the Exposure band disagree on purpose, and a reader
        // who notices that deserves an answer rather than a puzzle. 21 CVSS
        // criticals with an Exposure of HIGH is not a contradiction: CVSS rates
        // how bad a flaw would be if exploited, and 47% of a typical host's
        // findings are HIGH or above, so it cannot order a work queue. The band
        // and the action list rank on whether anyone is actually exploiting it.
        Label footnote = new Label(
                "CVSS rates how bad each flaw would be. It is not the order to work in"
                + " -- see Do these first.");
        footnote.setWrapText(true);
        footnote.getStyleClass().add(Styles.CARD_NOTE);
        VBox.setMargin(footnote, new Insets(6, 0, 0, 0));

        severityBars.getChildren().setAll(
                bar("Critical", posture.count(Severity.CRITICAL), max, Styles.FILL_CRITICAL),
                bar("High",     posture.count(Severity.HIGH),     max, Styles.FILL_HIGH),
                bar("Medium",   posture.count(Severity.MEDIUM),   max, Styles.FILL_ELEVATED),
                bar("Low",      posture.count(Severity.LOW),      max, Styles.FILL_LOW),
                bar("Not checked", unchecked, max, Styles.FILL_UNCHECKED),
                footnote);
    }

    private void renderActions(NetworkPosture posture, boolean indexAvailable) {
        actionList.getChildren().clear();
        List<NetworkPosture.Action> actions = posture.topActions(TOP_ACTIONS);

        if (actions.isEmpty()) {
            Label empty = new Label(!indexAvailable
                    ? "No CVE index. Build one from the scan page and findings will appear here."
                    : posture.isEmpty()
                        ? "Nothing to do yet - no scans have been taken."
                        : "Nothing matched the index. That is not the same as nothing being"
                          + " wrong: check the coverage figure above.");
            empty.setWrapText(true);
            empty.getStyleClass().add(Styles.EMPTY_STATE);
            actionList.getChildren().add(empty);
            return;
        }

        int rank = 1;
        for (NetworkPosture.Action action : actions) {
            Label number = new Label(String.valueOf(rank++));
            number.getStyleClass().add(Styles.ACTION_RANK);
            number.setMinWidth(14);

            Label what = new Label(action.target() + " · " + action.finding().where()
                    + " · " + action.finding().product());
            what.getStyleClass().add(Styles.ACTION_TEXT);

            Label why = new Label(action.finding().vulnerability().cveId() + "  ·  "
                    + action.finding().urgency().label().toLowerCase(java.util.Locale.ROOT)
                    + "  ·  " + reasonFor(action));
            why.getStyleClass().add(Styles.ACTION_WHY);

            VBox text = new VBox(1, what, why);
            HBox row = new HBox(9, number, text);
            row.setAlignment(Pos.TOP_LEFT);
            Tooltip.install(row, new Tooltip(action.describe()));
            actionList.getChildren().add(row);
        }
    }

    /** Why this finding outranks the others, in the words of the evidence. */
    private static String reasonFor(NetworkPosture.Action action) {
        var signal = action.finding().vulnerability().signal();
        if (signal.isRansomware()) {
            return "used in ransomware";
        }
        if (signal.isKnownExploited()) {
            return "in CISA KEV";
        }
        if (signal.hasEpss()) {
            return String.format("EPSS %.2f", signal.epssScore());
        }
        return "no exploitation data";
    }

    // ------------------------------------------------------------ components

    private VBox card(String title, Node content) {
        Label heading = new Label(title);
        heading.getStyleClass().add(Styles.CARD_TITLE);
        VBox box = new VBox(10, heading, content);
        box.getStyleClass().add(Styles.CARD);
        return box;
    }

    private VBox statCard(String title, Node value, String note) {
        Label heading = new Label(title);
        heading.getStyleClass().add(Styles.CARD_TITLE);

        Label footer = new Label(note);
        footer.setWrapText(true);
        footer.getStyleClass().add(Styles.CARD_NOTE);

        HBox valueRow = new HBox(value);
        valueRow.setAlignment(Pos.CENTER_LEFT);
        valueRow.setMinHeight(46);

        VBox box = new VBox(4, heading, valueRow, footer);
        box.getStyleClass().add(Styles.CARD);
        return box;
    }

    private static Label bigNumber(String text) {
        Label label = new Label(text);
        label.getStyleClass().add(Styles.CARD_VALUE);
        return label;
    }

    /** A band, as a tinted chip carrying its own name. Colour is never alone. */
    static Label bandChip(ExposureBand band) {
        Label chip = new Label(band.label().toUpperCase(java.util.Locale.ROOT));
        chip.getStyleClass().addAll(Styles.BAND_CHIP, styleFor(band));
        Tooltip.install(chip, new Tooltip(band.meaning()));
        return chip;
    }

    static String styleFor(ExposureBand band) {
        return switch (band) {
            case CRITICAL      -> Styles.BAND_CRITICAL;
            case HIGH          -> Styles.BAND_HIGH;
            case ELEVATED      -> Styles.BAND_ELEVATED;
            case LOW           -> Styles.BAND_LOW;
            case CLEAR         -> Styles.BAND_CLEAR;
            case INDETERMINATE -> Styles.BAND_INDETERMINATE;
        };
    }

    /**
     * Coverage as a ring.
     *
     * <p>Two stroked arcs, not a filled pie: a pie of a single value is a circle
     * with a bite out of it and readers consistently misjudge the angle. A ring
     * with the number in the middle is read from the number; the arc is
     * reinforcement.
     *
     * <p>The arc turns amber below the adequacy threshold, which is the same
     * amber as an inferred service -- both mean "this is not solid evidence".
     */
    /**
     * The ring, and the one case where it must not show a number.
     *
     * <p>{@code Coverage.fraction()} returns 1.0 when no services were examined,
     * and as a model answer that is right: nothing was missed because there was
     * nothing to miss. Rendered as a full ring reading <b>100%</b> next to "no
     * scans yet", it stops being that answer and becomes a reassurance about a
     * host that does not exist -- which is the exact failure this whole release
     * argues against. A fresh install opened on a green 100%.
     *
     * <p>The model is not wrong and is not changed. The renderer is where a
     * number turns into a claim, so the guard belongs here: nothing examined
     * means no arc and an em dash, and the caption underneath says why.
     */
    private Node coverageRing(Coverage coverage) {
        double radius = RING_RADIUS - 4;
        boolean known = coverage.isMeasured();
        double fraction = known ? coverage.fraction() : 0;

        Circle track = new Circle(radius);
        track.setFill(Color.TRANSPARENT);
        track.setStrokeWidth(RING_STROKE);
        track.getStyleClass().add(Styles.RING_TRACK);

        // Starts at 12 o'clock and sweeps clockwise, which is how people read a
        // dial. JavaFX angles are counter-clockwise-positive with 0 at 3 o'clock,
        // so clockwise is a NEGATIVE length.
        Arc fill = new Arc(0, 0, radius, radius, 90, -360 * fraction);
        fill.setType(ArcType.OPEN);
        fill.setFill(Color.TRANSPARENT);
        fill.setStrokeWidth(RING_STROKE);
        fill.setStrokeLineCap(StrokeLineCap.ROUND);
        fill.getStyleClass().add(coverage.isAdequate() ? Styles.RING_FILL : Styles.RING_FILL_POOR);

        Label value = new Label(known ? coverage.percent() + "%" : "—");
        value.getStyleClass().add(Styles.RING_VALUE);

        // THIS GROUP IS THE FIX, and it is worth understanding rather than copying.
        //
        // A StackPane centres each child by that child's own layout bounds. A full
        // Circle is symmetric about its centre, so it centres correctly. An Arc is
        // NOT: a 26% arc from 12 o'clock occupies only the top-right quadrant, so
        // its bounds are roughly (0,-r)-(r,+0.1r), and StackPane dutifully centred
        // that quadrant-shaped box in the middle of the pane -- pushing the arc
        // down and left, straight across the number. The smaller the percentage,
        // the further off it sat, which is why 57% looked slightly wrong and 26%
        // looked broken.
        //
        // Wrapping both shapes in one Group makes the arc's position relative to
        // the circle, not to the pane. The Group's bounds are the union, which the
        // full circle already makes symmetric, so the Group centres correctly and
        // the arc rides along at its true angle.
        // The arc is omitted entirely when nothing was examined. A zero-length
        // Arc still renders its round line cap -- a dot at 12 o'clock that reads
        // as "a very small amount of coverage" rather than "none measured".
        Group ring = known ? new Group(track, fill) : new Group(track);

        StackPane box = new StackPane(ring, value);
        box.setMinSize(RING_RADIUS * 2, RING_RADIUS * 2);
        box.setPrefSize(RING_RADIUS * 2, RING_RADIUS * 2);
        box.setMaxSize(RING_RADIUS * 2, RING_RADIUS * 2);
        return box;
    }

    private HBox bar(String name, int count, int max, String fillStyle) {
        Label label = new Label(name);
        label.getStyleClass().add(Styles.BAR_LABEL);
        label.setMinWidth(BAR_LABEL_WIDTH);

        Region fill = new Region();
        fill.getStyleClass().addAll(Styles.BAR_FILL, fillStyle);
        // max is at least 1, so this never divides by zero. A zero count still
        // draws a 2px stub rather than nothing: an empty row reads as a missing
        // row, and "zero critical findings" is a result worth seeing.
        fill.setPrefWidth(count == 0 ? 2 : Math.max(4, BAR_TRACK * count / (double) max));
        fill.setMinWidth(Region.USE_PREF_SIZE);
        fill.setMaxWidth(Region.USE_PREF_SIZE);
        fill.setPrefHeight(10);

        StackPane track = new StackPane(fill);
        StackPane.setAlignment(fill, Pos.CENTER_LEFT);
        track.getStyleClass().add(Styles.BAR_TRACK);
        track.setMinSize(BAR_TRACK, 10);
        track.setPrefSize(BAR_TRACK, 10);
        track.setMaxSize(BAR_TRACK, 10);

        Label number = new Label(String.valueOf(count));
        number.getStyleClass().add(Styles.BAR_COUNT);
        // Fixed width so the column of counts aligns, and wide enough for four
        // digits -- a /24 sweep of a busy subnet reaches four figures easily.
        number.setMinWidth(BAR_COUNT_WIDTH);

        HBox row = new HBox(10, label, track, number);
        row.setAlignment(Pos.CENTER_LEFT);
        return row;
    }

    // ---------------------------------------------------------- target table

    private void buildTargetTable() {
        targetTable.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);

        TableColumn<TargetPosture, String> target = text("Target", 190, TargetPosture::target);
        TableColumn<TargetPosture, String> when =
                text("Last scan", 120, t -> t.describeAge(Instant.now()));
        // Stale scans amber, for the same reason an inferred service is amber.
        when.setCellFactory(column -> new TableCell<>() {
            @Override protected void updateItem(String value, boolean empty) {
                super.updateItem(value, empty);
                getStyleClass().remove(Styles.STALE);
                setText(empty ? null : value);
                if (!empty && getIndex() < getTableView().getItems().size()
                        && getTableView().getItems().get(getIndex()).isStale(Instant.now())) {
                    getStyleClass().add(Styles.STALE);
                }
            }
        });

        TableColumn<TargetPosture, String> coverage =
                text("Coverage", 110, t -> t.coverage().percent() + "%  ("
                        + t.coverage().checked() + "/" + t.coverage().examined() + ")");
        TableColumn<TargetPosture, String> findings =
                text("Findings", 90, t -> String.valueOf(t.assessment().findingCount()));

        TableColumn<TargetPosture, TargetPosture> exposure = new TableColumn<>("Exposure");
        exposure.setPrefWidth(150);
        exposure.setCellValueFactory(cell ->
                new javafx.beans.property.SimpleObjectProperty<>(cell.getValue()));
        exposure.setCellFactory(column -> new TableCell<>() {
            @Override protected void updateItem(TargetPosture value, boolean empty) {
                super.updateItem(value, empty);
                setText(null);
                setGraphic(empty || value == null ? null : bandChip(value.band()));
            }
        });

        TableColumn<TargetPosture, String> trend = text("Trend", 70,
                t -> t.trend().mark());
        trend.setCellFactory(column -> new TableCell<>() {
            @Override protected void updateItem(String value, boolean empty) {
                super.updateItem(value, empty);
                getStyleClass().removeAll(Styles.TREND_WORSE, Styles.TREND_BETTER,
                                          Styles.TREND_FLAT);
                setText(empty ? null : value);
                if (empty || getIndex() >= getTableView().getItems().size()) {
                    setTooltip(null);
                    return;
                }
                PostureTrend movement = getTableView().getItems().get(getIndex()).trend();
                getStyleClass().add(movement.isWorse() ? Styles.TREND_WORSE
                        : movement.isBetter() ? Styles.TREND_BETTER : Styles.TREND_FLAT);
                // The arrow is one character. The sentence is what it means.
                setTooltip(new Tooltip(movement.meaning()));
            }
        });

        targetTable.getColumns().setAll(List.of(target, when, coverage, findings,
                                                exposure, trend));
    }

    private static TableColumn<TargetPosture, String> text(
            String title, double width, Function<TargetPosture, String> value) {
        TableColumn<TargetPosture, String> column = new TableColumn<>(title);
        column.setPrefWidth(width);
        column.setCellValueFactory(cell ->
                new SimpleStringProperty(value.apply(cell.getValue())));
        return column;
    }

    // Package-private accessors, for tests and harnesses.
    TableView<TargetPosture> table() { return targetTable; }
    VBox actions()                   { return actionList; }
    HBox cards()                     { return statCards; }
}
