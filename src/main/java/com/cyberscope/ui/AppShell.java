package com.cyberscope.ui;

import javafx.scene.Parent;
import javafx.scene.layout.BorderPane;

import java.util.EnumMap;
import java.util.Map;

/**
 * The window: sidebar on the left, one page in the middle.
 *
 * <p>Thin on purpose. Every rule about where you can go lives in
 * {@link Navigation}, which has no JavaFX and is tested; every rule about what a
 * page shows lives in the page. What is left here is the wiring, and there is
 * one decision in it worth stating.
 *
 * <h2>All six pages are built at startup, not on first visit</h2>
 *
 * Lazy construction is the reflex, and it is wrong here. Building a page on
 * first navigation means the first click on each sidebar item is the slow one,
 * and -- worse -- a constructor that throws does so in the middle of a click
 * handler, where there is no good place to report it. Six panels of controls
 * cost single-digit milliseconds to construct; a scan costs seconds. Paying that
 * up front means every navigation after startup is a {@code setCenter} call, and
 * any failure happens once, at launch, where it can be handled.
 *
 * <p>The pages are built eagerly; the <i>data</i> is not. {@link Page#onShown()}
 * is what runs on every visit, so a page holds an empty table until someone
 * looks at it.
 */
public final class AppShell {

    private final AppContext context;
    private final Navigation navigation;
    private final Map<PageId, Page> pages = new EnumMap<>(PageId.class);
    private final BorderPane root = new BorderPane();
    private final ScanPage scanPage;

    public AppShell(AppContext context) {
        this.context = context;
        this.navigation = new Navigation(context.blockedPages());

        this.scanPage = new ScanPage(context);
        register(scanPage);
        register(new AboutPage(context));
        register(new PlaceholderPage(PageId.VULNERABILITIES,
                "Every finding across all targets in one filterable list, with its "
                + "KEV and EPSS status. Lands in v0.6.0 Part 4."));
        register(new PlaceholderPage(PageId.SETTINGS,
                "Scan defaults, where the databases live, and manual control of the "
                + "CVE and exploit feeds. Lands in v0.6.0 Part 4."));

        // Built after the placeholders so they replace one if it can be shown.
        if (context.hasScans()) {
            register(new DashboardPage(context));
            register(new HistoryPage(context));
        } else {
            register(new PlaceholderPage(PageId.DASHBOARD, context.scansUnavailable()));
            register(new PlaceholderPage(PageId.HISTORY, context.scansUnavailable()));
        }

        Sidebar sidebar = new Sidebar(navigation);
        navigation.onChange(this::show);

        root.getStyleClass().add(Styles.APP_SHELL);
        root.setLeft(sidebar.root());
        show(navigation.current());

        // Attached to the root Parent rather than the Scene, so the shell is
        // styled wherever it is used -- including a snapshot harness.
        Styles.apply(root);
    }

    private void register(Page page) {
        pages.put(page.id(), page);
    }

    private void show(PageId id) {
        Page page = pages.get(id);
        if (page == null) {
            // Registered pages and PageId are meant to be the same set. If they
            // ever diverge, an empty window with no explanation is the worst
            // possible symptom, so say what happened instead.
            throw new IllegalStateException("no page registered for " + id);
        }
        root.setCenter(page.node());
        page.onShown();
    }

    public Parent root() {
        return root;
    }

    /** Runs on the FX thread at shutdown. */
    public void shutdown() {
        scanPage.shutdown();
        context.shutdown();
    }

    // Package-private accessors, for tests and harnesses.
    Navigation navigation()  { return navigation; }
    Page page(PageId id)     { return pages.get(id); }
}
