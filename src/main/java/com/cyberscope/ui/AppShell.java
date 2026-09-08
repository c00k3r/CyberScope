package com.cyberscope.ui;

import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.layout.BorderPane;

import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;

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
        register(new SettingsPage(context, context.preferences()));

        // The three pages that read stored scans. Navigation already refuses to
        // open them without a database; UnavailablePage is what sits behind that
        // refusal, carrying the reason and saying that scanning still works.
        if (context.hasScans()) {
            register(new DashboardPage(context));
            register(new HistoryPage(context));
            register(new VulnerabilitiesPage(context));
        } else {
            register(new UnavailablePage(PageId.DASHBOARD, context.scansUnavailable()));
            register(new UnavailablePage(PageId.HISTORY, context.scansUnavailable()));
            register(new UnavailablePage(PageId.VULNERABILITIES, context.scansUnavailable()));
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

    /**
     * Puts the caret where the user is going to start typing.
     *
     * <h2>A regression that making the sidebar focusable created</h2>
     *
     * A {@code Scene} gives initial focus to the <b>first focus-traversable node
     * in scene-graph order</b>. The sidebar is the {@code BorderPane}'s left
     * child, so it comes before the page -- which did not matter while the nav
     * rows were unfocusable, and does the moment they are not. CyberScope opened
     * with focus on a nav row, so someone who launched it and started typing a
     * target got nothing.
     *
     * <p>No unit test could have caught this. Focus assignment needs a running
     * toolkit, and every rule that <i>is</i> testable was correct: one tab stop,
     * arrows skipping blocked rows, Enter activating. It was found by rendering
     * the window and looking at which row had the ring.
     *
     * <p>Called once, at startup, rather than on every navigation. Stealing
     * focus on each page change would undo the point of the arrow keys: open a
     * page with Enter, focus jumps into the content, and the next Down arrow
     * scrolls a table instead of moving along the rail.
     */
    public void focusContent() {
        firstTraversable(root.getCenter()).ifPresent(Node::requestFocus);
    }

    /** Depth-first, which is the order the user would Tab through anyway. */
    private static Optional<Node> firstTraversable(Node node) {
        if (node == null || node.isDisabled() || !node.isVisible()) {
            return Optional.empty();
        }
        if (node.isFocusTraversable()) {
            return Optional.of(node);
        }
        if (node instanceof Parent parent) {
            for (Node child : parent.getChildrenUnmodifiable()) {
                Optional<Node> found = firstTraversable(child);
                if (found.isPresent()) {
                    return found;
                }
            }
        }
        return Optional.empty();
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
