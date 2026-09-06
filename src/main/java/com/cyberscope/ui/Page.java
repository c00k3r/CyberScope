package com.cyberscope.ui;

import javafx.scene.Node;

/**
 * One destination in the sidebar.
 *
 * <h2>Why {@code onShown} and not an event bus</h2>
 *
 * Pages need to react to things that happen elsewhere: finishing a scan should
 * update the dashboard, the history list and the vulnerability page. The
 * textbook answer is an observer registry -- pages subscribe, the scan publishes,
 * everything refreshes.
 *
 * <p>That is the wrong trade here. It means every page keeps re-querying the
 * database in the background whether or not anyone is looking at it, and it adds
 * a subscription lifecycle that is easy to leak. A desktop application with six
 * pages and one window has a simpler property available: <b>only one page is
 * visible at a time</b>. So a page pulls what it needs at the moment it becomes
 * visible, and nothing pushes.
 *
 * <p>The cost is honest: a page open while a scan finishes does not live-update.
 * The scan page is the only page that can be open when that happens, and it
 * renders its own result directly, so in practice nothing is lost. If a later
 * version adds a second window, this is the assumption that breaks.
 *
 * <p>{@code onShown} runs on the FX thread, so an implementation must not do
 * slow work in it. Reading a page of scan summaries from a local SQLite file is
 * sub-millisecond; anything heavier belongs on {@code AppContext.worker()}.
 */
interface Page {

    PageId id();

    /** Built once, in the constructor. Called on every navigation, so it must be cheap. */
    Node node();

    /** Called after this page becomes the visible one. Refresh here, not in a listener. */
    default void onShown() {
    }
}
