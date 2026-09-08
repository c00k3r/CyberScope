package com.cyberscope.ui;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * Which page is showing, and which pages can be reached at all.
 *
 * <p>Pure: no JavaFX, no I/O, no clock. {@link Sidebar} renders it and
 * {@link AppShell} listens to it; neither adds any rule of its own.
 *
 * <h2>Blocked pages</h2>
 *
 * Three of the six pages read the scan database, and the database is allowed to
 * be missing -- a read-only home directory or a full disk must not stop someone
 * running a scan. Before v0.6.0 that was handled per-component, by passing a
 * nullable repository down and having each place remember to check it. That
 * works until one place forgets, and then a click produces a stack trace.
 *
 * <p>Here the reason a page cannot be opened is stated once, up front, and the
 * model refuses to navigate there. The sidebar reads the same map to grey the
 * item out and put the reason in its tooltip, so the user is told <i>why</i> the
 * page is unavailable instead of clicking a dead button.
 *
 * <h2>Two rules worth stating</h2>
 *
 * <ol>
 *   <li><b>The initial page must be reachable.</b> Starting on a blocked page
 *       would show an empty frame the user cannot navigate away from and cannot
 *       explain, so the constructor falls forward to the first page that is
 *       open. With no database that is Network scan -- which is the right answer
 *       anyway, because scanning is the part that still works.</li>
 *   <li><b>Navigating to the current page does nothing.</b> Not a cosmetic
 *       detail: a page refreshes itself when it is shown, and several of those
 *       refreshes query the database. Without this rule, clicking the sidebar
 *       item you are already on re-runs the query and rebuilds the view, which
 *       loses the row the user had selected.</li>
 * </ol>
 */
public final class Navigation {

    private final Map<PageId, String> blocked;
    private final List<Consumer<PageId>> listeners = new ArrayList<>();
    private PageId current;

    /** Everything reachable, starting at the first page. */
    public Navigation() {
        this(Map.of());
    }

    /**
     * @param blocked pages that cannot be opened, mapped to the reason why; the
     *                reason is shown to the user, so it has to be a sentence a
     *                person can act on, not an exception class name
     */
    public Navigation(Map<PageId, String> blocked) {
        this.blocked = new EnumMap<>(PageId.class);
        this.blocked.putAll(Objects.requireNonNull(blocked, "blocked"));
        this.current = firstReachable();
    }

    private PageId firstReachable() {
        for (PageId page : PageId.values()) {
            if (!blocked.containsKey(page)) {
                return page;
            }
        }
        // Every page blocked. Not reachable in practice -- Network scan, Settings
        // and About need nothing -- but returning null here would turn a
        // configuration mistake into a NullPointerException three frames away.
        throw new IllegalArgumentException(
                "every page is blocked; there is nothing to show");
    }

    public PageId current() {
        return current;
    }

    /** The pages, in sidebar order. */
    public List<PageId> pages() {
        return List.of(PageId.values());
    }

    public boolean isBlocked(PageId page) {
        return blocked.containsKey(page);
    }

    /** Why {@code page} cannot be opened, or empty if it can. */
    public Optional<String> blockedReason(PageId page) {
        return Optional.ofNullable(blocked.get(page));
    }

    /**
     * Moves to {@code page}.
     *
     * @return true if the current page changed; false if the page is blocked or
     *         was already showing. Listeners fire only when it returns true.
     */
    public boolean goTo(PageId page) {
        Objects.requireNonNull(page, "page");
        if (blocked.containsKey(page) || page == current) {
            return false;
        }
        current = page;
        for (Consumer<PageId> listener : listeners) {
            listener.accept(page);
        }
        return true;
    }

    /**
     * The next page a keyboard user should land on.
     *
     * <p>Arrow-key movement in a sidebar is not "index + 1". Two rules make it
     * different, and both are here rather than in {@link Sidebar} so they can be
     * tested without a display:
     *
     * <ul>
     *   <li><b>Blocked pages are skipped, not landed on.</b> Focusing a row that
     *       cannot be opened is a dead end -- the user presses Enter, nothing
     *       happens, and there is no feedback explaining why. Moving past it is
     *       the only behaviour that does not waste a keystroke.</li>
     *   <li><b>It wraps.</b> Six items is short enough that running off the end
     *       and stopping feels like the control broke. Wrapping is what a menu
     *       does.</li>
     * </ul>
     *
     * @param from      where focus is now
     * @param direction {@code +1} for down, {@code -1} for up
     * @return the page to move focus to; {@code from} when nothing else is
     *         reachable, so a caller can always move focus somewhere
     */
    public PageId neighbour(PageId from, int direction) {
        List<PageId> pages = pages();
        int size = pages.size();
        int start = pages.indexOf(Objects.requireNonNull(from, "from"));
        if (start < 0 || direction == 0) {
            return from;
        }
        int step = direction > 0 ? 1 : -1;
        // Bounded by size: with every other page blocked this returns `from`
        // rather than looping forever.
        for (int i = 1; i < size; i++) {
            PageId candidate = pages.get(Math.floorMod(start + step * i, size));
            if (!blocked.containsKey(candidate)) {
                return candidate;
            }
        }
        return from;
    }

    /** Called after the current page changes, never on a refused navigation. */
    public void onChange(Consumer<PageId> listener) {
        listeners.add(Objects.requireNonNull(listener, "listener"));
    }
}
