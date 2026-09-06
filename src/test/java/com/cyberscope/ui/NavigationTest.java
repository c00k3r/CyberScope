package com.cyberscope.ui;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The shell's navigation rules.
 *
 * <p>These run without a display because {@link Navigation} has no JavaFX in it.
 * That was the point of splitting it out: the JavaFX toolkit will not start
 * headless here, Monocle is not in the Maven artifact, and the two ways around
 * that are an unmaintained test dependency or an X server the reviewer may not
 * have. Moving the rules out of the widget means the rules get tested and the
 * widget is small enough to read.
 */
class NavigationTest {

    @Test
    @DisplayName("starts on the first page when everything is reachable")
    void startsOnFirstPage() {
        assertEquals(PageId.DASHBOARD, new Navigation().current());
    }

    @Test
    @DisplayName("falls forward past blocked pages to pick a reachable start")
    void startsOnFirstReachablePage() {
        Navigation nav = new Navigation(Map.of(
                PageId.DASHBOARD, "no scan history yet",
                PageId.SCAN, "nmap not found"));
        assertEquals(PageId.HISTORY, nav.current(),
                "starting on a blocked page shows a frame the user cannot explain");
    }

    @Test
    @DisplayName("refuses to construct when every page is blocked")
    void everyPageBlockedIsAConfigurationError() {
        Map<PageId, String> all = new java.util.EnumMap<>(PageId.class);
        for (PageId page : PageId.values()) {
            all.put(page, "nope");
        }
        assertThrows(IllegalArgumentException.class, () -> new Navigation(all));
    }

    @Test
    @DisplayName("navigating to a reachable page changes the current page and notifies")
    void navigatesAndNotifies() {
        Navigation nav = new Navigation();
        List<PageId> seen = new ArrayList<>();
        nav.onChange(seen::add);

        assertTrue(nav.goTo(PageId.SCAN));
        assertAll(
                () -> assertEquals(PageId.SCAN, nav.current()),
                () -> assertEquals(List.of(PageId.SCAN), seen));
    }

    @Test
    @DisplayName("navigating to the page already showing is a no-op and does not notify")
    void reNavigatingIsANoOp() {
        Navigation nav = new Navigation();
        List<PageId> seen = new ArrayList<>();
        nav.onChange(seen::add);

        assertFalse(nav.goTo(PageId.DASHBOARD));
        assertAll(
                () -> assertEquals(PageId.DASHBOARD, nav.current()),
                () -> assertTrue(seen.isEmpty(),
                        "a page reloads itself when shown; re-showing it would "
                        + "re-run its queries and drop the user's selection"));
    }

    @Test
    @DisplayName("a blocked page cannot be navigated to and does not notify")
    void blockedPageIsRefused() {
        Navigation nav = new Navigation(Map.of(PageId.HISTORY, "database is read-only"));
        List<PageId> seen = new ArrayList<>();
        nav.onChange(seen::add);

        assertAll(
                () -> assertFalse(nav.goTo(PageId.HISTORY)),
                () -> assertEquals(PageId.DASHBOARD, nav.current()),
                () -> assertTrue(seen.isEmpty()));
    }

    @Test
    @DisplayName("a blocked page carries the reason, for the sidebar tooltip")
    void blockedPageCarriesItsReason() {
        Navigation nav = new Navigation(Map.of(PageId.HISTORY, "database is read-only"));
        assertAll(
                () -> assertTrue(nav.isBlocked(PageId.HISTORY)),
                () -> assertEquals("database is read-only",
                        nav.blockedReason(PageId.HISTORY).orElseThrow()),
                () -> assertFalse(nav.isBlocked(PageId.SCAN)),
                () -> assertTrue(nav.blockedReason(PageId.SCAN).isEmpty()));
    }

    @Test
    @DisplayName("the sidebar order is the declaration order, and every page appears once")
    void pagesAreDeclarationOrder() {
        Navigation nav = new Navigation();
        assertAll(
                () -> assertEquals(List.of(PageId.values()), nav.pages()),
                () -> assertEquals(PageId.values().length,
                        nav.pages().stream().distinct().count()));
    }

    @Test
    @DisplayName("every page has a title and a subtitle that says what it is for")
    void everyPageIsLabelled() {
        for (PageId page : PageId.values()) {
            assertFalse(page.title().isBlank(), page + " has no title");
            assertFalse(page.subtitle().isBlank(), page + " has no subtitle");
            assertFalse(page.subtitle().equalsIgnoreCase(page.title()),
                    page + "'s subtitle just repeats its title");
        }
    }

    @Test
    @DisplayName("listeners are all called, in order")
    void everyListenerIsCalled() {
        Navigation nav = new Navigation();
        List<String> order = new ArrayList<>();
        nav.onChange(p -> order.add("first:" + p));
        nav.onChange(p -> order.add("second:" + p));

        nav.goTo(PageId.ABOUT);
        assertEquals(List.of("first:ABOUT", "second:ABOUT"), order);
    }
}
