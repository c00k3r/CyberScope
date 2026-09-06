package com.cyberscope.ui;

/**
 * The pages in the sidebar, in the order they appear.
 *
 * <p>Deliberately an enum rather than free strings. The sidebar, the navigation
 * model and the page registry all have to agree on what a page is called, and
 * three string literals that must stay in sync is the same failure mode the
 * {@code -cs-worse} bug came from -- a name that is wrong compiles fine and does
 * nothing.
 *
 * <p>No JavaFX here, and none in {@link Navigation}. That is not tidiness: the
 * JavaFX toolkit cannot start without a display, Monocle is not in the Maven
 * artifact (verified: {@code javafx-graphics-21.0.7-linux.jar} contains no
 * Monocle classes, and forcing {@code -Dglass.platform=Monocle} fails with
 * "Failed to load Glass factory class"), and the alternatives are an
 * unmaintained test dependency or an Xvfb that a reviewer's machine may not
 * have. So the part of the shell that has rules is written without JavaFX and
 * tested normally, and the part that draws is kept thin enough to read.
 */
public enum PageId {

    DASHBOARD("Dashboard",
              "Where this network stands, worst first"),

    SCAN("Network scan",
         "Run a scan against a target you are authorised to test"),

    HISTORY("Scan history",
            "Past scans, and what changed between them"),

    VULNERABILITIES("Vulnerabilities",
                    "Every finding from the latest scan of each target"),

    SETTINGS("Settings",
             "Scan defaults, data locations and the CVE index"),

    ABOUT("About",
          "What CyberScope does, and the rules it is used under");

    private final String title;
    private final String subtitle;

    PageId(String title, String subtitle) {
        this.title = title;
        this.subtitle = subtitle;
    }

    /** The sidebar label and the page header. One string, so they cannot drift. */
    public String title() {
        return title;
    }

    /** The line under the page header. Says what the page is for, not what it is. */
    public String subtitle() {
        return subtitle;
    }
}
