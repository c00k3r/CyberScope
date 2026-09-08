package com.cyberscope.ui;

import com.cyberscope.App;
import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.layout.VBox;

/**
 * What CyberScope is, what it is not, and the rule it is used under.
 *
 * <p>Written in full rather than stubbed, because one section of it is not
 * decoration. A scanner ships with an obligation attached, and the place a user
 * looks for it is here. The sidebar carries the short form on every page; this
 * is the long form.
 *
 * <p>The version is read from {@link App#VERSION}, which Maven filters from
 * {@code pom.xml}. There is one source of truth for the number and no way for
 * the title bar, the sidebar and this page to disagree -- which they did once,
 * when v0.3.1 shipped in a window labelled v0.3.0.
 */
final class AboutPage implements Page {

    private final Node node;

    AboutPage(AppContext context) {
        VBox body = new VBox(18);
        body.setPadding(new Insets(4, 24, 24, 20));
        body.setMaxWidth(780);

        body.getChildren().addAll(
                section("What it does",
                        "CyberScope runs Nmap against a target you control, and then does the "
                        + "part Nmap leaves to you: it separates what was measured from what "
                        + "was assumed.\n\n"
                        + "Nmap reports a service the same way whether it opened a connection "
                        + "and read a banner or simply looked the port number up in a table. "
                        + "Those are different claims. Every service says which it is, every "
                        + "CVE match says whether it was an exact version, a version range, or "
                        + "a vendor statement covering all versions, and the dashboard says "
                        + "how much of the host any of it is based on."),

                section("How findings are ranked",
                        "By whether anyone is exploiting them - not by CVSS.\n\n"
                        + "Measured against this project's own index: 47% of a typical host's "
                        + "findings are rated HIGH or CRITICAL, and about 1% appear in CISA's "
                        + "Known Exploited Vulnerabilities catalogue. A field where half the "
                        + "rows say \"critical\" cannot order a work queue. So CyberScope ranks "
                        + "on KEV membership, ransomware association and EPSS probability, and "
                        + "shows CVSS as a column rather than a verdict.\n\n"
                        + "There is deliberately no single security score. The same machine "
                        + "scored 91/100 and 100/100 in testing depending on which CPE Nmap "
                        + "reported for the same nginx - one string matches NVD and the other "
                        + "matches nothing. One number cannot separate \"nothing is wrong\" "
                        + "from \"nothing was checked\", so the dashboard shows an exposure "
                        + "band and a coverage figure side by side instead."),

                section("Authorised targets only",
                        "Port scanning a machine you do not own or have written permission to "
                        + "test is unlawful in most jurisdictions, including under the "
                        + "Information Technology Act, 2000 in India and the Computer Fraud "
                        + "and Abuse Act in the United States. It is not made lawful by "
                        + "curiosity, by the scan being read-only, or by nothing breaking.\n\n"
                        + "Use CyberScope against your own machines, a lab you built, a "
                        + "deliberately vulnerable target such as Metasploitable or the "
                        + "scanme.nmap.org host Nmap publishes for this purpose, or a system "
                        + "whose owner has authorised the test in writing and in scope.\n\n"
                        + "The confirmation checkbox on the scan page is a prompt, not a "
                        + "permission. It cannot verify anything, and there is no setting to "
                        + "turn it off. You are the control."),

                section("Where your data goes",
                        "Nowhere. Scan results are written to a local SQLite file in your home "
                        + "directory and nothing about your network is transmitted.\n\n"
                        + "The only outbound connections fetch public vulnerability data: the "
                        + "NVD JSON feeds, the CISA KEV catalogue, and the EPSS daily scores. "
                        + "Those downloads are identical for every user and carry no query "
                        + "about your hosts. All matching happens locally, against the "
                        + "downloaded copy."),

                section("What it is not",
                        "Not a vulnerability scanner. CyberScope sends no exploit traffic, "
                        + "authenticates to nothing, and never confirms that a listed CVE is "
                        + "present and reachable on your host. It matches a version string to "
                        + "a catalogue, which is inference, and it is labelled as inference "
                        + "throughout.\n\n"
                        + "A finding here is a question to investigate. A clean result is not "
                        + "a clean bill of health - the coverage figure exists precisely "
                        + "because \"we found nothing\" and \"we could not look\" are different "
                        + "sentences, and only one of them is reassuring."),

                section("This release",
                        "CyberScope " + App.VERSION + " adds exportable reports. A scan, or the "
                        + "whole dashboard, can be written to a self-contained HTML file that "
                        + "carries its own provenance: which index it was scored against, how "
                        + "old that index is, and how old the scan is. A report that does not "
                        + "say when its data was current cannot be acted on a month later, so "
                        + "every caveat travels with the document.\n\n"
                        + "A network report is not several scan reports stapled together. It "
                        + "reports the targets that were scanned and never \"your network\": a "
                        + "host nobody has scanned is absent from it, not counted as clear.\n\n"
                        + "The sidebar is reachable by keyboard - Tab into it, arrows to move, "
                        + "Enter to open - and the window reopens where you left it.\n\n"
                        + "Java 21, JavaFX 21, SQLite. Requires Nmap on your PATH.\n"
                        + "Vulnerability data: NVD (public domain), CISA KEV (public domain), "
                        + "EPSS by FIRST.org.\n\n"
                        + "Built by Mrityunjay Guleria.  github.com/c00k3r/CyberScope"));

        if (!context.hasScans()) {
            body.getChildren().add(section("Scan history is unavailable",
                    context.scansUnavailable()
                    + "\n\nScanning still works; results are shown but not saved."));
        }
        if (!context.indexUnavailable().isEmpty()) {
            body.getChildren().add(section("CVE index is unavailable",
                    context.indexUnavailable()
                    + "\n\nServices are reported as unchecked rather than clean."));
        }

        ScrollPane scroll = new ScrollPane(body);
        scroll.setFitToWidth(true);
        scroll.getStyleClass().add(Styles.PAGE_SCROLL);
        this.node = PageFrame.wrap(PageId.ABOUT, scroll);
    }

    private static VBox section(String heading, String text) {
        Label title = new Label(heading);
        title.getStyleClass().add(Styles.SECTION_TITLE);

        Label body = new Label(text);
        body.setWrapText(true);
        body.getStyleClass().add(Styles.PROSE);

        return new VBox(5, title, body);
    }

    @Override
    public PageId id() {
        return PageId.ABOUT;
    }

    @Override
    public Node node() {
        return node;
    }
}
