package com.cyberscope.ui;

import com.cyberscope.App;
import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.layout.VBox;

/**
 * What CyberScope is, what it does not do, and the rule it is used under.
 *
 * <p>Written in full in v0.6.0 rather than stubbed, because one section of it is
 * not decoration. A scanner ships with an obligation attached, and the place a
 * user looks for it is here. The sidebar carries the short form on every page;
 * this is the long form.
 */
final class AboutPage implements Page {

    private final Node node;

    AboutPage(AppContext context) {
        VBox body = new VBox(18);
        body.setPadding(new Insets(4, 24, 24, 20));
        body.setMaxWidth(760);

        body.getChildren().addAll(
                section("What it does",
                        "CyberScope runs Nmap against a target you control, and then does the "
                        + "part Nmap leaves to you: it separates what was measured from what "
                        + "was assumed.\n\n"
                        + "Nmap reports a service the same way whether it opened a connection "
                        + "and read a banner or simply looked the port number up in a table. "
                        + "Those are different claims. Every service in the results table says "
                        + "which one it is, and every version match against the CVE index says "
                        + "whether the match was exact, a version range, or a vendor statement "
                        + "that covers all versions."),

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
                        + "permission. It cannot verify anything. You are the control."),

                section("Where your data goes",
                        "Nowhere. Scan results are written to a local SQLite file in your home "
                        + "directory and nothing about your network is transmitted.\n\n"
                        + "The one outbound connection CyberScope makes is to fetch public "
                        + "vulnerability data -- the NVD JSON feeds, the CISA Known Exploited "
                        + "Vulnerabilities catalogue, and the EPSS daily scores. Those "
                        + "downloads are the same for every user and carry no query about your "
                        + "hosts; matching happens locally, against the downloaded copy."),

                section("What it is not",
                        "Not a vulnerability scanner. CyberScope does not send exploit traffic, "
                        + "authenticate to anything, or confirm that a listed CVE is present "
                        + "and reachable on your host. It matches a version string to a "
                        + "catalogue, which is inference, and it is labelled as inference "
                        + "throughout.\n\n"
                        + "A finding here is a question to investigate, not a confirmed "
                        + "vulnerability. A clean result is not a clean bill of health -- the "
                        + "coverage figure on the dashboard exists precisely because "
                        + "\"we found nothing\" and \"we could not look\" are different "
                        + "sentences."),

                section("Version",
                        "CyberScope " + App.VERSION + "\n"
                        + "Java 21, JavaFX 21, SQLite. Requires Nmap on your PATH.\n"
                        + "Vulnerability data: NVD (public domain), CISA KEV (public domain), "
                        + "EPSS by FIRST.org.\n\n"
                        + "Built by Mrityunjay Guleria. Source: github.com/c00k3r/CyberScope"));

        if (!context.hasScans()) {
            body.getChildren().add(section("Scan history is unavailable",
                    context.scansUnavailable()
                    + "\n\nScanning still works; results are shown but not saved."));
        }
        if (!context.indexUnavailable().isEmpty()) {
            body.getChildren().add(section("CVE index is unavailable",
                    context.indexUnavailable()
                    + "\n\nServices will be reported as unchecked rather than clean."));
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
