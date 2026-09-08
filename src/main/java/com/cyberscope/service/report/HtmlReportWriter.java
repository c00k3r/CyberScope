package com.cyberscope.service.report;

import com.cyberscope.model.Coverage;
import com.cyberscope.model.ExploitSignal;
import com.cyberscope.model.ExposureBand;
import com.cyberscope.model.Host;
import com.cyberscope.model.NetworkPosture;
import com.cyberscope.model.NetworkReport;
import com.cyberscope.model.Port;
import com.cyberscope.model.RankedFinding;
import com.cyberscope.model.ReportProvenance;
import com.cyberscope.model.ScanReport;
import com.cyberscope.model.Service;
import com.cyberscope.model.TargetPosture;
import com.cyberscope.model.Severity;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;

/**
 * Renders a {@link ScanReport} as one self-contained HTML file.
 *
 * <h2>Why HTML and not PDF</h2>
 *
 * A PDF library is 5-7 MB and has no HTML renderer, so every table, wrap and
 * page break would be laid out by hand. This file opens anywhere, attaches to an
 * email, prints to PDF in two clicks, and -- the property that turned out to
 * matter most -- <b>is diffable</b>. Two reports of the same target a month
 * apart can be compared with {@code diff}.
 *
 * <h2>Why the report is light and the application is dark</h2>
 *
 * The application is a screen you stare at; a report is a document that gets
 * printed, annotated and attached to a ticket. Dark ink on white is what
 * survives a printer and a photocopier, and a dark page either wastes toner or
 * silently loses its own colour coding when the browser strips backgrounds for
 * printing. The two are different media and share no stylesheet.
 *
 * <h2>Every value is escaped, and the document forbids script</h2>
 *
 * See {@link Html}. Service banners are chosen by the host being scanned, so
 * they are attacker-controlled input that ends up in a file the analyst opens.
 * Escaping is the control; the CSP below is the second control that assumes the
 * first one will eventually fail.
 *
 * <p>The output is well-formed XML as well as valid HTML -- self-closing void
 * elements, quoted attributes, no bare ampersands. Not for standards points: it
 * means the test suite can parse it with the JDK's XML parser and assert on its
 * structure, and a document whose escaping is broken stops parsing.
 */
public final class HtmlReportWriter {

    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm z");

    private HtmlReportWriter() {
    }

    public static String render(ScanReport report, Instant now, ZoneId zone) {
        StringBuilder out = new StringBuilder(16_384);
        head(out, report, zone);
        summary(out, report, now, zone);
        caveats(out, report, now);
        actions(out, report);
        findings(out, report);
        evidence(out, report);
        provenance(out, report, zone);
        out.append("</body>\n</html>\n");
        return out.toString();
    }

    /**
     * The network-wide report: every target that has been scanned.
     *
     * <p>Shares the head, the caveat block and the provenance footer with the
     * per-scan report, because those three are the parts that must not diverge.
     * If a scan report and a network report of the same data ever disagreed
     * about which feeds were loaded, neither would be trustworthy.
     */
    public static String renderNetwork(NetworkReport report, Instant now, ZoneId zone) {
        StringBuilder out = new StringBuilder(32_768);
        networkHead(out, report);
        networkSummary(out, report, now, zone);
        genericCaveats(out, report.caveats(now));
        networkActions(out, report);
        networkTargets(out, report, now);
        provenanceSection(out, report.provenance(), zone);
        out.append("</body>\n</html>\n");
        return out.toString();
    }

    // ------------------------------------------------------------------ head

    private static void networkHead(StringBuilder out, NetworkReport report) {
        documentHead(out, "CyberScope network report");
    }

    private static void head(StringBuilder out, ScanReport report, ZoneId zone) {
        documentHead(out, "CyberScope report - " + report.target());
    }

    /** One head for both report kinds, so the CSP cannot drift between them. */
    private static void documentHead(StringBuilder out, String title) {
        out.append("<!DOCTYPE html>\n")
           .append("<html lang=\"en\">\n<head>\n")
           .append("<meta charset=\"utf-8\"/>\n")
           // The second control. A report has no script of its own, so denying
           // script outright costs nothing and stops a payload that survived an
           // escaping bug. img-src 'none' matters too: <img src=x onerror=...>
           // is the shortest working XSS payload there is.
           .append("<meta http-equiv=\"Content-Security-Policy\" content=\"")
           .append("default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; ")
           .append("img-src 'none'; object-src 'none'; base-uri 'none'\"/>\n")
           .append("<title>").append(Html.escape(title)).append("</title>\n")
           .append("<style>\n").append(CSS).append("</style>\n")
           .append("</head>\n<body>\n");
    }

    // --------------------------------------------------------------- summary

    private static void summary(StringBuilder out, ScanReport report,
                                Instant now, ZoneId zone) {
        out.append("<header>\n")
           .append("<h1>Security scan report</h1>\n")
           .append("<p class=\"target\">").append(Html.escape(report.target())).append("</p>\n")
           .append("</header>\n");

        out.append("<section id=\"summary\">\n<h2>Summary</h2>\n");

        out.append("<p class=\"headline band-").append(bandSlug(report.band())).append("\">")
           .append(Html.escape(report.headline())).append("</p>\n");

        Coverage coverage = report.coverage();
        out.append("<dl class=\"facts\">\n");
        fact(out, "Exposure", report.band().label() + " - " + report.band().meaning());
        fact(out, "Coverage", coverage.percent() + "% (" + coverage.describe() + ")");
        fact(out, "Scanned", STAMP.format(report.scannedAt().atZone(zone))
                + "  (" + ReportProvenance.describeAge(report.scanAge(now)) + " before this report)");
        fact(out, "Scan type", report.scanType().displayName());
        fact(out, "Command", report.commandLine());
        out.append("</dl>\n</section>\n");
    }

    private static void fact(StringBuilder out, String term, String value) {
        out.append("<dt>").append(Html.escape(term)).append("</dt>")
           .append("<dd>").append(Html.escape(value)).append("</dd>\n");
    }

    // --------------------------------------------------------------- caveats

    /**
     * Rendered before the findings, never after.
     *
     * <p>A reader who stops after the first screen must have met the reasons to
     * distrust the numbers. Caveats at the bottom of a report are decoration.
     */
    private static void caveats(StringBuilder out, ScanReport report, Instant now) {
        genericCaveats(out, report.caveats(now));
    }

    private static void genericCaveats(StringBuilder out, List<String> caveats) {
        if (caveats.isEmpty()) {
            return;
        }
        out.append("<section id=\"caveats\" class=\"warn\">\n")
           .append("<h2>Read this before the findings</h2>\n<ul>\n");
        for (String caveat : caveats) {
            out.append("<li>").append(Html.escape(caveat)).append("</li>\n");
        }
        out.append("</ul>\n</section>\n");
    }

    // --------------------------------------------------------------- actions

    private static void actions(StringBuilder out, ScanReport report) {
        List<RankedFinding> top = report.topActions(5);
        out.append("<section id=\"actions\">\n<h2>Do these first</h2>\n");
        if (top.isEmpty()) {
            out.append("<p class=\"empty\">")
               .append(Html.escape(report.findingCount() == 0
                       ? "Nothing matched the index. That is not the same as nothing being "
                         + "wrong: see the coverage figure above."
                       : "No finding could be ranked."))
               .append("</p>\n</section>\n");
            return;
        }
        out.append("<ol>\n");
        for (RankedFinding finding : top) {
            out.append("<li><span class=\"what\">")
               .append(Html.escape(finding.product().isBlank()
                       ? finding.where() : finding.product() + " on " + finding.where()))
               .append("</span> <span class=\"cve\">")
               .append(Html.escape(finding.vulnerability().cveId()))
               .append("</span> <span class=\"why\">")
               .append(Html.escape(reason(finding))).append("</span></li>\n");
        }
        out.append("</ol>\n</section>\n");
    }

    /**
     * Why this finding ranks where it does -- the actual driver, not a number.
     *
     * <p>The first version printed the EPSS score whenever there was one, which
     * produced this in a real report:
     *
     * <pre>
     *   4. openbsd:openssh 9.6p1 on 22/tcp   CVE-2026-60002   EPSS 0.00
     * </pre>
     *
     * That reads as "do this fourth because its exploitation probability is
     * zero", which is nonsense. The finding is there because its CVSS rating is
     * CRITICAL, and {@code RankedFinding.urgency()} promotes those to ELEVATED
     * regardless of EPSS. Printing the score without the reason attributes the
     * ranking to the wrong evidence -- the exact error this project spends its
     * time arguing against.
     *
     * <p>So each branch mirrors the branch in {@code urgency()} that produced
     * the band, and where CVSS did the promoting it says so and reports the low
     * EPSS as the qualifier it is.
     */
    static String reason(RankedFinding finding) {
        ExploitSignal signal = finding.vulnerability().signal();
        if (finding.vulnerability().isWeaklyMatched()) {
            return "matched only by an \"all versions\" claim - listed, but not ranked on";
        }
        if (signal.isRansomware()) {
            return "used in ransomware campaigns";
        }
        if (signal.isKnownExploited()) {
            return "listed in CISA KEV";
        }
        if (signal.epssAtLeast(0.5)) {
            return String.format("EPSS %.2f - exploitation more likely than not",
                    signal.epssScore());
        }
        if (signal.epssAtLeast(0.1)) {
            return String.format("EPSS %.2f", signal.epssScore());
        }
        if (finding.vulnerability().severity() == Severity.CRITICAL) {
            return signal.hasEpss()
                    ? String.format("rated CVSS critical; EPSS only %.2f", signal.epssScore())
                    : "rated CVSS critical; no exploitation data";
        }
        return signal.hasEpss()
                ? String.format("EPSS %.2f", signal.epssScore())
                : "no exploitation data";
    }

    // -------------------------------------------------------------- findings

    private static void findings(StringBuilder out, ScanReport report) {
        out.append("<section id=\"findings\">\n<h2>All findings</h2>\n");
        List<RankedFinding> all = report.findings();
        if (all.isEmpty()) {
            out.append("<p class=\"empty\">No findings.</p>\n</section>\n");
            return;
        }
        out.append("<p class=\"note\">")
           .append(Html.escape("Ordered by whether the vulnerability is being exploited, not "
                   + "by CVSS. CVSS rates how bad a flaw would be; it does not say whether "
                   + "anyone is using it."))
           .append("</p>\n");
        out.append("<table id=\"findings-table\">\n<thead><tr>")
           .append("<th>Port</th><th>Service</th><th>CVE</th><th>CVSS</th>")
           .append("<th>Urgency</th><th>Exploited</th><th>EPSS</th><th>Matched</th>")
           .append("</tr></thead>\n<tbody>\n");

        for (RankedFinding finding : all) {
            ExploitSignal signal = finding.vulnerability().signal();
            out.append("<tr>")
               .append(cell(finding.where()))
               .append(cell(finding.product()))
               .append(cell(finding.vulnerability().cveId()))
               .append(cell(finding.vulnerability().severity().toString().toLowerCase(Locale.ROOT)))
               .append("<td class=\"band-").append(bandSlug(finding.urgency())).append("\">")
               .append(Html.escape(finding.urgency().label())).append("</td>")
               .append(cell(signal.isRansomware() ? "ransomware"
                       : signal.isKnownExploited() ? "CISA KEV" : "-"))
               .append(cell(signal.hasEpss() ? String.format("%.2f", signal.epssScore()) : "-"))
               .append(cell(finding.vulnerability().precision().description()))
               .append("</tr>\n");
        }
        out.append("</tbody>\n</table>\n</section>\n");
    }

    // -------------------------------------------------------------- evidence

    /**
     * Every open service, whether or not it produced a finding.
     *
     * <p>This is the section that makes the report falsifiable. A findings table
     * on its own cannot be checked -- the reader has no way to tell a service
     * with nothing filed against it from a service nobody could identify. Both
     * appear here, labelled.
     */
    private static void evidence(StringBuilder out, ScanReport report) {
        out.append("<section id=\"evidence\">\n<h2>Services seen</h2>\n")
           .append("<p class=\"note\">")
           .append(Html.escape("\"Probed\" means CyberScope opened a connection and read a "
                   + "banner. \"Inferred\" means the service was guessed from the port "
                   + "number and was never confirmed. Only probed services can be matched "
                   + "against the CVE index."))
           .append("</p>\n");

        out.append("<table id=\"evidence-table\">\n<thead><tr>")
           .append("<th>Host</th><th>Port</th><th>State</th><th>Service</th>")
           .append("<th>Version</th><th>Evidence</th>")
           .append("</tr></thead>\n<tbody>\n");

        for (Host host : report.hosts()) {
            for (Port port : host.openPorts()) {
                Service service = port.service();
                String evidence = switch (service.method()) {
                    case PROBED -> "probed (" + service.confidence() + "/10)";
                    case TABLE  -> "inferred from port number (" + service.confidence() + "/10)";
                    case NONE   -> "none";
                };
                out.append("<tr>")
                   .append(cell(host.displayName()))
                   .append(cell(port.number() + "/" + port.protocol()))
                   .append(cell(port.state().toString()))
                   .append(cell(service.name().isBlank() ? "unknown" : service.name()))
                   .append(cell(service.product().isBlank() ? "-" : service.describe()))
                   .append("<td class=\"ev-")
                   .append(service.method().name().toLowerCase(Locale.ROOT)).append("\">")
                   .append(Html.escape(evidence)).append("</td>")
                   .append("</tr>\n");
            }
        }
        out.append("</tbody>\n</table>\n</section>\n");
    }

    // ------------------------------------------------------------ provenance

    private static void provenance(StringBuilder out, ScanReport report, ZoneId zone) {
        provenanceSection(out, report.provenance(), zone);
    }

    private static void provenanceSection(StringBuilder out, ReportProvenance provenance,
                                          ZoneId zone) {
        out.append("<section id=\"provenance\">\n<h2>What this was checked against</h2>\n")
           .append("<ul>\n");
        source(out, provenance.corpus(), zone, "No CVE corpus was loaded.");
        source(out, provenance.kev(), zone, "The CISA KEV catalogue was not loaded.");
        source(out, provenance.epss(), zone, "EPSS scores were not loaded.");
        out.append("</ul>\n")
           .append("<p class=\"note\">")
           .append(Html.escape("Findings are matched against these data sets as they stood "
                   + "when this report was generated. The same scan re-reported later may "
                   + "differ, because the data moves and the scan does not."))
           .append("</p>\n</section>\n");

        out.append("<section id=\"authorisation\" class=\"warn\">\n")
           .append("<h2>Authorisation</h2>\n<p>")
           .append(Html.escape(ScanReport.AUTHORISATION_NOTICE))
           .append("</p>\n</section>\n");

        out.append("<footer>").append(Html.escape(provenance.describe(zone)))
           .append("</footer>\n");
    }

    private static void source(StringBuilder out, ReportProvenance.Source source,
                               ZoneId zone, String absent) {
        out.append("<li>")
           .append(Html.escape(source == null ? absent : source.describe(zone)))
           .append("</li>\n");
    }

    // ----------------------------------------------------- network sections

    private static void networkSummary(StringBuilder out, NetworkReport report,
                                       Instant now, ZoneId zone) {
        out.append("<header>\n<h1>Network scan report</h1>\n")
           .append("<p class=\"target\">")
           .append(Html.escape(report.targets().size()
                   + (report.targets().size() == 1 ? " target" : " targets") + " scanned"))
           .append("</p>\n</header>\n");

        out.append("<section id=\"summary\">\n<h2>Summary</h2>\n")
           .append("<p class=\"headline band-").append(bandSlug(report.band())).append("\">")
           .append(Html.escape(report.headline())).append("</p>\n");

        out.append("<dl class=\"facts\">\n");
        fact(out, "Exposure", report.band().label() + " - " + report.band().meaning());
        fact(out, "Coverage", report.coverage().percent()
                + "% (" + report.coverage().describe() + ")");
        // The oldest scan dates the whole document. Averaging the ages would hide
        // a three-week-old host behind four fresh ones.
        report.oldest().ifPresent(target -> fact(out, "Oldest scan",
                target.target() + ", " + target.describeAge(now)));
        fact(out, "Findings", report.posture().findingCount() + " across "
                + report.posture().targetsNeedingAction() + " target(s) needing action");
        out.append("</dl>\n</section>\n");
    }

    private static void networkActions(StringBuilder out, NetworkReport report) {
        List<NetworkPosture.Action> top = report.topActions(10);
        out.append("<section id=\"actions\">\n<h2>Do these first</h2>\n");
        if (top.isEmpty()) {
            out.append("<p class=\"empty\">")
               .append(Html.escape("Nothing matched the index across any target. That is "
                       + "not the same as nothing being wrong: see the coverage figure."))
               .append("</p>\n</section>\n");
            return;
        }
        out.append("<p class=\"note\">")
           .append(Html.escape("Ranked across every target at once, not grouped by host. "
                   + "The worst thing on the network is the worst thing on the network, "
                   + "whichever machine it is on."))
           .append("</p>\n<ol>\n");
        for (NetworkPosture.Action action : top) {
            out.append("<li><span class=\"what\">")
               .append(Html.escape(action.target() + " - " + action.finding().product()
                       + " on " + action.finding().where()))
               .append("</span> <span class=\"cve\">")
               .append(Html.escape(action.finding().vulnerability().cveId()))
               .append("</span> <span class=\"why\">")
               .append(Html.escape(reason(action.finding()))).append("</span></li>\n");
        }
        out.append("</ol>\n</section>\n");
    }

    private static void networkTargets(StringBuilder out, NetworkReport report, Instant now) {
        out.append("<section id=\"targets\">\n<h2>Targets</h2>\n")
           .append("<p class=\"note\">")
           .append(Html.escape("Worst first. Coverage is per target: a host with low "
                   + "coverage has not been given a clean result, it has been given a "
                   + "partial one."))
           .append("</p>\n")
           .append("<table id=\"targets-table\">\n<thead><tr>")
           .append("<th>Target</th><th>Last scan</th><th>Coverage</th>")
           .append("<th>Findings</th><th>Exposure</th><th>Since previous</th>")
           .append("</tr></thead>\n<tbody>\n");

        for (TargetPosture target : report.targets()) {
            out.append("<tr>")
               .append(cell(target.target()))
               .append(cell(target.describeAge(now) + (target.isStale(now) ? " (stale)" : "")))
               .append(cell(target.coverage().percent() + "% ("
                       + target.coverage().checked() + "/"
                       + target.coverage().examined() + ")"))
               .append(cell(String.valueOf(target.assessment().findingCount())))
               .append("<td class=\"band-").append(bandSlug(target.band())).append("\">")
               .append(Html.escape(target.band().label())).append("</td>")
               .append(cell(target.trend().meaning()))
               .append("</tr>\n");
        }
        out.append("</tbody>\n</table>\n</section>\n");
    }

    // ------------------------------------------------------------- utilities

    private static String cell(String value) {
        return "<td>" + Html.escape(value) + "</td>";
    }

    /** A CSS-safe band name. Derived from the enum, never from user input. */
    static String bandSlug(ExposureBand band) {
        return band.name().toLowerCase(Locale.ROOT);
    }

    // ------------------------------------------------------------------- CSS

    /**
     * Print-first. The screen gets whatever the print rules leave behind.
     *
     * <p>{@code page-break-inside: avoid} on table rows is the rule that makes a
     * printed report readable: without it a finding can be split across a page
     * boundary with its CVE id on one page and its severity on the next.
     */
    private static final String CSS = """
            :root { --ink:#14171c; --muted:#5b6472; --rule:#d5dae2; --warn-bg:#fff8e6;
                    --warn-rule:#e0b400; --crit:#a3231c; --high:#b45309; --elev:#8a6100;
                    --low:#1f4fbf; --clear:#0f6b3a; --ind:#5b6472; }
            * { box-sizing: border-box; }
            body { font: 14px/1.55 -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial,
                   sans-serif; color: var(--ink); background:#fff; margin: 0 auto; padding: 32px;
                   max-width: 62rem; }
            header { border-bottom: 2px solid var(--ink); padding-bottom: 10px; margin-bottom: 22px; }
            h1 { font-size: 21px; margin: 0; letter-spacing: .01em; }
            h2 { font-size: 14px; text-transform: uppercase; letter-spacing: .07em;
                 color: var(--muted); margin: 26px 0 8px; }
            .target { font: 600 17px/1.3 ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
                      margin: 6px 0 0; }
            .headline { font-size: 16px; font-weight: 700; margin: 0 0 14px;
                        padding: 10px 12px; border-left: 4px solid var(--ind);
                        background: #f6f7f9; }
            .band-critical      { border-left-color: var(--crit);  color: var(--crit); }
            .band-high          { border-left-color: var(--high);  color: var(--high); }
            .band-elevated      { border-left-color: var(--elev);  color: var(--elev); }
            .band-low           { border-left-color: var(--low);   color: var(--low); }
            .band-clear         { border-left-color: var(--clear); color: var(--clear); }
            .band-indeterminate { border-left-color: var(--ind);   color: var(--ind); }
            td.band-critical, td.band-high, td.band-elevated,
            td.band-low, td.band-clear, td.band-indeterminate
                { border-left: none; background: none; font-weight: 700; }
            dl.facts { display: grid; grid-template-columns: 8.5rem 1fr; gap: 3px 14px; margin: 0; }
            dt { color: var(--muted); }
            dd { margin: 0; font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
                 font-size: 13px; word-break: break-word; }
            table { border-collapse: collapse; width: 100%; font-size: 12.5px; margin-top: 6px; }
            th { text-align: left; border-bottom: 2px solid var(--ink); padding: 5px 8px 5px 0;
                 font-size: 11px; text-transform: uppercase; letter-spacing: .05em;
                 color: var(--muted); }
            td { border-bottom: 1px solid var(--rule); padding: 5px 8px 5px 0;
                 vertical-align: top; }
            .ev-probed { color: var(--clear); font-weight: 600; }
            .ev-table  { color: var(--elev);  font-weight: 600; }
            .warn { background: var(--warn-bg); border-left: 4px solid var(--warn-rule);
                    padding: 12px 16px; margin: 20px 0; }
            .warn h2 { margin-top: 0; color: #6f5200; }
            .warn ul { margin: 0; padding-left: 20px; }
            .warn li + li { margin-top: 7px; }
            .note { color: var(--muted); font-size: 12.5px; margin: 4px 0 10px; }
            .empty { color: var(--muted); }
            ol { padding-left: 22px; margin: 6px 0; }
            ol li { margin-bottom: 7px; }
            .what { font-weight: 600; }
            .cve  { font-family: ui-monospace, Menlo, Consolas, monospace; }
            .why  { color: var(--muted); }
            #provenance ul { padding-left: 20px; margin: 4px 0; }
            footer { margin-top: 30px; padding-top: 10px; border-top: 1px solid var(--rule);
                     color: var(--muted); font-size: 11.5px; }
            @media print {
              body { padding: 0; max-width: none; font-size: 11pt; }
              h2 { margin-top: 16px; }
              /* A finding split across a page break loses its own meaning: the
                 CVE id on one page, the severity on the next. */
              tr, li { page-break-inside: avoid; }
              section { page-break-inside: auto; }
              thead { display: table-header-group; }
              .warn { border-left-width: 3px; }
            }
            """;
}
