package com.cyberscope.model;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Everything one report contains, before anything decides how to draw it.
 *
 * <p>Pure and immutable, with no HTML in it. The renderer in Part 2 turns this
 * into a page; the CLI could turn the same object into text. Keeping the content
 * decisions here rather than inside a template is what lets the rules below be
 * unit-tested, and they are rules -- not formatting.
 *
 * <h2>Three rules this record enforces</h2>
 *
 * <ol>
 *   <li><b>A finding count never appears without a coverage figure.</b>
 *       {@link #headline} produces both or neither. "14 findings" on its own is
 *       the single-number problem in a different costume: it cannot be read
 *       without knowing how much was looked at.</li>
 *   <li><b>Two ages, never one.</b> A report carries the age of the <i>scan</i>
 *       and the age of the <i>index</i>, because v0.6.0 scores stored scans
 *       against today's data and those two clocks run independently.</li>
 *   <li><b>The command is recorded with its output path stripped.</b> See
 *       {@link #sanitiseCommand}.</li>
 * </ol>
 *
 * @param target      the target string as the user typed it
 * @param scanId      the stored scan this was built from, 0 for an unsaved scan
 * @param scannedAt   when the scan ran -- NOT when the report was written
 * @param scanType    which profile was used
 * @param command     the nmap invocation, sanitised
 * @param assessment  the posture, scored against the index named in provenance
 * @param hosts       every host in the scan, for the evidence section
 * @param provenance  what the vulnerability data looked like at generation time
 */
public record ScanReport(String target, long scanId, Instant scannedAt, ScanType scanType,
                         List<String> command, PostureAssessment assessment,
                         List<Host> hosts, ReportProvenance provenance) {

    public ScanReport {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(scannedAt, "scannedAt");
        Objects.requireNonNull(assessment, "assessment");
        // Mandatory. A report without provenance is an assertion, not a finding:
        // there is no way to reproduce it or to tell it apart from a later one
        // scored against different data.
        Objects.requireNonNull(provenance, "provenance -- a report must record the "
                + "vulnerability data it was scored against");
        command = command == null ? List.of() : sanitiseCommand(command);
        hosts = hosts == null ? List.of() : List.copyOf(hosts);
    }

    /**
     * Removes the {@code -oX <path>} pair from a recorded command.
     *
     * <p>Nmap writes its XML to a temporary file and CyberScope passes the path
     * on the command line, so the raw invocation ends with something like
     * {@code -oX /tmp/cyberscope-scan-17234220050205854625.xml}. That path is
     * three unhelpful things in a document that gets forwarded: noise, a local
     * filesystem layout, and a filename that no longer exists, which invites a
     * reader to go looking for it.
     *
     * <p>Removed here rather than in the renderer, so every output format gets
     * the same treatment and none of them can forget.
     */
    static List<String> sanitiseCommand(List<String> raw) {
        List<String> cleaned = new java.util.ArrayList<>(raw.size());
        for (int i = 0; i < raw.size(); i++) {
            String token = raw.get(i);
            if (token.equals("-oX") || token.equals("-oN") || token.equals("-oG")
                    || token.equals("-oA")) {
                i++;                      // also drop the path that follows it
                continue;
            }
            cleaned.add(token);
        }
        return List.copyOf(cleaned);
    }

    public String commandLine() {
        return String.join(" ", command);
    }

    public ExposureBand band() {
        return assessment.band();
    }

    public Coverage coverage() {
        return assessment.coverage();
    }

    public int findingCount() {
        return assessment.findingCount();
    }

    /** Findings in the same order the UI shows them: exploitation first. */
    public List<RankedFinding> findings() {
        return assessment.ranked();
    }

    public List<RankedFinding> topActions(int limit) {
        return assessment.topActions(limit);
    }

    // ------------------------------------------------------------------ ages

    /** How old the evidence is. */
    public Duration scanAge(Instant now) {
        Duration age = Duration.between(scannedAt, now);
        return age.isNegative() ? Duration.ZERO : age;
    }

    public boolean scanIsStale(Instant now) {
        return scanAge(now).compareTo(TargetPosture.STALE_AFTER) >= 0;
    }

    // -------------------------------------------------------------- headline

    /**
     * The summary sentence, which never states one number without the other.
     *
     * <p>Examples:
     *
     * <pre>
     *   HIGH exposure - 14 findings across 6 of 8 services checked (75% coverage)
     *   CLEAR - nothing found across 8 of 8 services checked (100% coverage)
     *   INDETERMINATE - 2 of 9 services could be checked (22% coverage)
     * </pre>
     *
     * The third form is the one that matters: when coverage is inadequate the
     * sentence leads with what could <i>not</i> be examined, because a finding
     * count from a fifth of a host is not the headline.
     */
    public String headline() {
        Coverage coverage = coverage();
        String scope = coverage.describe() + " (" + coverage.percent() + "% coverage)";

        if (band() == ExposureBand.INDETERMINATE) {
            return "INDETERMINATE - " + scope
                 + (findingCount() == 0 ? "" : ", " + findingCount() + " finding"
                    + (findingCount() == 1 ? "" : "s") + " in what was checked");
        }
        if (findingCount() == 0) {
            return band().label().toUpperCase(java.util.Locale.ROOT)
                 + " - nothing found across " + scope;
        }
        return band().label().toUpperCase(java.util.Locale.ROOT) + " exposure - "
             + findingCount() + " finding" + (findingCount() == 1 ? "" : "s")
             + " across " + scope;
    }

    /**
     * Everything that qualifies this report, in the order a reader meets it.
     *
     * <p>Scan age first, then index provenance. The scan is the evidence and the
     * index is the interpretation; a reader who only reads one line should get
     * the one about the evidence.
     */
    public List<String> caveats(Instant now) {
        List<String> caveats = new java.util.ArrayList<>();
        if (scanIsStale(now)) {
            caveats.add("This scan was taken "
                    + ReportProvenance.describeAge(scanAge(now))
                    + " ago. Ports may have opened or closed since; every statement "
                    + "here describes the host as it was then.");
        }
        int unchecked = coverage().unchecked();
        if (unchecked > 0) {
            caveats.add(unchecked + " open service" + (unchecked == 1 ? " was" : "s were")
                    + " not checked against the index, usually because no version could "
                    + "be probed. Those services are listed but carry no findings, which "
                    + "is not the same as having none.");
        }
        caveats.addAll(provenance.warnings(now));
        return List.copyOf(caveats);
    }

    /** The standing constraint, reproduced on every report. */
    public static final String AUTHORISATION_NOTICE =
            "This scan was run under the operator's assertion that they are authorised "
          + "to test this target. CyberScope cannot verify authorisation and does not "
          + "attempt to. Port scanning a system without permission is unlawful in most "
          + "jurisdictions.";
}
