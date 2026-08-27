package com.cyberscope.service.report;
 
import com.cyberscope.service.compare.DiffWarning;
import com.cyberscope.service.compare.HostDiff;
import com.cyberscope.service.compare.PortChange;
import com.cyberscope.service.compare.ScanDiff;
 
import java.time.Duration;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
 
/**
 * Renders a comparison as text.
 *
 * <p>The layout carries the argument the comparator makes. Warnings come first,
 * because a warning that the two scans may not describe the same machine has to
 * be read <em>before</em> the differences it qualifies, not discovered
 * underneath them. Host changes and evidence changes are separate sections with
 * separate headings, so nobody has to know that {@code ~} means something
 * different from {@code +}.
 */
public final class ScanDiffFormatter {
 
    private static final DateTimeFormatter TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z");
    private static final String RULE = "=".repeat(78);
    private static final String THIN = "-".repeat(78);
 
    private ScanDiffFormatter() {
    }
 
    public static String format(ScanDiff diff, ZoneId zone) {
        StringBuilder out = new StringBuilder();
 
        out.append(RULE).append('\n');
        out.append(" CyberScope scan comparison\n");
        out.append(RULE).append('\n');
        out.append(field("Target", diff.after().run().target().describe()));
        out.append(field("Earlier", TIMESTAMP.format(diff.before().run().startedAt().atZone(zone))
                + "   (" + diff.before().run().scanType().displayName() + ")"));
        out.append(field("Later",   TIMESTAMP.format(diff.after().run().startedAt().atZone(zone))
                + "   (" + diff.after().run().scanType().displayName() + ")"));
        out.append(field("Interval", humanInterval(diff.interval())));
        out.append(RULE).append("\n\n");
 
        appendWarnings(out, diff);
        appendHostPresence(out, diff);
        appendChanges(out, diff);
        appendCoverage(out, diff);
        appendSummary(out, diff);
 
        return out.toString();
    }
 
    // ------------------------------------------------------------- sections
 
    /**
     * First, deliberately.
     *
     * <p>A reader who scrolls to the changes and stops has still seen the reason
     * not to trust them. The other order is how a caveat gets missed.
     */
    private static void appendWarnings(StringBuilder out, ScanDiff diff) {
        if (diff.warnings().isEmpty()) {
            return;
        }
        for (DiffWarning warning : diff.warnings()) {
            String marker = warning.invalidatesComparison() ? " !! " : " !  ";
            out.append(marker).append(warning.kind()).append('\n');
            out.append("      ").append(warning.detail()).append('\n');
        }
        if (!diff.isTrustworthy()) {
            out.append('\n');
            out.append(" These scans may not describe the same machine. The differences below\n");
            out.append(" are reported for completeness and should not be read as changes to a\n");
            out.append(" host until the routes are accounted for.\n");
        }
        out.append('\n').append(THIN).append("\n\n");
    }
 
    private static void appendHostPresence(StringBuilder out, ScanDiff diff) {
        diff.addedHosts().forEach(host ->
                out.append(" + host ").append(host.address())
                   .append(" responded in the later scan only\n"));
        diff.removedHosts().forEach(host ->
                out.append(" - host ").append(host.address())
                   .append(" responded in the earlier scan only\n"));
        if (!diff.addedHosts().isEmpty() || !diff.removedHosts().isEmpty()) {
            out.append('\n');
        }
    }
 
    private static void appendChanges(StringBuilder out, ScanDiff diff) {
        if (diff.hostChanges().isEmpty() && diff.evidenceChanges().isEmpty()) {
            out.append(" No differences found at any port both scans examined.\n\n");
            return;
        }
 
        if (!diff.hostChanges().isEmpty()) {
            out.append(" CHANGES ON THE HOST\n");
            out.append(" ").append("-".repeat(19)).append('\n');
            for (PortChange change : diff.hostChanges()) {
                out.append("   + ").append(change.describe()).append('\n');
            }
            out.append('\n');
        }
 
        if (!diff.evidenceChanges().isEmpty()) {
            out.append(" CHANGES IN WHAT WE KNOW\n");
            out.append(" ").append("-".repeat(23)).append('\n');
            for (PortChange change : diff.evidenceChanges()) {
                out.append("   ~ ").append(change.describe()).append('\n');
            }
            out.append('\n');
            out.append("   These are differences in detection quality, not in the host.\n");
            out.append("   The services may be unchanged; what changed is whether\n");
            out.append("   CyberScope was able to confirm them.\n\n");
        }
    }
 
    /**
     * What could not be compared, stated plainly.
     *
     * <p>"No changes found" and "nothing changed" are different claims. Omitting
     * this section would let a report make the second while only supporting the
     * first.
     */
    private static void appendCoverage(StringBuilder out, ScanDiff diff) {
        int uncompared = diff.hosts().stream()
                .mapToInt(host -> host.uncomparedPorts().size()).sum();
        boolean gap = diff.hosts().stream().anyMatch(HostDiff::hasCoverageGap);
        if (uncompared == 0 && !gap) {
            return;
        }
        out.append(" NOT COMPARED\n");
        out.append(" ").append("-".repeat(12)).append('\n');
        if (uncompared > 0) {
            out.append("   ").append(uncompared)
               .append(uncompared == 1 ? " port was" : " ports were")
               .append(" examined by only one of the two scans.\n");
            out.append("   Nothing can be said about ")
               .append(uncompared == 1 ? "it" : "them").append(".\n");
        }
        for (HostDiff host : diff.hosts()) {
            if (!host.coverageComplete()) {
                out.append("   ").append(host.address())
                   .append(": a scan counted ports it could not name, so even the\n")
                   .append("   figure above understates what was not compared.\n");
            }
        }
        out.append('\n');
    }
 
    private static void appendSummary(StringBuilder out, ScanDiff diff) {
        out.append(RULE).append('\n');
        out.append(' ')
           .append(count(diff.hostChanges().size(), "change")).append(" on the host, ")
           .append(count(diff.evidenceChanges().size(), "change")).append(" in evidence")
           .append('\n');
        out.append(RULE).append('\n');
    }
 
    // -------------------------------------------------------------- helpers
 
    private static String humanInterval(Duration interval) {
        long seconds = Math.abs(interval.getSeconds());
        if (seconds < 90) {
            return seconds + " s";
        }
        if (seconds < 5_400) {
            return String.format("%.0f min", seconds / 60.0);
        }
        if (seconds < 172_800) {
            return String.format("%.1f hours", seconds / 3_600.0);
        }
        return String.format("%.1f days", seconds / 86_400.0);
    }
 
    private static String field(String label, String value) {
        return String.format(" %-9s : %s%n", label, value);
    }
 
    private static String count(int n, String noun) {
        return n + " " + noun + (n == 1 ? "" : "s");
    }
}
 