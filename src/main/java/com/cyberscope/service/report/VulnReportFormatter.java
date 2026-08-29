package com.cyberscope.service.report;

import com.cyberscope.model.MappingOutcome;
import com.cyberscope.model.Port;
import com.cyberscope.model.Severity;
import com.cyberscope.model.VulnAssessment;
import com.cyberscope.model.Vulnerability;
import com.cyberscope.repository.IndexMetadata;

import java.time.Instant;
import java.time.ZoneId;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Renders vulnerability assessments as text.
 *
 * <h2>The problem this class exists to solve</h2>
 *
 * A realistic twelve-service host produces <b>303 findings</b> against the real
 * index -- 73 for one MySQL instance alone. Printing them is not a report, it is
 * a data dump, and a data dump gets skimmed and then ignored. An ignored report
 * and no report are the same artefact.
 *
 * <p>So the default view answers three questions in order, and only then offers
 * detail:
 *
 * <ol>
 *   <li><b>What could we not check?</b> Printed first and unconditionally,
 *       because it is the question a findings list silently answers wrong.</li>
 *   <li><b>Which ports are worst?</b> One line each, ordered by severity.</li>
 *   <li><b>What specifically?</b> The top few per port, with a count of the rest.</li>
 * </ol>
 *
 * <p>{@code --vulns} switches to the full listing. Nothing is hidden; the default
 * is a summary, not a filter.
 */
public final class VulnReportFormatter {

    private static final int DEFAULT_PER_PORT = 3;
    private static final String RULE =
            "--------------------------------------------------------------------------";

    private VulnReportFormatter() {
    }

    /**
     * @param assessments in port order, as {@code VulnerabilityService.assess} returns them
     * @param index       index metadata, or null when there is no index
     * @param verbose     list every finding rather than the top few
     */
    public static String format(Map<Port, VulnAssessment> assessments,
                                IndexMetadata index, Instant now, ZoneId zone,
                                boolean verbose) {
        StringBuilder out = new StringBuilder();
        out.append('\n').append(" VULNERABILITIES\n").append(RULE).append('\n');

        if (index == null) {
            out.append(" No CVE index. Run --update-cve-index to build one"
                       + " (about 100 MB, one minute).\n");
            out.append(" Nothing below is a statement about these services.\n");
            return out.toString();
        }
        out.append(" Index: ").append(index.describe(now, zone)).append('\n');
        if (index.isStale(now)) {
            out.append("   ! This index is more than ")
               .append(IndexMetadata.STALE_AFTER.toDays())
               .append(" days old. NVD publishes on the order of 500 advisories a"
                       + " day, so\n     'no findings' below may simply mean"
                       + " 'not yet in this copy'.\n");
        }
        out.append('\n');

        if (assessments.isEmpty()) {
            out.append(" No open ports to assess.\n");
            return out.toString();
        }

        Map<MappingOutcome, Integer> counts = new EnumMap<>(MappingOutcome.class);
        int withFindings = 0, clean = 0, totalFindings = 0, weak = 0;
        for (VulnAssessment a : assessments.values()) {
            counts.merge(a.outcome(), 1, Integer::sum);
            if (a.outcome() == MappingOutcome.MAPPED) {
                if (a.vulnerabilities().isEmpty()) {
                    clean++;
                } else {
                    withFindings++;
                }
            }
            totalFindings += a.vulnerabilities().size();
            weak += a.weaklyMatchedCount();
        }

        out.append(' ').append(count(assessments.size(), "open port"))
           .append(" examined\n");
        int mapped = counts.getOrDefault(MappingOutcome.MAPPED, 0);
        if (mapped > 0) {
            out.append("    ").append(pad(mapped)).append(" looked up");
            out.append("          ").append(withFindings).append(" with findings, ")
               .append(clean).append(" with none\n");
        }
        emit(out, counts, MappingOutcome.UNRESOLVED,        "could not be looked up");
        emit(out, counts, MappingOutcome.NOT_APPLICABLE,    "had no version to look up");
        emit(out, counts, MappingOutcome.INDEX_UNAVAILABLE, "could not reach the index");

        // The line the whole version exists for. Printed before any finding,
        // because a reader who stops after the findings list must not stop
        // before learning that part of the host was never asked about.
        int unchecked = assessments.size() - mapped;
        if (unchecked > 0) {
            out.append('\n')
               .append(" ! ").append(count(unchecked, "service"))
               .append(" could not be checked. Their absence from the list below is\n")
               .append("   a gap in the lookup, not a clean bill of health.\n");
        }
        out.append('\n');

        // Three sections, in this order, with explicit headings rather than one
        // list sorted by severity. An earlier draft interleaved them and the
        // un-checkable services drifted to the bottom, because they have no
        // severity to sort by -- which is precisely backwards for a report whose
        // argument is that a gap in the lookup outranks a finding.

        List<Map.Entry<Port, VulnAssessment>> found = assessments.entrySet().stream()
                .filter(e -> !e.getValue().vulnerabilities().isEmpty())
                .sorted((a, b) -> {
                    int bySeverity = Integer.compare(b.getValue().worstSeverity().rank(),
                                                     a.getValue().worstSeverity().rank());
                    return bySeverity != 0 ? bySeverity
                            : Integer.compare(a.getKey().number(), b.getKey().number());
                })
                .toList();

        List<Map.Entry<Port, VulnAssessment>> gaps = assessments.entrySet().stream()
                .filter(e -> e.getValue().outcome() != MappingOutcome.MAPPED)
                .sorted(Map.Entry.comparingByKey(
                        (x, y) -> Integer.compare(x.number(), y.number())))
                .toList();

        if (!gaps.isEmpty()) {
            out.append(RULE).append('\n')
               .append(" NOT CHECKED -- ").append(count(gaps.size(), "service")).append('\n')
               .append(RULE).append('\n');
            for (Map.Entry<Port, VulnAssessment> entry : gaps) {
                appendPort(out, entry.getKey(), entry.getValue(), verbose);
            }
            out.append('\n');
        }

        if (!found.isEmpty()) {
            out.append(RULE).append('\n')
               .append(" FINDINGS -- ").append(count(found.size(), "service")).append('\n')
               .append(RULE).append('\n');
            for (Map.Entry<Port, VulnAssessment> entry : found) {
                appendPort(out, entry.getKey(), entry.getValue(), verbose);
            }
            out.append('\n');
        }

        if (clean > 0) {
            out.append(RULE).append('\n')
               .append(" LOOKED UP, NOTHING FILED -- ").append(count(clean, "service"))
               .append('\n').append(RULE).append('\n');
            assessments.forEach((port, a) -> {
                if (a.outcome() == MappingOutcome.MAPPED && a.vulnerabilities().isEmpty()) {
                    out.append("   ").append(port.number()).append('/')
                       .append(port.protocol().toString().toLowerCase())
                       .append("  ").append(a.lookedUp().map(c -> c.productKey()
                               + " " + c.version()).orElse("")).append('\n');
                }
            });
            out.append('\n');
        }

        if (!verbose && totalFindings > 0) {
            out.append(" ").append(totalFindings).append(" finding(s) in total");
            if (weak > 0) {
                out.append("; ").append(weak)
                   .append(" of them rest on an 'all versions' claim");
            }
            out.append(".\n Run with --vulns for the complete list.\n");
        }
        return out.toString();
    }

    private static void appendPort(StringBuilder out, Port port, VulnAssessment a,
                                   boolean verbose) {
        String head = String.format("  %d/%s   %s", port.number(),
                port.protocol().toString().toLowerCase(),
                a.lookedUp().map(c -> c.productKey() + " " + c.version())
                            .orElse(port.service().describe()));
        out.append(head);
        out.append(" ".repeat(Math.max(1, 58 - head.length())));
        out.append(a.outcome() == MappingOutcome.MAPPED
                        ? a.worstSeverity() + "  " + a.vulnerabilities().size() + " found"
                        : a.outcome().summary().toUpperCase());
        out.append('\n');

        if (a.outcome() != MappingOutcome.MAPPED) {
            for (String line : wrap(a.detail(), 70)) {
                out.append("    ").append(line).append('\n');
            }
            return;
        }

        List<Vulnerability> shown = verbose ? a.vulnerabilities()
                : a.vulnerabilities().stream()
                   .filter(v -> !v.isWeaklyMatched())
                   .limit(DEFAULT_PER_PORT).toList();

        for (Vulnerability v : shown) {
            out.append(String.format("    %-16s %-9s %-5s %s%n",
                    v.cveId(), v.severity(),
                    v.cvssScore() == null ? "-" : String.valueOf(v.cvssScore()),
                    describeMatch(v)));
            if (!v.description().isBlank()) {
                out.append("        ").append(trim(v.description(), 66)).append('\n');
            }
        }

        int remaining = a.vulnerabilities().size() - shown.size();
        if (remaining > 0) {
            long weakHere = a.weaklyMatchedCount();
            out.append("    ... ").append(remaining).append(" more");
            if (weakHere > 0) {
                out.append(", of which ").append(weakHere)
                   .append(" NVD files against every version");
            }
            out.append('\n');
        }
    }

    /**
     * Says how the finding matched, in words rather than in enum names.
     *
     * <p>An {@code ALL_VERSIONS} match is labelled explicitly because it is the
     * one that produces a 2008 Red Hat packaging incident on a 2024 OpenSSH.
     */
    private static String describeMatch(Vulnerability v) {
        return switch (v.precision()) {
            case VERSION_EXACT -> "this exact version";
            case VERSION_RANGE -> "in range " + v.matchedOn();
            case ALL_VERSIONS  -> "claimed for ALL versions -- weak evidence";
        };
    }

    private static void emit(StringBuilder out, Map<MappingOutcome, Integer> counts,
                             MappingOutcome outcome, String text) {
        int n = counts.getOrDefault(outcome, 0);
        if (n > 0) {
            out.append("    ").append(pad(n)).append(' ').append(text).append('\n');
        }
    }

    private static String pad(int n) {
        return String.format("%2d", n);
    }

    private static String count(int n, String noun) {
        return n + " " + noun + (n == 1 ? "" : "s");
    }

    private static String trim(String text, int width) {
        String flat = text.replaceAll("\\s+", " ").trim();
        return flat.length() <= width ? flat : flat.substring(0, width - 3) + "...";
    }

    private static List<String> wrap(String text, int width) {
        List<String> lines = new java.util.ArrayList<>();
        StringBuilder line = new StringBuilder();
        for (String word : text.replaceAll("\\s+", " ").trim().split(" ")) {
            if (line.length() + word.length() + 1 > width && line.length() > 0) {
                lines.add(line.toString());
                line.setLength(0);
            }
            if (line.length() > 0) {
                line.append(' ');
            }
            line.append(word);
        }
        if (line.length() > 0) {
            lines.add(line.toString());
        }
        return lines;
    }
}