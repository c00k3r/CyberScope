package com.cyberscope.service.report;

import com.cyberscope.model.DetectionMethod;
import com.cyberscope.model.Host;
import com.cyberscope.model.Port;
import com.cyberscope.model.Service;
import com.cyberscope.service.scanner.NmapRunResult;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Renders scan results as a plain-text report.
 *
 * <p>A pure function: no printing, no clock, no I/O. The timezone is a parameter
 * rather than {@code ZoneId.systemDefault()} so the output is deterministic and
 * therefore testable.
 */
public final class ScanReportFormatter {

    private static final DateTimeFormatter TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z");
    private static final String RULE = "=".repeat(78);
    private static final String[] HEADERS = {"PORT", "STATE", "SERVICE", "VERSION", "DETECTION"};

    private ScanReportFormatter() {
    }

    public static String format(NmapRunResult run, List<Host> hosts, ZoneId zone) {
        StringBuilder out = new StringBuilder();

        out.append(RULE).append('\n');
        out.append(" CyberScope scan report\n");
        out.append(RULE).append('\n');
        out.append(field("Target",    run.target().describe()));
        out.append(field("Scan type", run.scanType().displayName()
                                      + " - " + run.scanType().description()));
        out.append(field("Started",   TIMESTAMP.format(run.startedAt().atZone(zone))));
        out.append(field("Duration",  String.format("%.1f s", run.elapsed().toMillis() / 1000.0)));
        out.append(field("Command",   String.join(" ", run.command())));
        out.append(RULE).append("\n\n");

        if (run.hasWarnings()) {
            out.append(" Nmap warnings:\n");
            run.warnings().lines().forEach(l -> out.append("   ! ").append(l).append('\n'));
            out.append('\n');
        }

        if (hosts.isEmpty()) {
            out.append(" No hosts were found. The target may be down, filtered,"
                     + " or unresolvable.\n\n");
        }

        boolean anyGuessed = false;
        int totalOpen = 0;
        int hostsUp = 0;

        for (Host host : hosts) {
            if (host.isUp()) {
                hostsUp++;
            }
            List<Port> open = host.openPorts();
            totalOpen += open.size();

            out.append(' ').append(host.displayName())
               .append("  [").append(host.state()).append("]\n");

            int other = host.ports().size() - open.size();
            out.append(' ').append(count(open.size(), "open port"));
            if (other > 0) {
                out.append(", ").append(other).append(" closed or filtered");
            }
            out.append("\n\n");

            if (open.isEmpty()) {
                out.append("   No open ports found.\n\n");
                continue;
            }

            List<String[]> rows = new ArrayList<>(open.size());
            for (Port port : open) {
                Service service = port.service();
                if (service.method() == DetectionMethod.TABLE) {
                    anyGuessed = true;
                }
                rows.add(new String[]{
                        port.number() + "/" + port.protocol(),
                        port.state().toString(),
                        service.name().isBlank() ? "unknown" : service.name(),
                        service.product().isBlank() ? "-" : service.describe(),
                        detection(service)});
            }
            out.append(table(rows)).append('\n');
        }

        out.append(RULE).append('\n');
        out.append(' ').append(count(hosts.size(), "host")).append(" scanned, ")
           .append(hostsUp).append(" up, ")
           .append(count(totalOpen, "open port")).append(" total\n");
        out.append(RULE).append('\n');

        if (anyGuessed) {
            out.append('\n');
            out.append(" Note: services marked 'table' were inferred from the port number, not\n");
            out.append("       probed. Treat them as unconfirmed and do not use them as evidence.\n");
        }
        return out.toString();
    }

    private static String detection(Service service) {
        return switch (service.method()) {
            case PROBED -> "probed (conf " + service.confidence() + ")";
            case TABLE  -> "table  (conf " + service.confidence() + ")";
            case NONE   -> "-";
        };
    }

    private static String field(String label, String value) {
        return String.format(" %-11s : %s%n", label, value);
    }

    private static String count(int n, String noun) {
        return n + " " + noun + (n == 1 ? "" : "s");
    }

    /** Column widths come from the content, so a long version string is never truncated. */
    private static String table(List<String[]> rows) {
        int[] width = new int[HEADERS.length];
        for (int c = 0; c < HEADERS.length; c++) {
            width[c] = HEADERS[c].length();
            for (String[] row : rows) {
                width[c] = Math.max(width[c], row[c].length());
            }
        }
        StringBuilder sb = new StringBuilder();
        sb.append("   ").append(row(HEADERS, width)).append('\n');

        String[] rule = new String[HEADERS.length];
        for (int c = 0; c < HEADERS.length; c++) {
            rule[c] = "-".repeat(width[c]);
        }
        sb.append("   ").append(row(rule, width)).append('\n');

        for (String[] r : rows) {
            sb.append("   ").append(row(r, width)).append('\n');
        }
        return sb.toString();
    }

    private static String row(String[] cells, int[] width) {
        StringBuilder sb = new StringBuilder();
        for (int c = 0; c < cells.length; c++) {
            sb.append(String.format("%-" + width[c] + "s", cells[c]));
            if (c < cells.length - 1) {
                sb.append("  ");
            }
        }
        return sb.toString().stripTrailing();
    }
}
