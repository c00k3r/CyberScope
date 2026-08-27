package com.cyberscope.service.report;
 
import com.cyberscope.model.DetectionMethod;
import com.cyberscope.model.Host;
import com.cyberscope.model.PortState;
import com.cyberscope.model.Port;
import com.cyberscope.model.Service;
import com.cyberscope.service.scanner.NmapRunResult;
 
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
 
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
        if (run.context().isKnown()) {
            out.append(field("Route",  run.context().describe()));
        }
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
 
            // "1 open port" is not a result. "1 open of 100 scanned" is: without
            // the denominator a reader cannot tell a clean host from a scan that
            // barely looked. The collapsed states come from the <extraports>
            // summaries, which is the only place that number exists.
            out.append(' ').append(coverage(host)).append("\n");
            if (!host.coverageIsComplete()) {
                out.append("   ! Some scanned ports could not be identified individually;\n");
                out.append("     coverage below is a subset of what was examined.\n");
            }
            out.append('\n');
 
            // Every port Nmap listed, not only the open ones. Closed and
            // filtered ports are listed individually only when there are few of
            // them, so this stays short -- the ninety-nine closed ports of a
            // typical scan are in the coverage line above, not here.
            List<Port> listed = host.ports();
            if (listed.isEmpty()) {
                out.append("   No ports were reported individually.\n\n");
                continue;
            }
 
            List<String[]> rows = new ArrayList<>(listed.size());
            for (Port port : listed) {
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
            out.append(table(rows));
            out.append('\n');
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
 
    /** e.g. {@code "100 ports scanned: 1 open, 99 closed"}. */
    private static String coverage(Host host) {
        StringBuilder out = new StringBuilder();
        out.append(count(host.scannedPortCount(), "port")).append(" scanned: ");
 
        Map<PortState, Integer> byState = new LinkedHashMap<>();
        host.ports().forEach(p -> byState.merge(p.state(), 1, Integer::sum));
        host.summaries().forEach(s -> byState.merge(s.state(), s.count(), Integer::sum));
 
        // Open first, then the rest. A reader looking for exposure should not
        // have to hunt past "97 closed" to find it.
        StringBuilder parts = new StringBuilder();
        appendState(parts, byState, PortState.OPEN);
        byState.keySet().stream().filter(state -> state != PortState.OPEN)
               .forEach(state -> appendState(parts, byState, state));
 
        return out.append(parts.length() == 0 ? "nothing reported" : parts).toString();
    }
 
    private static void appendState(StringBuilder out, Map<PortState, Integer> counts,
                                    PortState state) {
        Integer value = counts.get(state);
        if (value == null || value == 0) {
            return;
        }
        if (out.length() > 0) {
            out.append(", ");
        }
        out.append(value).append(' ').append(state);
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
 
    /** Column widths are derived from the content, so nothing is ever truncated. */
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
 

