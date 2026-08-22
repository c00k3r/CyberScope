package com.cyberscope.ui;

import com.cyberscope.model.Host;
import com.cyberscope.service.scanner.NmapRunResult;

import java.util.List;

/**
 * What one completed scan produced: the raw run plus the parsed hosts.
 *
 * <p>A {@code Task<V>} returns a single value, and the view needs both — the hosts
 * for the table, the run for warnings, timing and the command that was executed.
 */
public record ScanOutcome(NmapRunResult run, List<Host> hosts) {

    public ScanOutcome {
        hosts = List.copyOf(hosts);
    }

    public int totalOpenPorts() {
        return hosts.stream().mapToInt(h -> h.openPorts().size()).sum();
    }
}
