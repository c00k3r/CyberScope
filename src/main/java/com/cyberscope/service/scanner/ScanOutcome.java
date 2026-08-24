package com.cyberscope.service.scanner;

import com.cyberscope.model.Host;

import java.util.List;

/** What one completed scan produced: the raw run plus the parsed hosts. */
public record ScanOutcome(NmapRunResult run, List<Host> hosts) {

    public ScanOutcome {
        hosts = List.copyOf(hosts);
    }

    public int totalOpenPorts() {
        return hosts.stream().mapToInt(h -> h.openPorts().size()).sum();
    }
}