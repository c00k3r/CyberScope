package com.cyberscope.repository;

import com.cyberscope.model.ScanType;

import java.time.Duration;
import java.time.Instant;

/**
 * A row in the history list.
 *
 * <p>Deliberately not the whole scan: listing history should not load every port of
 * every host just to render a few lines. The full {@code ScanOutcome} is fetched
 * only when a user selects one.
 */
public record ScanSummary(long id, String target, ScanType scanType,
                          Instant startedAt, Duration elapsed,
                          int hostCount, int openPortCount) {

    /** e.g. "192.168.1.0/24 - 12 hosts, 31 open" */
    public String describe() {
        return target + "  - " + hostCount + (hostCount == 1 ? " host, " : " hosts, ")
             + openPortCount + " open";
    }
}