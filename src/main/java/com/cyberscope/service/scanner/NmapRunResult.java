package com.cyberscope.service.scanner;

import java.time.Duration;
import java.util.List;

/**
 * The raw outcome of one Nmap invocation.
 *
 * @param command  the exact arguments used, for display and reporting
 * @param xml      Nmap's XML report; the temp file it came from is already deleted
 * @param elapsed  wall-clock duration of the scan
 * @param warnings anything Nmap wrote to stderr. Nmap exits 0 for an unresolvable
 *                 host, so this is often the only indication that nothing was scanned.
 */
public record NmapRunResult(List<String> command, String xml,
                            Duration elapsed, String warnings) {

    public NmapRunResult {
        command = List.copyOf(command);
        warnings = warnings == null ? "" : warnings;
    }

    public boolean hasWarnings() {
        return !warnings.isBlank();
    }
}
