package com.cyberscope.service.scanner;

import com.cyberscope.model.ScanType;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Everything about one Nmap invocation.
 *
 * @param target    the validated target that was scanned
 * @param scanType  the profile used
 * @param command   the exact arguments, for the report and for reproducibility
 * @param xml       Nmap's XML report; its temp file has already been deleted
 * @param startedAt when the scan began — a report must state when, not when it was rendered
 * @param elapsed   wall-clock duration
 * @param warnings  anything Nmap wrote to stderr; often the only sign nothing was scanned
 */
public record NmapRunResult(String target, ScanType scanType, List<String> command,
                            String xml, Instant startedAt, Duration elapsed, String warnings) {

    public NmapRunResult {
        Objects.requireNonNull(target, "target must not be null");
        Objects.requireNonNull(scanType, "scanType must not be null");
        Objects.requireNonNull(startedAt, "startedAt must not be null");
        command  = List.copyOf(command);
        warnings = warnings == null ? "" : warnings;
    }

    public boolean hasWarnings() {
        return !warnings.isBlank();
    }
}
