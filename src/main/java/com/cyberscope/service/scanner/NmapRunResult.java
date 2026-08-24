package com.cyberscope.service.scanner;

import com.cyberscope.model.ScanType;
import com.cyberscope.util.ValidatedTarget;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;

public record NmapRunResult(ValidatedTarget target, ScanType scanType, List<String> command,
                            String xml, Instant startedAt, Duration elapsed, String warnings) {

    public NmapRunResult {
        Objects.requireNonNull(target, "target must not be null");
        Objects.requireNonNull(scanType, "scanType must not be null");
        Objects.requireNonNull(startedAt, "startedAt must not be null");
        Objects.requireNonNull(elapsed, "elapsed must not be null");
        command  = List.copyOf(command);
        warnings = warnings == null ? "" : warnings;

        // Duration.between(Instant, Instant) carries nanoseconds, but the elapsed
        // time of a network scan is not meaningful below a millisecond and the
        // database column is elapsed_ms. Normalising here -- rather than at the
        // point of storage -- means every NmapRunResult in the program carries the
        // same precision as one loaded back out of the database, so a saved scan and
        // the scan it was saved from compare equal. Precision the value cannot
        // survive a round trip with is a correctness problem, not a cosmetic one.
        elapsed = elapsed.truncatedTo(ChronoUnit.MILLIS);
    }

    public boolean hasWarnings() { return !warnings.isBlank(); }
}