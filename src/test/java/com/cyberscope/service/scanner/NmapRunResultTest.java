package com.cyberscope.service.scanner;

import com.cyberscope.model.ScanType;
import com.cyberscope.util.TargetKind;
import com.cyberscope.util.ValidatedTarget;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class NmapRunResultTest {

    private static NmapRunResult withElapsed(Duration elapsed) {
        return new NmapRunResult(
                new ValidatedTarget("127.0.0.1", TargetKind.IPV4, 1),
                ScanType.QUICK, List.of("nmap", "127.0.0.1"), "",
                Instant.parse("2026-08-20T10:00:00Z"), elapsed, "");
    }

    @Test
    @DisplayName("elapsed is normalised to whole milliseconds")
    void elapsedIsTruncatedToMilliseconds() {
        NmapRunResult run = withElapsed(Duration.ofSeconds(6).plusNanos(789_123_456));

        assertEquals(Duration.ofMillis(6789), run.elapsed());
    }

    /**
     * Truncation, not rounding. Rounding would make a 999_999 ns measurement report
     * as 1 ms of elapsed time that never happened -- a report should never claim
     * more than was measured.
     */
    @ParameterizedTest(name = "{0} ns -> {1} ms")
    @CsvSource({
            "0,        0",
            "999999,   0",
            "1000000,  1",
            "1999999,  1",
            "1500000,  1"
    })
    void nanosecondsAreTruncatedNotRounded(long nanos, long expectedMillis) {
        assertEquals(expectedMillis, withElapsed(Duration.ofNanos(nanos)).elapsed().toMillis());
    }

    @Test
    @DisplayName("a duration that is already whole milliseconds is left alone")
    void wholeMillisecondsAreUnchanged() {
        Duration exact = Duration.ofMillis(6789);

        assertEquals(exact, withElapsed(exact).elapsed());
    }

    @Test
    void theCommandIsDefensivelyCopied() {
        List<String> mutable = new ArrayList<>(List.of("nmap", "127.0.0.1"));
        NmapRunResult run = new NmapRunResult(
                new ValidatedTarget("127.0.0.1", TargetKind.IPV4, 1), ScanType.QUICK,
                mutable, "", Instant.now(), Duration.ofSeconds(1), "");

        mutable.add("--script=vuln");

        assertEquals(List.of("nmap", "127.0.0.1"), run.command(),
                "the record kept a live reference to the caller's list");
    }

    @Test
    void nullElapsedIsRejectedRatherThanCrashingLater() {
        assertThrows(NullPointerException.class, () -> withElapsed(null));
    }
}