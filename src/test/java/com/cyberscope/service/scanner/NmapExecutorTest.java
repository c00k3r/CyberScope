package com.cyberscope.service.scanner;

import com.cyberscope.model.ScanType;
import com.cyberscope.util.InvalidTargetException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class NmapExecutorTest {

    private static final String TEMP_PREFIX = "cyberscope-scan-";

    private static long strayTempFiles() throws IOException {
        try (Stream<Path> files = Files.list(Path.of(System.getProperty("java.io.tmpdir")))) {
            return files.filter(p -> p.getFileName().toString().startsWith(TEMP_PREFIX)).count();
        }
    }

    private static boolean nmapAvailable() {
        try {
            NmapDetector.detectVersion();
            return true;
        } catch (NmapNotFoundException e) {
            return false;
        }
    }

    @Nested
    @DisplayName("input handling (no Nmap required)")
    class InputHandling {

        @Test
        @DisplayName("propagates InvalidTargetException before starting any process")
        void rejectsInvalidTarget() {
            assertThrows(InvalidTargetException.class,
                    () -> NmapExecutor.execute(ScanType.QUICK, "-iL /etc/passwd"));
        }

        @Test
        @DisplayName("rejects a null scan type")
        void rejectsNullScanType() {
            assertThrows(NullPointerException.class,
                    () -> NmapExecutor.execute(null, "127.0.0.1"));
        }

        @Test
        @DisplayName("leaves no temp file behind when the target is rejected")
        void cleansUpAfterRejectedTarget() throws Exception {
            long before = strayTempFiles();
            assertThrows(InvalidTargetException.class,
                    () -> NmapExecutor.execute(ScanType.QUICK, "999.999.999.999"));
            assertEquals(before, strayTempFiles(), "a temp file was leaked");
        }
    }

    @Nested
    @DisplayName("real scans (skipped when Nmap is absent)")
    class RealScans {

        @Test
        @DisplayName("scans localhost and returns complete XML")
        void scansLocalhost() throws Exception {
            assumeTrue(nmapAvailable(), "Nmap is not installed");

            NmapRunResult result = NmapExecutor.execute(ScanType.QUICK, "127.0.0.1");

            assertFalse(result.xml().isBlank(), "XML must not be blank");
            assertTrue(result.xml().contains("<nmaprun"), "XML must contain the nmaprun root");
            assertTrue(result.xml().contains("</nmaprun>"), "XML must be complete");
            assertTrue(result.elapsed().toMillis() > 0, "elapsed time must be recorded");
            assertEquals("nmap", result.command().get(0));
            assertEquals("127.0.0.1", result.command().get(result.command().size() - 1));
        }

        @Test
        @DisplayName("deletes the temp file after a successful scan")
        void cleansUpAfterSuccess() throws Exception {
            assumeTrue(nmapAvailable(), "Nmap is not installed");

            long before = strayTempFiles();
            NmapExecutor.execute(ScanType.QUICK, "127.0.0.1");
            assertEquals(before, strayTempFiles(), "a temp file was leaked");
        }

        @Test
        @DisplayName("an unresolvable host is a warning, not a failure")
        void unresolvableHostIsNotAnException() throws Exception {
            assumeTrue(nmapAvailable(), "Nmap is not installed");

            NmapRunResult result =
                    NmapExecutor.execute(ScanType.QUICK, "no-such-host.invalid");

            assertTrue(result.hasWarnings(),
                    "Nmap exits 0 here, so stderr is the only signal that nothing was scanned");
            assertTrue(result.warnings().contains("Failed to resolve"));
        }
    }

    @Nested
    @DisplayName("result record")
    class ResultRecord {

        @Test
        @DisplayName("normalises a null warnings value to an empty string")
        void normalisesNullWarnings() {
            NmapRunResult r = new NmapRunResult(
        "127.0.0.1",
        ScanType.QUICK,
        List.of("nmap"),
        "<nmaprun/>",
        java.time.Instant.now(),
        java.time.Duration.ZERO,
        null);
            assertEquals("", r.warnings());
            assertFalse(r.hasWarnings());
        }

        @Test
        @DisplayName("the command list is immutable even if a mutable list was passed in")
        void commandIsImmutable() {
            NmapRunResult r = new NmapRunResult(
        "127.0.0.1",
        ScanType.QUICK,
        new ArrayList<>(List.of("nmap")),
        "<nmaprun/>",
        java.time.Instant.now(),
        java.time.Duration.ZERO,
        "");
            assertThrows(UnsupportedOperationException.class, () -> r.command().add("-sS"));
        }
    }
}
