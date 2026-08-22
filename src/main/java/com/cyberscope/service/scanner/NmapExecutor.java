package com.cyberscope.service.scanner;

import com.cyberscope.model.ScanType;
import com.cyberscope.util.ProcessResult;
import com.cyberscope.util.ProcessRunner;
import com.cyberscope.util.ProcessTimeoutException;
import com.cyberscope.util.ValidatedTarget;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Runs a single Nmap scan and returns its XML report.
 *
 * <p>The XML is written to a securely created temporary file, read back, and the
 * file is deleted before this method returns — including on every failure path.
 * Callers never see a path and so cannot leak one.
 *
 * <p>A host that is down or unresolvable is not an error: Nmap exits 0 and
 * the outcome is reported through {@link NmapRunResult#warnings()} and the XML.
 */
public final class NmapExecutor {

    private static final String TEMP_PREFIX = "cyberscope-scan-";
    private static final String TEMP_SUFFIX = ".xml";

    private NmapExecutor() {
    }

    /**
     * Executes a scan using a target that has already passed validation.
     *
     * @throws NmapExecutionException if Nmap could not run, timed out, or exited non-zero
     */
    public static NmapRunResult execute(
            ScanType scanType,
            ValidatedTarget target
    ) throws NmapExecutionException {

        Objects.requireNonNull(scanType, "scanType must not be null");
        Objects.requireNonNull(target, "target must not be null");

        Duration budget = scanType.timeoutFor(target.addressCount());

        Path xmlOutput = null;

        try {
            // Unpredictable name, atomic creation, owner-only permissions (0600).
            xmlOutput = Files.createTempFile(TEMP_PREFIX, TEMP_SUFFIX);

            /*
 * The command builder accepts only a ValidatedTarget, preserving the
 * validation boundary all the way to Nmap command construction.
 */
            List<String> command =
        NmapCommandBuilder.build(
                scanType,
                target,
                xmlOutput
                    );

            Instant started = Instant.now();

            ProcessResult result = ProcessRunner.run(command, budget);

            Duration elapsed = Duration.between(started, Instant.now());

            if (!result.isSuccess()) {
                throw new NmapExecutionException(
                        "Nmap exited with code " + result.exitCode()
                                + detail("stderr", result.stderr())
                                + detail("stdout", result.stdout())
                );
            }

            String xml = Files.readString(
                    xmlOutput,
                    StandardCharsets.UTF_8
            );

            if (xml.isBlank()) {
                throw new NmapExecutionException(
                        "Nmap reported success but produced no XML output. "
                                + "The scan may have been terminated externally."
                );
            }

            return new NmapRunResult(
                    target,
                    scanType,
                    command,
                    xml,
                    started,
                    elapsed,
                    result.stderr()
            );

        } catch (ProcessTimeoutException e) {
            throw new NmapExecutionException(
                    "Scan of '" + target.describe()
                            + "' exceeded the " + budget.toSeconds()
                            + "s limit for the " + scanType.displayName()
                            + " profile and was stopped. "
                            + "Try a narrower scan or a more responsive target.",
                    e
            );

        } catch (IOException e) {
            throw new NmapExecutionException(
                    "Could not run Nmap or read its output: "
                            + e.getMessage(),
                    e
            );

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();

            throw new NmapExecutionException(
                    "Scan was interrupted before it completed.",
                    e
            );

        } finally {
            deleteQuietly(xmlOutput);
        }
    }

    private static String detail(String label, String text) {
        return (text == null || text.isBlank())
                ? ""
                : "\n  " + label + ": " + text.strip();
    }

    private static void deleteQuietly(Path path) {
        if (path == null) {
            return;
        }

        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // A leftover temp file is untidy, not dangerous, and an exception
            // thrown from finally would replace the real failure.
        }
    }
}