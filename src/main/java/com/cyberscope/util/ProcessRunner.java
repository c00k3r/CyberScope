package com.cyberscope.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Runs an external command and captures its output.
 *
 * <p>Both output streams are drained concurrently while the process runs. Waiting
 * for the process before reading its output deadlocks once the output exceeds the
 * operating system's pipe buffer.
 *
 * <p>The child is destroyed on every exit path, including thread interruption.
 * Without that, cancelling a scan leaves Nmap running with nobody waiting on it.
 */
public final class ProcessRunner {

    private ProcessRunner() {
    }

    public static ProcessResult run(List<String> command, Duration timeout)
            throws IOException, InterruptedException, ProcessTimeoutException {

        if (command == null || command.isEmpty()) {
            throw new IllegalArgumentException("command must not be null or empty");
        }

        Process process = new ProcessBuilder(command).start();
        try {
            // Start draining BEFORE waiting. This ordering is the whole point.
            CompletableFuture<String> stdout = readAsync(process.inputReader());
            CompletableFuture<String> stderr = readAsync(process.errorReader());

            boolean exited = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);

            if (!exited) {
                throw new ProcessTimeoutException(command, timeout);
            }
            return new ProcessResult(process.exitValue(), stdout.join(), stderr.join());

        } finally {
            // Covers the timeout, an interrupt, and any unexpected failure above.
            // SIGKILL, because a scanner that keeps scanning after you stop it is
            // worse than one that never started.
            if (process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }

    private static CompletableFuture<String> readAsync(BufferedReader reader) {
        return CompletableFuture.supplyAsync(() -> {
            try (reader) {
                return reader.lines().collect(Collectors.joining("\n"));
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
    }
}
