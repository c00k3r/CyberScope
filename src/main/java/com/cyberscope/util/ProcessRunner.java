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
 * <p>Both output streams are drained concurrently while the process runs.
 * Waiting for the process before reading its output deadlocks as soon as the
 * output exceeds the operating system's pipe buffer.
 */
public final class ProcessRunner {

    private ProcessRunner() {
    }

    /**
     * Runs a command to completion.
     *
     * @param command the executable followed by its arguments, as separate elements
     * @param timeout how long to wait before killing the process
     * @throws IOException              if the executable could not be started at all
     * @throws ProcessTimeoutException  if the process outlived the timeout
     * @throws InterruptedException     if this thread was interrupted while waiting
     */
    public static ProcessResult run(List<String> command, Duration timeout)
            throws IOException, InterruptedException, ProcessTimeoutException {

        if (command == null || command.isEmpty()) {
            throw new IllegalArgumentException("command must not be null or empty");
        }

        Process process = new ProcessBuilder(command).start();

        // Start draining BEFORE waiting. This ordering is the whole point.
        CompletableFuture<String> stdout = readAsync(process.inputReader());
        CompletableFuture<String> stderr = readAsync(process.errorReader());

        boolean exited = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);

        if (!exited) {
            process.destroyForcibly();
            process.waitFor();
            throw new ProcessTimeoutException(command, timeout);
        }

        return new ProcessResult(process.exitValue(), stdout.join(), stderr.join());
    }

    /** Consumes a stream on a background thread so the child can never block on a full pipe. */
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
