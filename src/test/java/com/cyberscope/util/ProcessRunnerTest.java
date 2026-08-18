package com.cyberscope.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ProcessRunnerTest {

    @Test
    @DisplayName("captures stdout and a zero exit code")
    void capturesStdout() throws Exception {
        ProcessResult r = ProcessRunner.run(List.of("echo", "hello"), Duration.ofSeconds(5));
        assertEquals(0, r.exitCode());
        assertEquals("hello", r.stdout());
        assertTrue(r.isSuccess());
    }

    @Test
    @DisplayName("keeps stderr separate from stdout")
    void separatesStreams() throws Exception {
        ProcessResult r = ProcessRunner.run(
                List.of("sh", "-c", "echo out; echo err >&2"), Duration.ofSeconds(5));
        assertEquals("out", r.stdout());
        assertEquals("err", r.stderr());
    }

    @Test
    @DisplayName("reports a non-zero exit code without throwing")
    void reportsNonZeroExit() throws Exception {
        ProcessResult r = ProcessRunner.run(List.of("sh", "-c", "exit 3"), Duration.ofSeconds(5));
        assertEquals(3, r.exitCode());
        assertFalse(r.isSuccess());
    }

    @Test
    @DisplayName("throws IOException when the executable does not exist")
    void throwsWhenExecutableMissing() {
        assertThrows(IOException.class, () ->
                ProcessRunner.run(List.of("cyberscope-no-such-binary"), Duration.ofSeconds(5)));
    }

    @Test
    @DisplayName("kills a process that exceeds the timeout")
    void killsOnTimeout() {
        long start = System.currentTimeMillis();
        assertThrows(ProcessTimeoutException.class, () ->
                ProcessRunner.run(List.of("sleep", "30"), Duration.ofSeconds(2)));
        assertTrue(System.currentTimeMillis() - start < 10_000,
                "should return shortly after the timeout, not wait for the child");
    }

    @Test
    @DisplayName("does not deadlock when output exceeds the pipe buffer")
    void doesNotDeadlockOnLargeOutput() throws Exception {
        ProcessResult r = ProcessRunner.run(
                List.of("sh", "-c",
                        "yes 0123456789012345678901234567890123456789 | head -50000"),
                Duration.ofSeconds(20));
        assertEquals(0, r.exitCode());
        assertTrue(r.stdout().length() > 1_000_000);
    }

    @Test
    @DisplayName("rejects an empty command")
    void rejectsEmptyCommand() {
        assertThrows(IllegalArgumentException.class, () ->
                ProcessRunner.run(List.of(), Duration.ofSeconds(5)));
    }
}
