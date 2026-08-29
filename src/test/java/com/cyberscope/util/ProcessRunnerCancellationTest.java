package com.cyberscope.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression tests for the child process outliving its caller.
 *
 * <p>Before v0.2, interrupting the thread running a scan threw out of
 * {@code Process.waitFor} without destroying the child, so pressing Stop left Nmap
 * scanning with nobody waiting on it.
 */
class ProcessRunnerCancellationTest {

    private static long sleepersRunning() throws Exception {
        Process p = new ProcessBuilder("bash", "-c",
                "pgrep -f '[s]leep 3675' | wc -l").start();
        String out = new String(p.getInputStream().readAllBytes()).trim();
        p.waitFor();
        return Long.parseLong(out);
    }

    @Test
    @DisplayName("interrupting the caller destroys the child process")
    void interruptionKillsTheChild() throws Exception {
        long before = sleepersRunning();

        CountDownLatch started = new CountDownLatch(1);
        AtomicReference<Exception> thrown = new AtomicReference<>();

        Thread worker = new Thread(() -> {
            try {
                started.countDown();
                // A distinctive duration so the test only counts its own child.
                ProcessRunner.run(List.of("sleep", "3675"), Duration.ofMinutes(10));
            } catch (Exception e) {
                thrown.set(e);
            }
        }, "runner-under-test");

        worker.start();
        assertTrue(started.await(5, TimeUnit.SECONDS));
        Thread.sleep(500);
        assertEquals(before + 1, sleepersRunning(), "the child should be running");

        worker.interrupt();
        worker.join(5_000);
        assertFalse(worker.isAlive(), "the worker should have unblocked");

        Thread.sleep(500);
        assertEquals(before, sleepersRunning(),
                "the child must be destroyed, not left orphaned");
        assertInstanceOf(InterruptedException.class, thrown.get());
    }

    @Test
    @DisplayName("a timeout also destroys the child")
    void timeoutKillsTheChild() throws Exception {
        long before = sleepersRunning();

        assertThrows(ProcessTimeoutException.class, () ->
                ProcessRunner.run(List.of("sleep", "3675"), Duration.ofMillis(300)));

        Thread.sleep(500);
        assertEquals(before, sleepersRunning(), "the child must not survive the timeout");
    }

    @Test
    @DisplayName("a normal completion leaves nothing behind")
    void normalCompletionLeavesNothing() throws Exception {
        long before = sleepersRunning();
        ProcessResult r = ProcessRunner.run(List.of("echo", "done"), Duration.ofSeconds(5));
        assertEquals(0, r.exitCode());
        assertEquals(before, sleepersRunning());
    }
}
