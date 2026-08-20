package com.cyberscope;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the CLI contract. Possible only because {@code run()} returns an exit
 * code rather than calling System.exit, and because argument handling happens
 * before any Nmap or network work.
 */
class AppTest {

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();
    private PrintStream originalOut;
    private PrintStream originalErr;

    @BeforeEach
    void captureStreams() {
        originalOut = System.out;
        originalErr = System.err;
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(err, true, StandardCharsets.UTF_8));
    }

    @AfterEach
    void restoreStreams() {
        System.setOut(originalOut);
        System.setErr(originalErr);
    }

    private String stdout() { return out.toString(StandardCharsets.UTF_8); }
    private String stderr() { return err.toString(StandardCharsets.UTF_8); }

    @Test
    @DisplayName("--help succeeds and works without Nmap installed")
    void helpSucceeds() {
        assertEquals(App.EXIT_OK, App.run(new String[]{"--help"}));
        assertTrue(stdout().contains("Usage: cyberscope"), stdout());
    }

    @Test
    @DisplayName("--version prints the version and succeeds")
    void versionSucceeds() {
        assertEquals(App.EXIT_OK, App.run(new String[]{"--version"}));
        assertTrue(stdout().contains(App.VERSION), stdout());
    }

    @Test
    @DisplayName("no arguments prints usage and succeeds")
    void noArgumentsShowsUsage() {
        assertEquals(App.EXIT_OK, App.run(new String[]{}));
        assertTrue(stdout().contains("Usage: cyberscope"), stdout());
    }

    @Test
    @DisplayName("an unknown option is rejected rather than treated as a target")
    void unknownOptionRejected() {
        assertEquals(App.EXIT_INVALID_TARGET, App.run(new String[]{"--script=evil"}));
        assertTrue(stderr().contains("Unknown option"), stderr());
    }

    @Test
    @DisplayName("two targets are rejected rather than silently using the first")
    void twoTargetsRejected() {
        assertEquals(App.EXIT_INVALID_TARGET, App.run(new String[]{"1.1.1.1", "2.2.2.2"}));
        assertTrue(stderr().contains("Exactly one target"), stderr());
    }

    @Test
    @DisplayName("an invalid target is rejected before Nmap is even looked for")
    void invalidTargetRejected() {
        assertEquals(App.EXIT_INVALID_TARGET, App.run(new String[]{"999.999.999.999"}));
        assertTrue(stderr().contains("outside the range"), stderr());
    }

    @Test
    @DisplayName("a decimal-notation IP is rejected")
    void alternateNotationRejected() {
        assertEquals(App.EXIT_INVALID_TARGET, App.run(new String[]{"2130706433"}));
    }
}
