package com.cyberscope.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ProcessTimeoutExceptionTest {

    @Test
    @DisplayName("renders a sub-second timeout in milliseconds, not as '0s'")
    void subSecondTimeoutIsNotZeroSeconds() {
        String message = new ProcessTimeoutException(List.of("nmap"), Duration.ofMillis(200))
                .getMessage();
        assertTrue(message.contains("200ms"), message);
        assertTrue(!message.contains(" 0s"), "must not read as '0s': " + message);
    }

    @Test
    @DisplayName("renders a multi-second timeout in seconds")
    void multiSecondTimeoutUsesSeconds() {
        String message = new ProcessTimeoutException(List.of("nmap"), Duration.ofSeconds(180))
                .getMessage();
        assertTrue(message.contains("180s"), message);
    }

    @Test
    @DisplayName("includes the command that timed out")
    void includesCommand() {
        String message = new ProcessTimeoutException(
                List.of("nmap", "-sV", "127.0.0.1"), Duration.ofSeconds(5)).getMessage();
        assertTrue(message.contains("nmap -sV 127.0.0.1"), message);
    }
}
