package com.cyberscope.service.scanner;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

class NmapDetectorTest {

    /** Real output captured from `nmap --version` on the development machine. */
    private static final String REAL_OUTPUT = """
            Nmap version 7.99 ( https://nmap.org )
            Platform: x86_64-pc-linux-gnu
            Compiled with: liblua-5.4.8 openssl-3.6.2 libssh2-1.11.1
            Compiled without:
            Available nsock engines: epoll poll select
            """;

    @Test
    @DisplayName("parses the version from real nmap output")
    void parsesRealOutput() {
        assertEquals(Optional.of("7.99"), NmapDetector.parseVersion(REAL_OUTPUT));
    }

    @Test
    @DisplayName("parses a single-line version banner")
    void parsesSingleLine() {
        assertEquals(Optional.of("7.80"),
                NmapDetector.parseVersion("Nmap version 7.80 ( https://nmap.org )"));
    }

    @Test
    void returnsEmptyForNull() {
        assertEquals(Optional.empty(), NmapDetector.parseVersion(null));
    }

    @Test
    void returnsEmptyForBlank() {
        assertEquals(Optional.empty(), NmapDetector.parseVersion("   "));
    }

    @Test
    @DisplayName("returns empty for shell 'command not found' output")
    void returnsEmptyForUnrelated() {
        assertEquals(Optional.empty(),
                NmapDetector.parseVersion("bash: nmap: command not found"));
    }

    @Test
    @DisplayName("does not match 'Nmap version' appearing mid-line")
    void anchorsToLineStart() {
        assertEquals(Optional.empty(),
                NmapDetector.parseVersion("see also: Nmap version 9.99 (spoofed)"));
    }
}
