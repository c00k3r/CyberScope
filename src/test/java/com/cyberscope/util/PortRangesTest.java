package com.cyberscope.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PortRangesTest {

    @Nested
    @DisplayName("parsing Nmap's range notation")
    class Parsing {

        @Test
        void expandsASingleRange() {
            assertEquals(Set.of(1, 2, 3, 4), PortRanges.parse("1-4"));
        }

        @Test
        void expandsMixedSinglesAndRanges() {
            assertEquals(Set.of(1, 2, 3, 4, 6, 9, 10, 11), PortRanges.parse("1-4,6,9-11"));
        }

        @Test
        @DisplayName("handles the real attribute from a captured scan")
        void handlesRealNmapOutput() {
            // Verbatim from `nmap -sV -T4 -F 127.0.0.1`, which collapsed 99 ports.
            String real = "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,"
                        + "143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,"
                        + "631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,"
                        + "2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,"
                        + "5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,"
                        + "7070,8000,8008-8009,8081,8443,8888,9100,9999-10000,32768,49152-49157";

            Set<Integer> ports = PortRanges.parse(real);

            assertEquals(99, ports.size(), "Nmap said count=99; the range text must agree");
            assertTrue(ports.contains(3306));
            assertTrue(ports.contains(49157));
            assertTrue(ports.contains(6001));
        }

        /**
         * The ports attribute is #IMPLIED in Nmap's own DTD. Its absence is a
         * normal condition -- coverage is then unknown -- not a parse failure.
         */
        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"   ", "\t"})
        void absentOrBlankTextIsEmptyNotAnError(String text) {
            assertTrue(PortRanges.parse(text).isEmpty());
        }

        @Test
        void toleratesStrayWhitespaceAndEmptyElements() {
            assertEquals(Set.of(1, 2, 5), PortRanges.parse(" 1 - 2 , , 5 "));
        }

        @Test
        void theResultIsUnmodifiable() {
            Set<Integer> ports = PortRanges.parse("1-3");
            assertThrows(UnsupportedOperationException.class, () -> ports.add(9));
        }
    }

    @Nested
    @DisplayName("rejecting input that is not a port range")
    class Rejection {

        @ParameterizedTest
        @ValueSource(strings = {
                "65536",          // one past the top of the range
                "-1",             // reads as an empty low bound
                "70000",
                "abc",
                "80,abc",
                "1-",             // missing high bound
                "-5",
                "5-3",            // descending
                "1-2-3",          // ambiguous
                "999999999999",   // longer than any port number
                "1e3"
        })
        void malformedTextIsRejected(String text) {
            assertThrows(IllegalArgumentException.class, () -> PortRanges.parse(text));
        }

        @Test
        void portZeroIsAccepted() {
            // Port 0 is legal in Nmap's own -p syntax, so rejecting it would be
            // stricter than the tool whose output we are parsing.
            assertEquals(Set.of(0), PortRanges.parse("0"));
        }

        /**
         * A parser that is only safe because of who happens to be calling it is
         * not a safe parser. The cap is checked before the expansion loop runs,
         * so a hostile range cannot allocate first and fail second.
         */
        @Test
        void anAbsurdlyLargeRangeIsRefusedRatherThanAllocated() {
            // 65,536 ports is the whole space and is allowed exactly once...
            assertEquals(65_536, PortRanges.parse("0-65535").size());
            // ...but asking for the whole space twice is not.
            assertThrows(IllegalArgumentException.class,
                    () -> PortRanges.parse("0-65535,0-65535,1-100").size());
        }
    }

    @Nested
    @DisplayName("formatting back to Nmap's notation")
    class Formatting {

        @ParameterizedTest(name = "{0} -> \"{1}\"")
        @CsvSource({
                "'1,2,3',        '1-3'",
                "'1,2',          '1,2'",
                "'5',            '5'",
                "'1,2,3,6',      '1-3,6'",
                "'1,3,5',        '1,3,5'",
                "'3,1,2',        '1-3'"
        })
        void collapsesConsecutiveRuns(String input, String expected) {
            Set<Integer> ports = new LinkedHashSet<>();
            for (String n : input.split(",")) {
                ports.add(Integer.parseInt(n.trim()));
            }
            assertEquals(expected, PortRanges.format(ports));
        }

        @Test
        void emptyFormatsToEmpty() {
            assertEquals("", PortRanges.format(Set.of()));
            assertEquals("", PortRanges.format(null));
        }

        /**
         * The property that actually matters: this notation is how coverage will
         * be stored, so anything lost in a round trip is coverage the comparison
         * layer will silently get wrong.
         */
        @Test
        void formatAndParseRoundTrip() {
            for (String original : new String[]{
                    "1-4,6,9-11", "80", "1,2", "22,80,443,8080", "1-65535",
                    "7,9,13,21-23,25-26,1025-1029,49152-49157"}) {
                Set<Integer> parsed = PortRanges.parse(original);
                assertEquals(parsed, PortRanges.parse(PortRanges.format(parsed)),
                        "round trip lost ports for: " + original);
            }
        }
    }
}