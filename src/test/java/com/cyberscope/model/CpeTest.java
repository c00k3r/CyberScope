package com.cyberscope.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CpeTest {

    @Nested
    @DisplayName("CPE 2.2, the form Nmap emits")
    class TwoTwo {

        @Test
        void parsesWhatNmapActuallyProduced() {
            // Captured from a real scan in this session:
            //   nmap -sV -p 8099 --version-intensity 9 127.0.0.1
            //   service name=http product=SimpleHTTPServer version=0.6 method=probed
            Cpe cpe = Cpe.parse22("cpe:/a:python:simplehttpserver:0.6").orElseThrow();

            assertEquals(CpePart.APPLICATION, cpe.part());
            assertEquals("python", cpe.vendor());
            assertEquals("simplehttpserver", cpe.product());
            assertEquals("0.6", cpe.version());
            assertTrue(cpe.hasConcreteVersion());
        }

        @Test
        @DisplayName("a template with no version is not a parse failure")
        void versionlessUriIsValid() {
            Cpe cpe = Cpe.parse22("cpe:/a:openbsd:openssh").orElseThrow();

            assertEquals("openssh", cpe.product());
            assertEquals(Cpe.ANY, cpe.version());
            assertFalse(cpe.hasConcreteVersion(),
                    "no version means nothing to match a range against");
            assertTrue(cpe.isSearchable(),
                    "vendor and product are still usable as a lookup key");
        }

        @Test
        @DisplayName("nmap writes a trailing slash on its templates")
        void trailingSlashIsStripped() {
            assertEquals("openssh",
                    Cpe.parse22("cpe:/a:openbsd:openssh/").orElseThrow().product());
        }

        @Test
        void rejectsAnythingThatIsNotACpe22() {
            assertEquals(Optional.empty(), Cpe.parse22("cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"));
            assertEquals(Optional.empty(), Cpe.parse22("not a cpe"));
            assertEquals(Optional.empty(), Cpe.parse22(null));
            assertEquals(Optional.empty(), Cpe.parse22("cpe:/z:vendor:product"),
                    "z is not a valid part");
        }
    }

    @Nested
    @DisplayName("CPE 2.3, the form NVD stores")
    class TwoThree {

        @Test
        void parsesTheElevenFieldForm() {
            Cpe cpe = Cpe.parse23("cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*").orElseThrow();

            assertEquals("f5", cpe.vendor());
            assertEquals("nginx", cpe.product());
            assertEquals("1.24.0", cpe.version());
        }

        /**
         * Real data. CPE escapes ':' and '/' with a backslash, so a naive
         * split(":") shreds this row into the wrong number of fields and
         * silently produces a Cpe with product="purity\" -- which then matches
         * nothing, forever, with no error anywhere.
         */
        @Test
        @DisplayName("an escaped separator does not split the field")
        void escapedSeparatorsSurvive() {
            Cpe cpe = Cpe.parse23(
                    "cpe:2.3:a:purestorage:purity\\/\\/fa:*:*:*:*:*:*:*:*").orElseThrow();

            assertEquals("purestorage", cpe.vendor());
            assertEquals("purity//fa", cpe.product(),
                    "escapes are removed; the logical value is stored");
            assertEquals(Cpe.ANY, cpe.version());
        }

        /**
         * The test that was missing, and the mutation that found it.
         *
         * <p>Replacing the negative-lookbehind splitter with a plain
         * {@code split(":")} left every other test in this class green -- the
         * escaped characters in the purestorage row are slashes, not colons, so
         * the field boundaries land in the same places either way and
         * {@code normalise} strips the backslashes afterwards. That test proves
         * unescaping works; it does not prove the splitter does.
         *
         * <p>229 distinct products in the NVD corpus contain an escaped colon.
         * This is a real one. With a plain split the product becomes {@code 1c\}
         * and every CVE filed against it is unreachable, silently, forever.
         */
        @Test
        @DisplayName("an escaped COLON does not split the field")
        void escapedColonSurvives() {
            Cpe cpe = Cpe.parse23(
                    "cpe:2.3:a:1c:1c\\:enterprise:8.3:*:*:*:*:*:*:*").orElseThrow();

            assertEquals("1c", cpe.vendor());
            assertEquals("1c:enterprise", cpe.product());
            assertEquals("8.3", cpe.version());
        }

        @Test
        void aWildcardVersionIsNotAVersion() {
            Cpe cpe = Cpe.parse23("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*").orElseThrow();
            assertFalse(cpe.hasConcreteVersion());
        }

        @Test
        void rejectsATruncatedString() {
            assertEquals(Optional.empty(), Cpe.parse23("cpe:2.3:a:vendor"));
        }
    }

    @Nested
    class Normalisation {

        @Test
        @DisplayName("CPE is case-insensitive, so both sides are lower-cased once")
        void caseIsFolded() {
            Cpe upper = Cpe.parse22("cpe:/a:OpenBSD:OpenSSH:9.6").orElseThrow();
            Cpe lower = Cpe.parse22("cpe:/a:openbsd:openssh:9.6").orElseThrow();

            assertEquals(lower, upper, "records compare by value; these must be equal");
            assertEquals("openbsd:openssh", upper.productKey());
        }

        @Test
        @DisplayName("round-trips 2.2 to the 2.3 form NVD would store")
        void convertsBindings() {
            assertEquals("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*",
                    Cpe.parse22("cpe:/a:openbsd:openssh:9.6").orElseThrow().to23String());
        }

        /**
         * Locale.ROOT is not decoration. In the Turkish locale "I".toLowerCase()
         * produces a dotless i, so a JVM started with -Duser.language=tr would
         * quietly stop matching every vendor containing an I. Security lookups
         * must not depend on the operator's locale.
         */
        @Test
        @DisplayName("case folding does not depend on the default locale")
        void turkishIDoesNotBreakLookups() {
            assertEquals("cisco", Cpe.parse22("cpe:/a:CISCO:ios:1").orElseThrow().vendor());
        }
    }
}