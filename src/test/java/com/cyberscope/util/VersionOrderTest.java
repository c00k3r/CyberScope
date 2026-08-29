package com.cyberscope.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VersionOrderTest {

    private static void earlier(String a, String b) {
        Integer c = VersionOrder.compare(a, b);
        assertNotNull(c, a + " vs " + b + " should be comparable");
        assertTrue(c < 0, a + " should sort before " + b + " but compare returned " + c);
    }

    private static void later(String a, String b) {
        Integer c = VersionOrder.compare(a, b);
        assertNotNull(c, a + " vs " + b + " should be comparable");
        assertTrue(c > 0, a + " should sort after " + b + " but compare returned " + c);
    }

    @Nested
    @DisplayName("numeric ordering")
    class Numeric {

        /** The whole reason this class exists instead of String::compareTo. */
        @Test
        @DisplayName("1.10 is later than 1.9, though it sorts earlier as text")
        void componentsCompareAsNumbers() {
            assertTrue("1.10".compareTo("1.9") < 0, "text ordering is wrong here");
            later("1.10", "1.9");
            earlier("1.21.6", "1.21.11");
        }

        @Test
        void leadingZeroesDoNotChangeTheValue() {
            assertEquals(0, VersionOrder.compare("1.007.3", "1.7.3"));
        }

        @Test
        @DisplayName("a longer numeric tail is later")
        void extraComponentsMeanLater() {
            later("1.24.0", "1.24");
            earlier("2.0", "2.0.0");
        }

        @Test
        @DisplayName("separators are interchangeable")
        void punctuationIsNotSignificant() {
            assertEquals(0, VersionOrder.compare("1.2.3", "1-2-3"));
            assertEquals(0, VersionOrder.compare("1.2.3", "1_2+3"));
        }
    }

    @Nested
    @DisplayName("the alphabetic-suffix problem")
    class Suffixes {

        /**
         * These two are the reason the class documents itself as approximate.
         * Identical shape, opposite meaning, decided by nothing in the string.
         */
        @Test
        @DisplayName("rc means before the release, p means after it")
        void sameShapeOppositeMeaning() {
            earlier("1.0rc1", "1.0");
            later("9.6p1", "9.6");
        }

        @Test
        void otherPreReleaseMarkers() {
            earlier("3.0.0-beta", "3.0.0");
            earlier("3.0.0-alpha", "3.0.0-beta");
            earlier("2.5-SNAPSHOT", "2.5");
        }

        /**
         * OpenSSL-style sequence letters are later, not earlier. A single letter
         * must never be treated as a pre-release marker -- 'm' alone appears 8,801
         * times in NVD's version bounds and is almost always this.
         */
        @Test
        @DisplayName("a bare sequence letter means later")
        void opensslStyleLettersAreNotPreReleases() {
            later("1.0.2k", "1.0.2b");
            later("1.0.2m", "1.0.2");
        }

        @Test
        @DisplayName("distro packaging suffixes do not make a version earlier")
        void debianStyleSuffixes() {
            later("8.0.36-1ubuntu1", "8.0.36");
        }

        @Test
        void aNumberOutranksAWord() {
            later("1.2", "1.rc");
        }
    }

    @Nested
    @DisplayName("refusing to answer")
    class Undecidable {

        /** Four such strings exist in the real corpus: "", "-", ".", "]". */
        @Test
        @DisplayName("a string with no digits and no letters is incomparable")
        void degenerateInputReturnsNull() {
            assertNull(VersionOrder.compare("-", "1.0"));
            assertNull(VersionOrder.compare("1.0", "."));
            assertNull(VersionOrder.compare("", "1.0"));
            assertNull(VersionOrder.compare(null, "1.0"));
        }

        /**
         * The safety property. An undecidable comparison must not widen a match:
         * a vulnerability scanner that guesses in favour of a hit manufactures
         * false positives, and a scanner nobody trusts gets switched off.
         */
        @Test
        @DisplayName("an undecidable bound excludes rather than includes")
        void unknownNeverMeansInside() {
            assertFalse(VersionOrder.isWithin("1.0", "-", null, null, null));
            assertFalse(VersionOrder.isWithin("1.0", null, null, "]", null));
        }

        /** Go module pseudo-versions: 1,283 of them appear in NVD's bounds. */
        @Test
        @DisplayName("a component too large for an int does not overflow")
        void hugeNumericComponents() {
            later("0.0.0-20201201191210-20a61371de5b",
                  "0.0.0-20200220183623-bac4c82f6975");
        }
    }

    @Nested
    @DisplayName("range containment")
    class Ranges {

        /**
         * THE test. CVE-2024-6387 is regreSSHion: unauthenticated remote code
         * execution as root. NVD expresses it as
         *
         *     criteria = cpe:2.3:a:openbsd:openssh:*
         *     versionStartIncluding = 8.6
         *     versionEndIncluding   = 9.8
         *
         * There is no row anywhere in NVD saying "openssh:9.6". An implementation
         * that only compares CPE strings for equality cannot see this CVE at all.
         */
        @Test
        @DisplayName("OpenSSH 9.6 falls inside regreSSHion's declared range")
        void regresshionIsFound() {
            assertTrue(VersionOrder.isWithin("9.6", "8.6", null, "9.8", null));
        }

        @Test
        @DisplayName("and so does the p1 form Nmap actually reports")
        void portableReleaseSuffixDoesNotEscapeTheRange() {
            assertTrue(VersionOrder.isWithin("9.6p1", "8.6", null, "9.8", null));
        }

        @Test
        void versionsOutsideTheRangeAreExcluded() {
            assertFalse(VersionOrder.isWithin("8.5", "8.6", null, "9.8", null));
            assertFalse(VersionOrder.isWithin("9.9", "8.6", null, "9.8", null));
        }

        @Test
        @DisplayName("inclusive and exclusive bounds differ at the endpoint")
        void boundaryConditions() {
            assertTrue(VersionOrder.isWithin("9.8", "8.6", null, "9.8", null));
            assertFalse(VersionOrder.isWithin("9.8", "8.6", null, null, "9.8"));
            assertTrue(VersionOrder.isWithin("8.6", "8.6", null, null, null));
            assertFalse(VersionOrder.isWithin("8.6", null, "8.6", null, null));
        }

        @Test
        @DisplayName("an absent bound is open, not zero")
        void openEndedRanges() {
            assertTrue(VersionOrder.isWithin("99.0", "8.6", null, null, null));
            assertTrue(VersionOrder.isWithin("0.1", null, null, null, "4.4"));
        }
    }
}