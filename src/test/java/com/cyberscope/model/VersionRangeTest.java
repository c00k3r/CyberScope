package com.cyberscope.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VersionRangeTest {

    /**
     * The three shapes, in the proportions they occur in real data.
     * Measured across the 224,235 applicability entries in CVE-2024:
     * 73.4% exact, 25.1% ranged, 1.5% unbounded.
     */
    @Test
    @DisplayName("precision is decided by structure, before any version is seen")
    void theThreeClasses() {
        assertEquals(MatchPrecision.VERSION_EXACT,
                VersionRange.exactly("1.24.0").precision());

        assertEquals(MatchPrecision.VERSION_RANGE,
                new VersionRange("*", "8.6", null, "9.8", null).precision());

        assertEquals(MatchPrecision.ALL_VERSIONS,
                VersionRange.allVersions().precision());
    }

    @Test
    @DisplayName("only the unbounded class is flagged weak")
    void weaknessIsAProperty0fTheClass() {
        assertFalse(MatchPrecision.VERSION_EXACT.isWeak());
        assertFalse(MatchPrecision.VERSION_RANGE.isWeak());
        assertTrue(MatchPrecision.ALL_VERSIONS.isWeak());
    }

    @Test
    void blankBoundsAreTreatedAsAbsent() {
        VersionRange range = new VersionRange("*", "", "  ", null, null);
        assertFalse(range.hasBounds());
        assertEquals(MatchPrecision.ALL_VERSIONS, range.precision());
    }

    @Test
    @DisplayName("the report form reads as a constraint, not as JSON")
    void describesItselfForAHuman() {
        assertEquals(">= 8.6, <= 9.8",
                new VersionRange("*", "8.6", null, "9.8", null).describe());
        assertEquals("< 4.4",
                new VersionRange("*", null, null, null, "4.4").describe());
        assertEquals("= 1.24.0", VersionRange.exactly("1.24.0").describe());
        assertEquals("all versions", VersionRange.allVersions().describe());
    }
}