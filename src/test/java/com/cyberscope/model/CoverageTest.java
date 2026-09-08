package com.cyberscope.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The figure that qualifies every other figure, and the one case where it is
 * not a figure at all.
 *
 * <p>{@code Coverage} was exercised only through {@code PostureScorer} until
 * v0.7.0. It got its own test when {@link Coverage#isMeasured()} was added,
 * because that method exists to stop a rendering bug and a rule with no test is
 * a rule that comes back.
 */
class CoverageTest {

    @Test
    @DisplayName("checked cannot exceed examined, and neither can be negative")
    void impossibleCountsAreRejected() {
        assertAll(
                () -> assertThrows(IllegalArgumentException.class, () -> new Coverage(5, 3)),
                () -> assertThrows(IllegalArgumentException.class, () -> new Coverage(-1, 3)),
                () -> assertThrows(IllegalArgumentException.class, () -> new Coverage(0, -1)));
    }

    @Test
    @DisplayName("the fraction, and the divide-by-zero convention")
    void fractionHandlesTheEmptyCase() {
        assertAll(
                () -> assertEquals(0.5, new Coverage(4, 8).fraction()),
                () -> assertEquals(1.0, new Coverage(0, 0).fraction(),
                        "a host with no open services missed nothing, "
                      + "because there was nothing to miss"));
    }

    @Test
    @DisplayName("1.0 from an empty coverage is a convention, not a measurement")
    void nothingExaminedIsNotFullCoverage() {
        // This distinction is the whole reason the method exists. The dashboard
        // rendered Coverage.NONE as a full green ring reading 100% next to the
        // words "no scans yet" -- a divide-by-zero fallback presented as a clean
        // bill of health, which is the exact claim this project refuses to make.
        Coverage nothing = Coverage.NONE;
        assertAll(
                () -> assertEquals(1.0, nothing.fraction()),
                () -> assertEquals(100, nothing.percent()),
                () -> assertTrue(nothing.isAdequate()),
                () -> assertFalse(nothing.isMeasured(),
                        "every one of the three answers above is reassuring, and none "
                      + "of them is based on anything; isMeasured is what a display "
                      + "asks before it prints them"));
    }

    @Test
    @DisplayName("one examined service is enough to be measured")
    void oneServiceIsMeasured() {
        assertAll(
                () -> assertTrue(new Coverage(0, 1).isMeasured(),
                        "0 of 1 checked is a real answer -- and it is 0%, not 100%"),
                () -> assertEquals(0, new Coverage(0, 1).percent()),
                () -> assertTrue(new Coverage(1, 1).isMeasured()));
    }

    @Test
    @DisplayName("adequacy is a judgement written down, at 80%")
    void adequacySitsAtTheDocumentedThreshold() {
        assertAll(
                () -> assertEquals(0.80, Coverage.ADEQUATE),
                () -> assertTrue(new Coverage(8, 10).isAdequate(), "exactly at the line"),
                () -> assertFalse(new Coverage(79, 100).isAdequate()),
                () -> assertTrue(new Coverage(80, 100).isAdequate()));
    }

    @Test
    @DisplayName("describe() never says '0 of 0 services checked'")
    void describeHandlesTheEmptyCase() {
        assertAll(
                () -> assertEquals("no open services", Coverage.NONE.describe()),
                () -> assertEquals("1 of 1 service checked", new Coverage(1, 1).describe()),
                () -> assertEquals("8 of 14 services checked", new Coverage(8, 14).describe()));
    }

    @Test
    @DisplayName("unchecked is the remainder, and completeness does not imply coverage")
    void uncheckedAndCompleteness() {
        assertAll(
                () -> assertEquals(6, new Coverage(8, 14).unchecked()),
                () -> assertTrue(new Coverage(3, 3).isComplete()),
                () -> assertFalse(new Coverage(2, 3).isComplete()),
                () -> assertTrue(Coverage.NONE.isComplete(),
                        "vacuously complete, which is why isMeasured has to be asked "
                      + "separately"));
    }
}
