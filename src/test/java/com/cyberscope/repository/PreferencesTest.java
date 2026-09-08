package com.cyberscope.repository;

import com.cyberscope.model.ScanType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Settings are a convenience. A convenience that can stop the application from
 * starting is a liability, so every read here has a default and no read throws.
 */
class PreferencesTest {

    @TempDir
    Path directory;

    @Test
    @DisplayName("a missing file is all defaults, not an error")
    void missingFileIsFine() {
        Preferences preferences = new Preferences(directory.resolve("absent.properties"));
        assertEquals(ScanType.QUICK, preferences.defaultScanType());
    }

    @Test
    @DisplayName("a value survives a restart")
    void valuesRoundTrip() throws Exception {
        Path file = directory.resolve("settings.properties");
        new Preferences(file).setDefaultScanType(ScanType.STANDARD);

        assertAll(
                () -> assertTrue(Files.exists(file)),
                () -> assertEquals(ScanType.STANDARD, new Preferences(file).defaultScanType()));
    }

    @Test
    @DisplayName("the parent directory is created if it does not exist")
    void createsItsOwnDirectory() throws Exception {
        Path nested = directory.resolve("a/b/c/settings.properties");
        new Preferences(nested).setDefaultScanType(ScanType.STANDARD);
        assertTrue(Files.exists(nested));
    }

    @Test
    @DisplayName("a scan type this version does not have falls back to the default")
    void unknownScanTypeFallsBack() throws Exception {
        // Exactly what a settings file written by a later version looks like, or
        // one hand-edited by a curious user. Crashing on it is not acceptable.
        Path file = directory.resolve("settings.properties");
        Files.writeString(file, Preferences.DEFAULT_SCAN_TYPE + "=STEALTH_ULTRA\n");

        assertEquals(ScanType.QUICK, new Preferences(file).defaultScanType());
    }

    @Test
    @DisplayName("a file of binary junk is all defaults, not an exception")
    void binaryJunkFallsBack() throws Exception {
        Path file = directory.resolve("settings.properties");
        Files.write(file, new byte[] {0x00, (byte) 0xFF, 0x00, (byte) 0xFE, 0x00});

        assertEquals(ScanType.QUICK, new Preferences(file).defaultScanType());
    }

    @Test
    @DisplayName("a malformed unicode escape is all defaults, not an exception")
    void malformedEscapeFallsBack() throws Exception {
        // The binary-junk case above does NOT exercise the RuntimeException path:
        // Properties.load reads ISO-8859-1, where every byte is a valid character,
        // so it produces a garbage key and returns normally. Mutation testing
        // caught that -- removing the RuntimeException from the catch clause broke
        // no test. THIS is what actually throws: Properties.load raises
        // IllegalArgumentException("Malformed \\uxxxx encoding") on a bad escape,
        // which is an unchecked exception and would otherwise propagate out of a
        // constructor called during startup.
        Path file = directory.resolve("settings.properties");
        Files.writeString(file, Preferences.DEFAULT_SCAN_TYPE + "=\\uZZZZ\n");

        assertEquals(ScanType.QUICK, new Preferences(file).defaultScanType(),
                "an unchecked exception from a settings file must not reach startup");
    }

    @Test
    @DisplayName("a blank value falls back rather than throwing")
    void blankValueFallsBack() throws Exception {
        Path file = directory.resolve("settings.properties");
        Files.writeString(file, Preferences.DEFAULT_SCAN_TYPE + "=\n");

        assertEquals(ScanType.QUICK, new Preferences(file).defaultScanType());
    }

    @Test
    @DisplayName("null is stored as the default, never as a null property")
    void nullIsNormalised() throws Exception {
        Path file = directory.resolve("settings.properties");
        Preferences preferences = new Preferences(file);
        preferences.setDefaultScanType(null);

        assertEquals(ScanType.QUICK, new Preferences(file).defaultScanType());
    }

    @Test
    @DisplayName("a write that cannot succeed reports it rather than failing silently")
    void unwritableLocationThrows() throws Exception {
        // A directory where the file should be: open() fails, and a click that
        // silently did nothing is worse than an error the user can see.
        Path blocked = directory.resolve("blocked.properties");
        Files.createDirectory(blocked);

        Preferences preferences = new Preferences(blocked);
        assertThrows(RepositoryException.class,
                () -> preferences.setDefaultScanType(ScanType.STANDARD));
    }

    @Test
    @DisplayName("the file it reads is the file it reports")
    void exposesItsOwnPath() {
        Path file = directory.resolve("settings.properties");
        assertEquals(file, new Preferences(file).file(),
                "the Settings page prints this path; it must be the real one");
    }

    // ------------------------------------------------------------------
    // window geometry
    // ------------------------------------------------------------------

    @Test
    @DisplayName("no window has been saved yet")
    void windowIsAbsentByDefault() {
        Preferences preferences = new Preferences(directory.resolve("absent.properties"));
        assertAll(
                () -> assertNull(preferences.window()),
                () -> assertFalse(preferences.windowMaximized()));
    }

    @Test
    @DisplayName("window geometry survives a restart")
    void windowRoundTrips() throws Exception {
        Path file = directory.resolve("settings.properties");
        new Preferences(file).setWindow(120, 60, 1400, 820, false);

        assertArrayEquals(new double[] {120, 60, 1400, 820},
                new Preferences(file).window());
    }

    @Test
    @DisplayName("the maximized flag is stored separately from the size")
    void maximizedIsItsOwnFact() throws Exception {
        // The restored size is saved alongside maximized=true precisely so that
        // un-maximizing after a restart returns the window to the size the user
        // chose, rather than to the size of the screen.
        Path file = directory.resolve("settings.properties");
        new Preferences(file).setWindow(200, 100, 1180, 680, true);

        Preferences reread = new Preferences(file);
        assertAll(
                () -> assertTrue(reread.windowMaximized()),
                () -> assertArrayEquals(new double[] {200, 100, 1180, 680}, reread.window()));
    }

    @Test
    @DisplayName("partial geometry is no geometry")
    void partialGeometryIsRejected() throws Exception {
        // Half from the file and half from the default is a window position
        // nobody chose. All four values or none.
        Path file = directory.resolve("settings.properties");
        Files.writeString(file, Preferences.WINDOW_X + "=100\n"
                              + Preferences.WINDOW_Y + "=100\n"
                              + Preferences.WINDOW_WIDTH + "=1180\n");

        assertNull(new Preferences(file).window(), "the height is missing");
    }

    @Test
    @DisplayName("a value Double.parseDouble accepts can still be unusable")
    void nonFiniteValuesAreRejected() throws Exception {
        // parseDouble("NaN") and parseDouble("Infinity") both succeed, and
        // "1e400" parses to Infinity rather than throwing. This is the settings
        // file a user can open in a text editor, so the values that get through
        // the parser are exactly the ones that have to be checked afterwards.
        for (String bad : new String[] {"NaN", "Infinity", "-Infinity", "1e400", "wide"}) {
            Path file = directory.resolve(bad.replaceAll("\\W", "") + ".properties");
            Files.writeString(file, Preferences.WINDOW_X + "=100\n"
                                  + Preferences.WINDOW_Y + "=100\n"
                                  + Preferences.WINDOW_WIDTH + "=" + bad + "\n"
                                  + Preferences.WINDOW_HEIGHT + "=680\n");

            assertNull(new Preferences(file).window(),
                    "width=" + bad + " was allowed through to the stage");
        }
    }

    @Test
    @DisplayName("a non-finite geometry is refused rather than rounded to zero")
    void refusesToSaveNonFinite() {
        // Math.round(NaN) is 0, so without the guard an unshown stage would be
        // persisted as a plausible-looking window at the origin with no size --
        // and it would read back clean.
        Preferences preferences = new Preferences(directory.resolve("settings.properties"));
        assertThrows(IllegalArgumentException.class,
                () -> preferences.setWindow(Double.NaN, 0, 1180, 680, false));
    }

    @Test
    @DisplayName("a corrupt window entry does not take the scan type down with it")
    void oneBadValueDoesNotPoisonTheRest() throws Exception {
        Path file = directory.resolve("settings.properties");
        Files.writeString(file, Preferences.DEFAULT_SCAN_TYPE + "=STANDARD\n"
                              + Preferences.WINDOW_X + "=not-a-number\n");

        Preferences preferences = new Preferences(file);
        assertAll(
                () -> assertEquals(ScanType.STANDARD, preferences.defaultScanType()),
                () -> assertNull(preferences.window()));
    }
}
