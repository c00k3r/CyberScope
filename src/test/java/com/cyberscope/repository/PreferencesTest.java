package com.cyberscope.repository;

import com.cyberscope.model.ScanType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
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
}
