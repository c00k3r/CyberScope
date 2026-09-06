package com.cyberscope.repository;

import com.cyberscope.model.ScanType;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

/**
 * The handful of choices that survive a restart.
 *
 * <p>A properties file, not a table in the scan database. Two reasons, and the
 * second is the one that matters:
 *
 * <ol>
 *   <li>Preferences are read once at startup and written on a click. A SQLite
 *       schema, a migration and a repository for two keys is machinery without
 *       a job.</li>
 *   <li><b>The scan database is allowed to be missing.</b> That is a documented
 *       property of this application -- a read-only home directory or a corrupt
 *       file costs you history, not scanning. Putting preferences inside it
 *       would make "my database broke" also mean "my settings are gone", which
 *       couples two failures that have nothing to do with each other.</li>
 * </ol>
 *
 * <h2>Every read has a default and no read can throw</h2>
 *
 * A missing file, an unreadable file, a corrupt value, a scan type that was
 * renamed in a later version: all produce the default. Settings are a
 * convenience, and a convenience that can stop the application from starting is
 * a liability. Writes report failure, because a click that silently did nothing
 * is worse than an error.
 */
public final class Preferences {

    static final String DEFAULT_SCAN_TYPE = "scan.defaultType";

    private final Path file;
    private final Properties values = new Properties();

    /** Loads immediately. Never throws: an unreadable file means all defaults. */
    public Preferences(Path file) {
        this.file = file;
        try (InputStream in = Files.newInputStream(file)) {
            values.load(in);
        } catch (IOException | RuntimeException e) {
            // Missing, unreadable or malformed. All three mean "use the defaults",
            // and none of them is worth stopping startup for.
            values.clear();
        }
    }

    public static Path defaultLocation() {
        return Path.of(System.getProperty("user.home"), ".cyberscope", "settings.properties");
    }

    public Path file() {
        return file;
    }

    /**
     * The scan type the Network scan page opens with.
     *
     * <p>Falls back to {@link ScanType#QUICK} for an absent value and for a value
     * that no longer names a real scan type -- which is what happens to a
     * settings file written by a version that had a type this one has since
     * removed. Crashing on someone's old config file is not acceptable behaviour
     * for a preference.
     */
    public ScanType defaultScanType() {
        String stored = values.getProperty(DEFAULT_SCAN_TYPE);
        if (stored == null || stored.isBlank()) {
            return ScanType.QUICK;
        }
        try {
            return ScanType.valueOf(stored.strip());
        } catch (IllegalArgumentException e) {
            return ScanType.QUICK;
        }
    }

    /**
     * Stores the default scan type and writes the file.
     *
     * @throws RepositoryException if the file could not be written -- a click
     *                             that silently did nothing is worse than an error
     */
    public void setDefaultScanType(ScanType type) throws RepositoryException {
        values.setProperty(DEFAULT_SCAN_TYPE, type == null ? ScanType.QUICK.name() : type.name());
        save();
    }

    private void save() throws RepositoryException {
        try {
            Path parent = file.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            try (OutputStream out = Files.newOutputStream(file)) {
                values.store(out, "CyberScope settings. Safe to delete: every value"
                                + " falls back to a documented default.");
            }
        } catch (IOException e) {
            throw new RepositoryException(
                    "Could not save settings to " + file + ": " + e.getMessage(), e);
        }
    }
}
