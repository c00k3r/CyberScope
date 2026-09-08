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

    static final String WINDOW_X = "window.x";
    static final String WINDOW_Y = "window.y";
    static final String WINDOW_WIDTH = "window.width";
    static final String WINDOW_HEIGHT = "window.height";
    static final String WINDOW_MAXIMIZED = "window.maximized";

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

    /**
     * The window geometry last saved, as {@code {x, y, width, height}}.
     *
     * <p>Returns {@code null} when nothing is stored <b>or when any of the four
     * values is unreadable</b>. Partial geometry is not usable: a width with no
     * height, or an x that parsed next to a y that did not, would place a window
     * half from the file and half from the default, which is a position nobody
     * chose. All four or none.
     *
     * <p>What counts as "readable" is deliberately narrow -- a finite number.
     * The value is a string in a text file the user can edit, so
     * {@code NaN}, {@code Infinity} and {@code 1e400} are all things
     * {@code Double.parseDouble} accepts and this method must not return.
     * {@link com.cyberscope.model.ScanType} aside, this is the only preference
     * whose bad value can produce an invisible window.
     */
    public double[] window() {
        double x = number(WINDOW_X);
        double y = number(WINDOW_Y);
        double width = number(WINDOW_WIDTH);
        double height = number(WINDOW_HEIGHT);
        if (Double.isNaN(x) || Double.isNaN(y)
                || Double.isNaN(width) || Double.isNaN(height)) {
            return null;
        }
        return new double[] {x, y, width, height};
    }

    /** Whether the window was maximized when it was last closed. */
    public boolean windowMaximized() {
        return Boolean.parseBoolean(values.getProperty(WINDOW_MAXIMIZED, "false"));
    }

    /** {@link Double#NaN} for absent, unparseable, or non-finite. */
    private double number(String key) {
        String stored = values.getProperty(key);
        if (stored == null || stored.isBlank()) {
            return Double.NaN;
        }
        try {
            double parsed = Double.parseDouble(stored.strip());
            return Double.isFinite(parsed) ? parsed : Double.NaN;
        } catch (NumberFormatException e) {
            return Double.NaN;
        }
    }

    /**
     * Stores where the window was, and writes the file.
     *
     * <p>{@code maximized} is kept separately from the four numbers, and the
     * numbers passed in must be the <b>restored</b> bounds rather than the
     * maximized ones. Saving the maximized size as the plain size is a
     * well-known bug in this feature: the window re-opens filling the screen but
     * not actually maximized, and un-maximizing it does nothing visible because
     * its restored size is already the size of the screen.
     */
    public void setWindow(double x, double y, double width, double height,
                          boolean maximized) throws RepositoryException {
        // Math.round(NaN) is 0, so an unshown or half-initialised stage would
        // otherwise be persisted as a legitimate-looking window at the origin
        // with no size. Refuse rather than write a value that reads back clean.
        if (!Double.isFinite(x) || !Double.isFinite(y)
                || !Double.isFinite(width) || !Double.isFinite(height)) {
            throw new IllegalArgumentException(
                    "window geometry must be finite: " + x + "," + y
                  + " " + width + "x" + height);
        }
        values.setProperty(WINDOW_X, String.valueOf(Math.round(x)));
        values.setProperty(WINDOW_Y, String.valueOf(Math.round(y)));
        values.setProperty(WINDOW_WIDTH, String.valueOf(Math.round(width)));
        values.setProperty(WINDOW_HEIGHT, String.valueOf(Math.round(height)));
        values.setProperty(WINDOW_MAXIMIZED, String.valueOf(maximized));
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
