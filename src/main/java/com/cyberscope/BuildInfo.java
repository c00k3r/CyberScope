package com.cyberscope;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * The application's version, read from the build rather than typed in twice.
 *
 * <p>Until v0.4.0 the version lived in a {@code String} constant on {@link App},
 * which meant every release needed the same number edited in two places -- the
 * constant and {@code pom.xml}. That is a synchronisation problem with no
 * mechanism behind it, so it did what those always do: v0.3.1 shipped with a
 * window titled v0.3.0, and nothing failed, because nothing was checking.
 *
 * <p>Maven filters {@code version.properties} at build time and substitutes
 * {@code ${project.version}}. There is now one source of truth and no way for
 * the two to disagree.
 *
 * <p><strong>Only that one file is filtered.</strong> Turning filtering on for
 * the whole resources directory would run {@code app.css} and {@code schema.sql}
 * through the same substitution, which corrupts any file that legitimately
 * contains {@code ${...}} and risks re-encoding anything that is not text.
 */
public final class BuildInfo {

    private static final String RESOURCE = "/version.properties";

    /**
     * Used when the properties file is absent -- running straight from an IDE
     * that compiled without Maven, for instance.
     *
     * <p>Deliberately not a plausible-looking version number. A fallback of
     * "0.0.0" or "unknown" invites someone to report it as the version they are
     * running; "dev" says plainly that this build did not come from Maven.
     */
    private static final String FALLBACK = "dev";

    private static final String VERSION = load();

    private BuildInfo() {
    }

    /** e.g. {@code "0.4.0"}, or {@code "dev"} for a build Maven did not produce. */
    public static String version() {
        return VERSION;
    }

    private static String load() {
        try (InputStream in = BuildInfo.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                return FALLBACK;
            }
            Properties properties = new Properties();
            properties.load(in);
            String value = properties.getProperty("version", "").trim();

            // An unfiltered file still contains the literal placeholder. That
            // means the pom's resource configuration is wrong, and reporting
            // "${project.version}" as the version would be worse than "dev".
            if (value.isEmpty() || value.startsWith("${")) {
                return FALLBACK;
            }
            return value;
        } catch (IOException e) {
            return FALLBACK;
        }
    }
}