package com.cyberscope.repository;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Owns the CVE index file: where it lives, how it is opened, and its schema.
 *
 * <p>Deliberately a second database, beside {@code cyberscope.db} rather than
 * inside it. The two have opposite properties:
 *
 * <table>
 *   <caption>Why two files</caption>
 *   <tr><th></th><th>cyberscope.db</th><th>cve-index.db</th></tr>
 *   <tr><td>Contents</td><td>the user's scans -- real hosts, real versions</td>
 *       <td>public NVD data</td></tr>
 *   <tr><td>If lost</td><td>irreplaceable</td><td>re-downloadable in about a minute</td></tr>
 *   <tr><td>Size</td><td>kilobytes</td><td>~330 MB</td></tr>
 *   <tr><td>On corruption</td><td>stop and tell the user</td><td>delete and rebuild</td></tr>
 * </table>
 *
 * <p>That last row is the one that matters. A single file would mean a corrupt
 * CVE index costs the user their scan history, and it would mean the recovery
 * policy for a cache and the recovery policy for irreplaceable data had to be
 * the same policy. They should not be.
 */
public final class CveIndexManager {

    private static final String SCHEMA_RESOURCE = "/db/cve-index-schema.sql";

    /**
     * The schema version this build produces and understands.
     *
     * <p>Bump this and add an entry to {@link #MIGRATION_RESOURCES} together.
     */
    private static final int SCHEMA_VERSION = 1;

    private static final Map<Integer, String> MIGRATION_RESOURCES = Map.of(
            1, "/db/cve-migrations/V1__product_lookup_index.sql");

    private final Path indexFile;

    /**
     * Opens (and creates if needed) the index at the given path.
     *
     * <p>If the file exists but cannot be opened, or carries a schema version
     * this build does not understand, it is <b>deleted and recreated</b> rather
     * than reported as an error. That is safe here and only here: the index is a
     * cache of public data. {@link DatabaseManager} must never do this.
     */
    public CveIndexManager(Path indexFile) throws RepositoryException {
        this.indexFile = indexFile;
        prepareLocation();
        try {
            initialiseSchema();
        } catch (RepositoryException first) {
            // One retry, from a clean file. If that also fails the problem is the
            // filesystem, not the contents, and the caller should hear about it.
            discard();
            initialiseSchema();
        }
    }

    /** The default location: {@code ~/.cyberscope/cve-index.db}. */
    public static Path defaultLocation() {
        return Path.of(System.getProperty("user.home"), ".cyberscope", "cve-index.db");
    }

    public Path indexFile() {
        return indexFile;
    }

    /** Bytes on disk, or 0 if the file is missing. */
    public long sizeOnDisk() {
        try {
            return Files.exists(indexFile) ? Files.size(indexFile) : 0L;
        } catch (IOException e) {
            return 0L;
        }
    }

    /**
     * Opens a connection with foreign keys enforced.
     *
     * <p>SQLite has foreign key enforcement <em>off</em> by default and the
     * setting is per connection, not per database -- so the REFERENCES clause in
     * the schema is decorative until each connection turns it on. Same reasoning,
     * and the same trap, as {@link DatabaseManager#connect()}.
     */
    Connection connect() throws SQLException {
        Connection connection =
                DriverManager.getConnection("jdbc:sqlite:" + indexFile.toAbsolutePath());
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA foreign_keys = ON");
        } catch (SQLException e) {
            connection.close();
            throw e;
        }
        return connection;
    }

    /** Deletes the index file. The next construction rebuilds an empty one. */
    public void discard() throws RepositoryException {
        try {
            Files.deleteIfExists(indexFile);
        } catch (IOException e) {
            throw new RepositoryException(
                    "Could not delete the CVE index at " + indexFile + ": " + e.getMessage(), e);
        }
    }

    private void prepareLocation() throws RepositoryException {
        try {
            Path directory = indexFile.getParent();
            if (directory != null) {
                Files.createDirectories(directory);
            }
        } catch (IOException e) {
            throw new RepositoryException(
                    "Could not create the CVE index directory: " + e.getMessage(), e);
        }
    }

    private void initialiseSchema() throws RepositoryException {
        applyDdl(readResource(SCHEMA_RESOURCE), "the CVE index baseline schema");
        migrate();
    }

    // ------------------------------------------------------------- migrations

    private void migrate() throws RepositoryException {
        int current = schemaVersion();
        if (current > SCHEMA_VERSION) {
            throw new RepositoryException(
                    "The CVE index was written by a newer CyberScope (schema " + current
                    + ", this build understands " + SCHEMA_VERSION + ").");
        }
        for (int next = current + 1; next <= SCHEMA_VERSION; next++) {
            String resource = MIGRATION_RESOURCES.get(next);
            if (resource == null) {
                throw new RepositoryException("No migration script for CVE index schema " + next);
            }
            applyDdl(readResource(resource), "CVE index migration " + next);
            setSchemaVersion(next);
        }
    }

    int schemaVersion() throws RepositoryException {
        try (Connection connection = connect();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery("PRAGMA user_version")) {
            return rs.next() ? rs.getInt(1) : 0;
        } catch (SQLException e) {
            throw new RepositoryException("Could not read the CVE index schema version: "
                                          + e.getMessage(), e);
        }
    }

    private void setSchemaVersion(int version) throws RepositoryException {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            // PRAGMA does not accept a bound parameter, so the value is
            // interpolated. It is an int from a private constant, never input.
            statement.execute("PRAGMA user_version = " + version);
        } catch (SQLException e) {
            throw new RepositoryException("Could not set the CVE index schema version: "
                                          + e.getMessage(), e);
        }
    }

    // ------------------------------------------------------------- DDL

    /**
     * Runs a script as one transaction.
     *
     * <p>Comments are stripped <em>before</em> splitting on semicolons, not
     * after. The other order breaks on a semicolon inside a comment -- which is
     * exactly the bug this project shipped and caught during v0.4.0.
     */
    private void applyDdl(String script, String what) throws RepositoryException {
        List<String> statements = splitStatements(script);
        try (Connection connection = connect()) {
            connection.setAutoCommit(false);
            try (Statement statement = connection.createStatement()) {
                for (String sql : statements) {
                    statement.execute(sql);
                }
                connection.commit();
            } catch (SQLException e) {
                connection.rollback();
                throw e;
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException e) {
            throw new RepositoryException("Could not apply " + what + ": " + e.getMessage(), e);
        }
    }

    static List<String> splitStatements(String script) {
        StringBuilder withoutComments = new StringBuilder(script.length());
        for (String line : script.split("\n")) {
            int comment = line.indexOf("--");
            withoutComments.append(comment >= 0 ? line.substring(0, comment) : line).append('\n');
        }
        List<String> statements = new ArrayList<>();
        for (String candidate : withoutComments.toString().split(";")) {
            String trimmed = candidate.trim();
            if (!trimmed.isEmpty()) {
                statements.add(trimmed);
            }
        }
        return statements;
    }

    private static String readResource(String name) throws RepositoryException {
        try (InputStream in = CveIndexManager.class.getResourceAsStream(name)) {
            if (in == null) {
                throw new RepositoryException("Missing resource on the classpath: " + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RepositoryException("Could not read " + name + ": " + e.getMessage(), e);
        }
    }
}