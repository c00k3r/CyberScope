package com.cyberscope.repository;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Set;

/**
 * Owns the SQLite database file: where it lives, how it is opened, and its schema.
 *
 * <p>Every connection enables {@code PRAGMA foreign_keys}. SQLite has foreign key
 * enforcement <em>off</em> by default and the setting is per connection, not per
 * database -- so a schema full of REFERENCES and ON DELETE CASCADE clauses is
 * decorative until each connection turns it on.
 */
public final class DatabaseManager {

    private static final String SCHEMA_RESOURCE = "/db/schema.sql";

    private final Path databaseFile;

    /** Opens (and creates if needed) the database at the given path. */
    public DatabaseManager(Path databaseFile) throws RepositoryException {
        this.databaseFile = databaseFile;
        prepareLocation();
        initialiseSchema();
    }

    /** The default location: {@code ~/.cyberscope/cyberscope.db}. */
    public static Path defaultLocation() {
        return Path.of(System.getProperty("user.home"), ".cyberscope", "cyberscope.db");
    }

    public Path databaseFile() {
        return databaseFile;
    }

    /**
     * Opens a connection with foreign keys enforced.
     *
     * <p>The pragma is applied here rather than once at startup precisely because it
     * is connection-scoped: a connection opened anywhere else would silently lose it.
     */
    Connection connect() throws SQLException {
        Connection connection =
                DriverManager.getConnection("jdbc:sqlite:" + databaseFile.toAbsolutePath());
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA foreign_keys = ON");
        } catch (SQLException e) {
            connection.close();
            throw e;
        }
        return connection;
    }

    private void prepareLocation() throws RepositoryException {
        try {
            Path directory = databaseFile.getParent();
            if (directory != null) {
                Files.createDirectories(directory);
                restrictToOwner(directory, "rwx------");
            }
        } catch (IOException e) {
            throw new RepositoryException(
                    "Could not create the database directory: " + e.getMessage(), e);
        }
    }

    private void initialiseSchema() throws RepositoryException {
        String schema = readSchema();
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            for (String ddl : schema.split(";")) {
                if (!ddl.isBlank()) {
                    statement.execute(ddl);
                }
            }
        } catch (SQLException e) {
            throw new RepositoryException("Could not initialise the schema: " + e.getMessage(), e);
        }
        // Scan results name real hosts and their software versions. Owner-only.
        restrictToOwner(databaseFile, "rw-------");
    }

    private String readSchema() throws RepositoryException {
        try (InputStream in = DatabaseManager.class.getResourceAsStream(SCHEMA_RESOURCE)) {
            if (in == null) {
                throw new RepositoryException("Schema resource not found: " + SCHEMA_RESOURCE);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RepositoryException("Could not read the schema: " + e.getMessage(), e);
        }
    }

    /** Best effort: POSIX permissions do not exist on every filesystem. */
    private static void restrictToOwner(Path path, String permissions) {
        try {
            Set<PosixFilePermission> wanted = PosixFilePermissions.fromString(permissions);
            Files.setPosixFilePermissions(path, wanted);
        } catch (IOException | UnsupportedOperationException ignored) {
            // Windows and some mounts have no POSIX permissions. Not fatal.
        }
    }
}
