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
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
 
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
 
    /**
     * The schema version this build produces and understands.
     *
     * <p>Bump this and add an entry to {@link #MIGRATION_RESOURCES} together;
     * one without the other is a build that either never migrates or fails
     * looking for a file that does not exist.
     */
    private static final int SCHEMA_VERSION = 1;
 
    private static final Map<Integer, String> MIGRATION_RESOURCES = Map.of(
            1, "/db/migrations/V1__scan_context_and_summaries.sql");
 
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
        applyDdl(readResource(SCHEMA_RESOURCE), "the baseline schema");
        migrate();
        // Scan results name real hosts and their software versions. Owner-only.
        restrictToOwner(databaseFile, "rw-------");
    }
 
    // ------------------------------------------------------------- migrations
 
    /**
     * Brings the database up to {@link #SCHEMA_VERSION}, one migration at a time.
     *
     * <p>The version lives in {@code PRAGMA user_version}, a 32-bit integer that
     * SQLite keeps in the database file's header. It costs nothing, needs no
     * table of its own, and survives every reopen. Verified:
     *
     * <pre>
     *   fresh database user_version : 0
     *   after reopen                : 1
     *   tables matching '%version%' : 0   (it is in the header, not a table)
     * </pre>
     *
     * <p><strong>A new database is migrated too.</strong> {@code schema.sql} is
     * frozen as the v0 baseline and every database, however fresh, walks the
     * same path from 0 to the current version. Shipping an up-to-date
     * {@code schema.sql} and stamping new databases as current would be less
     * code and a worse idea: the migrations would then only ever run on somebody
     * else's older database, on the one day they must not fail, having never
     * executed during development. This way every test run exercises them.
     *
     * <p>Each migration runs inside a transaction and the version is stamped
     * within it, so a failure part-way leaves the database at the version it
     * started from rather than half-upgraded.
     */
    private void migrate() throws RepositoryException {
        try (Connection connection = connect()) {
            int current = readUserVersion(connection);
            if (current > SCHEMA_VERSION) {
                // A newer CyberScope has opened this file. Guessing at a schema
                // from the future is how data gets damaged; refusing is the only
                // safe move, and the message has to say what to do about it.
                throw new RepositoryException(
                        "This database was written by a newer version of CyberScope"
                      + " (schema " + current + ", this build understands " + SCHEMA_VERSION
                      + "). Upgrade CyberScope, or point --db at a different file.");
            }
            for (int next = current + 1; next <= SCHEMA_VERSION; next++) {
                applyMigration(connection, next);
            }
        } catch (SQLException e) {
            throw new RepositoryException("Could not migrate the database: " + e.getMessage(), e);
        }
    }
 
    private void applyMigration(Connection connection, int version)
            throws RepositoryException, SQLException {
        String resource = MIGRATION_RESOURCES.get(version);
        if (resource == null) {
            throw new RepositoryException("No migration defined for schema version " + version);
        }
        String ddl = readResource(resource);
 
        connection.setAutoCommit(false);
        try (Statement statement = connection.createStatement()) {
            for (String piece : splitStatements(ddl)) {
                statement.execute(piece);
            }
            // Stamped inside the transaction: if anything above fails, the
            // rollback takes the version number with it.
            statement.execute("PRAGMA user_version = " + version);
            connection.commit();
        } catch (SQLException e) {
            connection.rollback();
            throw new RepositoryException(
                    "Migration to schema version " + version + " failed and was rolled back: "
                  + e.getMessage(), e);
        } finally {
            connection.setAutoCommit(true);
        }
    }
 
    /** The schema version this build understands. */
    int schemaVersion() throws RepositoryException {
        try (Connection connection = connect()) {
            return readUserVersion(connection);
        } catch (SQLException e) {
            throw new RepositoryException("Could not read the schema version: "
                                        + e.getMessage(), e);
        }
    }
 
    private static int readUserVersion(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery("PRAGMA user_version")) {
            return rs.next() ? rs.getInt(1) : 0;
        }
    }
 
    private void applyDdl(String ddl, String what) throws RepositoryException {
        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {
            for (String piece : splitStatements(ddl)) {
                statement.execute(piece);
            }
        } catch (SQLException e) {
            throw new RepositoryException("Could not apply " + what + ": " + e.getMessage(), e);
        }
    }
 
    /**
     * Splits a DDL script into statements.
     *
     * <p><strong>Comments are stripped first, then the script is split.</strong>
     * The obvious order -- split on {@code ;}, then discard comment lines -- is
     * wrong, and it failed on the very first migration this project shipped.
     * That file contained the sentence:
     *
     * <pre>
     *   -- ...are one fact with a count; a
     *   -- row each would put roughly 25,000 rows...
     * </pre>
     *
     * <p>Splitting first cut the comment in half at that semicolon. The second
     * fragment began {@code " a"}, no longer started with {@code --}, survived
     * the filter, and reached SQLite as a statement:
     * {@code SQL error ... near "a": syntax error}.
     *
     * <p>Still naive in one respect: a semicolon inside a string literal would
     * break it. These scripts ship inside the jar and are written by this
     * project, so that is a bounded risk -- but it is the next thing to fix if a
     * migration ever needs a literal, and it is written down here rather than
     * left as a surprise.
     */
    private static List<String> splitStatements(String ddl) {
        String withoutComments = ddl.lines()
                .map(DatabaseManager::stripLineComment)
                .collect(Collectors.joining("\n"));
 
        List<String> statements = new ArrayList<>();
        for (String piece : withoutComments.split(";")) {
            String cleaned = piece.trim();
            if (!cleaned.isEmpty()) {
                statements.add(cleaned);
            }
        }
        return statements;
    }
 
    /** Removes a trailing {@code --} comment, keeping any SQL before it. */
    private static String stripLineComment(String line) {
        int marker = line.indexOf("--");
        return marker < 0 ? line : line.substring(0, marker);
    }
 
    private String readResource(String resource) throws RepositoryException {
        try (InputStream in = DatabaseManager.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new RepositoryException("Resource not found on the classpath: " + resource);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RepositoryException("Could not read " + resource + ": " + e.getMessage(), e);
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
 
