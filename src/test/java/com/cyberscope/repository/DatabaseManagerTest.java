package com.cyberscope.repository;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DatabaseManagerTest {

    @TempDir
    Path directory;

    /**
     * The single most important fact about SQLite in this project: foreign key
     * enforcement is OFF by default and the setting lives on the connection, not
     * the database. A schema full of REFERENCES and ON DELETE CASCADE does nothing
     * on a connection that forgot the pragma -- deletes silently orphan their
     * children. This test fails the moment someone opens a connection elsewhere.
     */
    @Test
    @DisplayName("every connection has foreign keys enforced")
    void everyConnectionEnablesForeignKeys() throws Exception {
        DatabaseManager manager = new DatabaseManager(directory.resolve("fk.db"));

        for (int i = 0; i < 3; i++) {
            try (Connection connection = manager.connect();
                 Statement statement = connection.createStatement();
                 ResultSet rs = statement.executeQuery("PRAGMA foreign_keys")) {
                assertTrue(rs.next());
                assertEquals(1, rs.getInt(1), "connection " + i + " had foreign keys off");
            }
        }
    }

    @Test
    @DisplayName("an orphan row is rejected, not accepted")
    void foreignKeysActuallyRejectOrphans() throws Exception {
        DatabaseManager manager = new DatabaseManager(directory.resolve("orphan.db"));

        try (Connection connection = manager.connect();
             Statement statement = connection.createStatement()) {
            SQLException thrown = assertThrows(SQLException.class, () -> statement.execute(
                    "INSERT INTO hosts (session_id, ip_address, hostname, state) "
                  + "VALUES (999, '10.0.0.1', '', 'UP')"));
            assertTrue(thrown.getMessage().contains("FOREIGN KEY"),
                    "expected a foreign key violation, got: " + thrown.getMessage());
        }
    }

    @Test
    @DisplayName("opening an existing database does not wipe it")
    void theSchemaIsIdempotent() throws Exception {
        Path file = directory.resolve("reopen.db");
        DatabaseManager first = new DatabaseManager(file);
        try (Connection connection = first.connect();
             Statement statement = connection.createStatement()) {
            statement.execute("""
                    INSERT INTO scan_sessions
                      (target, target_kind, address_count, scan_type, command,
                       started_at, elapsed_ms, warnings)
                    VALUES ('10.0.0.1','IPV4',1,'QUICK','nmap 10.0.0.1',
                            '2026-08-20T00:00:00Z', 1000, '')
                    """);
        }

        DatabaseManager second = new DatabaseManager(file);      // CREATE TABLE IF NOT EXISTS
        try (Connection connection = second.connect();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery("SELECT COUNT(*) FROM scan_sessions")) {
            assertTrue(rs.next());
            assertEquals(1, rs.getInt(1), "reopening the database lost existing rows");
        }
    }

    /**
     * Scan results name real hosts and the exact software versions they run. That
     * is reconnaissance data about someone's network, so the file is owner-only.
     * Skipped where POSIX permissions do not exist rather than asserted falsely.
     */
    @Test
    @DisplayName("the database file is readable only by its owner")
    void theDatabaseFileIsOwnerOnly() throws Exception {
        Path file = directory.resolve("perms.db");
        new DatabaseManager(file);

        if (!Files.getFileStore(file).supportsFileAttributeView("posix")) {
            return;
        }
        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(file);
        assertEquals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                permissions, "the database was world- or group-readable");
    }

    @Test
    @DisplayName("an unusable location fails with a clear message, not a stack trace")
    void anUncreatableDirectoryIsReported() {
        RepositoryException thrown = assertThrows(RepositoryException.class,
                () -> new DatabaseManager(Path.of("/proc/definitely-not-here/scans.db")));
        assertTrue(thrown.getMessage().toLowerCase().contains("director"),
                "unhelpful message: " + thrown.getMessage());
    }
}