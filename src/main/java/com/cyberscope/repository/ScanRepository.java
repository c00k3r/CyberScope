package com.cyberscope.repository;

import com.cyberscope.model.DetectionMethod;
import com.cyberscope.model.Host;
import com.cyberscope.model.HostState;
import com.cyberscope.model.Port;
import com.cyberscope.model.PortState;
import com.cyberscope.model.Protocol;
import com.cyberscope.model.ScanType;
import com.cyberscope.model.Service;
import com.cyberscope.service.scanner.NmapRunResult;
import com.cyberscope.service.scanner.ScanOutcome;
import com.cyberscope.util.TargetKind;
import com.cyberscope.util.ValidatedTarget;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Reads and writes scan history.
 *
 * <p>Every statement is a {@link PreparedStatement}. Values are bound as parameters,
 * never concatenated into SQL text -- which is the actual defence against SQL
 * injection, not escaping.
 *
 * <p>A save writes to three tables and is wrapped in one transaction, so a failure
 * part-way through leaves no half-recorded scan.
 */
public final class ScanRepository {

    /**
     * Lists are stored as newline-delimited text, not space-delimited.
     *
     * <p>A space separator loses information the moment an element contains a space:
     * {@code -oX /home/user name/scan.xml} comes back out as two arguments. No
     * argument CyberScope builds can contain a newline -- paths come from
     * {@code Files.createTempFile} and the target has been through
     * {@link com.cyberscope.util.TargetValidator}, which rejects control characters.
     */
    private static final String LIST_SEPARATOR = "\n";

    private final DatabaseManager database;

    public ScanRepository(DatabaseManager database) {
        this.database = database;
    }

    // ------------------------------------------------------------------ write

    /** Saves a completed scan and returns its new id. */
    public long save(ScanOutcome outcome) throws RepositoryException {
        try (Connection connection = database.connect()) {
            connection.setAutoCommit(false);
            try {
                long sessionId = insertSession(connection, outcome.run());
                for (Host host : outcome.hosts()) {
                    long hostId = insertHost(connection, sessionId, host);
                    for (Port port : host.ports()) {
                        insertPort(connection, hostId, port);
                    }
                }
                connection.commit();
                return sessionId;
            } catch (SQLException e) {
                connection.rollback();
                throw new RepositoryException("Could not save the scan: " + e.getMessage(), e);
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException e) {
            throw new RepositoryException("Could not open the database: " + e.getMessage(), e);
        }
    }

    private long insertSession(Connection connection, NmapRunResult run) throws SQLException {
        String sql = """
                INSERT INTO scan_sessions
                    (target, target_kind, address_count, scan_type, command,
                     started_at, elapsed_ms, warnings)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """;
        try (PreparedStatement ps =
                     connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, run.target().value());
            ps.setString(2, run.target().kind().name());
            ps.setInt(3, run.target().addressCount());
            ps.setString(4, run.scanType().name());
            ps.setString(5, String.join(LIST_SEPARATOR, run.command()));
            ps.setString(6, run.startedAt().toString());   // ISO-8601, UTC
            ps.setLong(7, run.elapsed().toMillis());
            ps.setString(8, run.warnings());
            ps.executeUpdate();
            try (ResultSet keys = ps.getGeneratedKeys()) {
                if (!keys.next()) {
                    throw new SQLException("No id was generated for the scan session");
                }
                return keys.getLong(1);
            }
        }
    }

    private long insertHost(Connection connection, long sessionId, Host host) throws SQLException {
        String sql = "INSERT INTO hosts (session_id, ip_address, hostname, state) "
                   + "VALUES (?, ?, ?, ?)";
        try (PreparedStatement ps =
                     connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setLong(1, sessionId);
            ps.setString(2, host.ipAddress());
            ps.setString(3, host.hostname());
            ps.setString(4, host.state().name());
            ps.executeUpdate();
            try (ResultSet keys = ps.getGeneratedKeys()) {
                if (!keys.next()) {
                    throw new SQLException("No id was generated for the host");
                }
                return keys.getLong(1);
            }
        }
    }

    private void insertPort(Connection connection, long hostId, Port port) throws SQLException {
        String sql = """
                INSERT INTO ports
                    (host_id, number, protocol, state, reason, service_name,
                     product, version, extra_info, cpes, method, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;
        Service service = port.service();
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setLong(1, hostId);
            ps.setInt(2, port.number());
            ps.setString(3, port.protocol().name());
            ps.setString(4, port.state().name());
            ps.setString(5, port.reason());
            ps.setString(6, service.name());
            ps.setString(7, service.product());
            ps.setString(8, service.version());
            ps.setString(9, service.extraInfo());
            ps.setString(10, String.join(LIST_SEPARATOR, service.cpes()));
            ps.setString(11, service.method().name());
            ps.setInt(12, service.confidence());
            ps.executeUpdate();
        }
    }

    // ------------------------------------------------------------------- read

    /** The most recent scans, newest first. */
    public List<ScanSummary> listRecent(int limit) throws RepositoryException {
        String sql = """
                SELECT s.id, s.target, s.scan_type, s.started_at, s.elapsed_ms,
                       (SELECT COUNT(*) FROM hosts h WHERE h.session_id = s.id) AS host_count,
                       (SELECT COUNT(*) FROM ports p
                          JOIN hosts h2 ON p.host_id = h2.id
                         WHERE h2.session_id = s.id AND p.state = 'OPEN') AS open_count
                  FROM scan_sessions s
                 ORDER BY s.started_at DESC, s.id DESC
                 LIMIT ?
                """;
        List<ScanSummary> summaries = new ArrayList<>();
        try (Connection connection = database.connect();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setInt(1, limit);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
    summaries.add(toSummary(rs));
}
            }
        } catch (SQLException e) {
            throw new RepositoryException("Could not list scan history: " + e.getMessage(), e);
        }
        return List.copyOf(summaries);
    }
/**
 * One mapping, used by both listing queries.
 */
private static ScanSummary toSummary(ResultSet rs) throws SQLException {
    return new ScanSummary(
            rs.getLong("id"),
            rs.getString("target"),
            ScanType.valueOf(rs.getString("scan_type")),
            Instant.parse(rs.getString("started_at")),
            Duration.ofMillis(rs.getLong("elapsed_ms")),
            rs.getInt("host_count"),
            rs.getInt("open_count"));
}
/**
 * The most recent scans of one target, newest first.
 */
public List<ScanSummary> findByTarget(String target, int limit) throws RepositoryException {
    String sql = """
            SELECT s.id, s.target, s.scan_type, s.started_at, s.elapsed_ms,
                   (SELECT COUNT(*) FROM hosts h
                      WHERE h.session_id = s.id) AS host_count,
                   (SELECT COUNT(*) FROM ports p
                      JOIN hosts h2 ON p.host_id = h2.id
                     WHERE h2.session_id = s.id AND p.state = 'OPEN') AS open_count
              FROM scan_sessions s
             WHERE s.target = ?
             ORDER BY s.started_at DESC, s.id DESC
             LIMIT ?
            """;

    List<ScanSummary> summaries = new ArrayList<>();

    try (Connection connection = database.connect();
         PreparedStatement ps = connection.prepareStatement(sql)) {

        ps.setString(1, target);
        ps.setInt(2, limit);

        try (ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                summaries.add(toSummary(rs));
            }
        }

    } catch (SQLException e) {
        throw new RepositoryException(
                "Could not list scans of " + target + ": " + e.getMessage(), e);
    }

    return List.copyOf(summaries);
}
    /** Loads one complete scan, or empty if that id does not exist. */
    public Optional<ScanOutcome> load(long id) throws RepositoryException {
        try (Connection connection = database.connect()) {
            NmapRunResult run = loadSession(connection, id);
            if (run == null) {
                return Optional.empty();
            }
            return Optional.of(new ScanOutcome(run, loadHosts(connection, id)));
        } catch (SQLException e) {
            throw new RepositoryException("Could not load scan " + id + ": " + e.getMessage(), e);
        }
    }

    private NmapRunResult loadSession(Connection connection, long id) throws SQLException {
        String sql = "SELECT * FROM scan_sessions WHERE id = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                // Reconstructed from stored fields rather than re-validated. The
                // database is written only by CyberScope and is mode 0600, so it is
                // trusted storage. If an "import a scan file" feature is ever added,
                // that path must validate -- it is a different trust boundary.
                ValidatedTarget target = new ValidatedTarget(
                        rs.getString("target"),
                        TargetKind.valueOf(rs.getString("target_kind")),
                        rs.getInt("address_count"));

                return new NmapRunResult(
                        target,
                        ScanType.valueOf(rs.getString("scan_type")),
                        splitList(rs.getString("command")),
                        "",                                     // XML is not retained
                        Instant.parse(rs.getString("started_at")),
                        Duration.ofMillis(rs.getLong("elapsed_ms")),
                        rs.getString("warnings"));
            }
        }
    }

    private List<Host> loadHosts(Connection connection, long sessionId) throws SQLException {
        String sql = "SELECT * FROM hosts WHERE session_id = ? ORDER BY id";
        List<Host> hosts = new ArrayList<>();
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setLong(1, sessionId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    long hostId = rs.getLong("id");
                    hosts.add(new Host(
                            rs.getString("ip_address"),
                            rs.getString("hostname"),
                            HostState.valueOf(rs.getString("state")),
                            loadPorts(connection, hostId)));
                }
            }
        }
        return hosts;
    }

    private List<Port> loadPorts(Connection connection, long hostId) throws SQLException {
        // ORDER BY id, not ORDER BY number. The repository's job is to return what
        // was stored, in the order it was stored. Sorting by port number looks
        // harmless -- Nmap emits ports in ascending order anyway, so real data is
        // unaffected -- but it makes load(save(x)) != x for any other input, which
        // is a promise this class should not quietly break. Sorting for display is
        // the UI's decision, not storage's.
        String sql = "SELECT * FROM ports WHERE host_id = ? ORDER BY id";
        List<Port> ports = new ArrayList<>();
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setLong(1, hostId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Service service = new Service(
                            rs.getString("service_name"),
                            rs.getString("product"),
                            rs.getString("version"),
                            rs.getString("extra_info"),
                            splitList(rs.getString("cpes")),
                            DetectionMethod.valueOf(rs.getString("method")),
                            rs.getInt("confidence"));

                    ports.add(new Port(
                            rs.getInt("number"),
                            Protocol.valueOf(rs.getString("protocol")),
                            PortState.valueOf(rs.getString("state")),
                            rs.getString("reason"),
                            service));
                }
            }
        }
        return ports;
    }

    /**
     * Splits stored list text back into a list.
     *
     * <p>The blank check is not defensive noise. {@code "".split("\n")} does not
     * return an empty array -- it returns an array of length one holding the empty
     * string, so the naive version yields {@code [""]}, a one-element list that
     * prints as {@code []} and would show a phantom CPE in the UI.
     */
    private static List<String> splitList(String stored) {
        return stored == null || stored.isEmpty()
                ? List.of()
                : List.of(stored.split(LIST_SEPARATOR, -1));
    }

    // ----------------------------------------------------------------- delete

    /** Deletes a scan. Hosts and ports go with it, via ON DELETE CASCADE. */
    public boolean delete(long id) throws RepositoryException {
        try (Connection connection = database.connect();
             PreparedStatement ps =
                     connection.prepareStatement("DELETE FROM scan_sessions WHERE id = ?")) {
            ps.setLong(1, id);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new RepositoryException("Could not delete scan " + id + ": " + e.getMessage(), e);
        }
    }

    public int count() throws RepositoryException {
        try (Connection connection = database.connect();
             PreparedStatement ps =
                     connection.prepareStatement("SELECT COUNT(*) FROM scan_sessions");
             ResultSet rs = ps.executeQuery()) {
            return rs.next() ? rs.getInt(1) : 0;
        } catch (SQLException e) {
            throw new RepositoryException("Could not count scans: " + e.getMessage(), e);
        }
    }
}
