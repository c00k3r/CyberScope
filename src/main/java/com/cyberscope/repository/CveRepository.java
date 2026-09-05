package com.cyberscope.repository;

import com.cyberscope.model.ExploitSignal;
import com.cyberscope.model.KevStatus;
import com.cyberscope.model.VersionRange;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * The only place CVE SQL exists.
 *
 * <p>Every lookup is keyed on {@code (vendor, product)} and returns every
 * applicability statement for that pair. Version filtering happens above this
 * class, in {@code service/vuln/}, because it needs
 * {@code util.VersionOrder} -- and pushing a Java comparator into a SQL WHERE
 * clause is not possible without either a stored function or storing versions in
 * a comparable normalised form, which would mean deciding the comparison rules
 * at index-build time and freezing them into 2.09 million rows.
 *
 * <p>Measured cost of doing it this way: 1.2 ms per lookup against the full
 * 2,093,452-row index, and the largest single product (openbsd:openssh) returns
 * 1,208 rows. Filtering 1,208 records in Java is free. The alternative buys
 * nothing and costs flexibility.
 *
 * <p>Exploitation information is deliberately joined with {@code LEFT JOIN}s.
 * EPSS and KEV are enrichment data: a CVE without either feed must still appear
 * in the report. An INNER JOIN would silently remove those CVEs.
 */
public final class CveRepository implements CveLookup {

    private final CveIndexManager manager;

    public CveRepository(CveIndexManager manager) {
        this.manager = manager;
    }

    /**
     * Every applicability statement filed against {@code vendor:product}.
     *
     * <p>Both arguments must already be normalised the way {@code model.Cpe}
     * normalises them -- unescaped and lower-cased. Passing a raw CPE field here
     * is the kind of mistake that returns an empty list rather than an error,
     * which is why {@code Cpe} does the normalising and this method takes its
     * output rather than a string from anywhere.
     *
     * @return possibly empty; never null. An empty list is a real answer -- it
     *         means NVD has nothing filed under that vendor:product, which is the
     *         {@code UNRESOLVED} case Part 3 reports out loud
     */
    @Override
    public List<CveMatchRow> findByProduct(String vendor, String product)
            throws RepositoryException {

        String sql = """
                SELECT m.cve_id, m.vendor, m.product, m.version,
                       m.start_incl, m.start_excl, m.end_incl, m.end_excl,
                       c.cvss_score, c.cvss_severity, c.cvss_vector, c.cvss_version,
                       c.published, c.description,
                       e.score AS epss, e.percentile AS epss_pct,
                       k.ransomware, 
                       k.date_added AS kev_added, 
                       k.due_date AS kev_due,
                       k.cve_id AS kev_present
                  FROM cve_match m
                  JOIN cve c ON c.id = m.cve_id
                  LEFT JOIN cve_epss e ON e.cve_id = m.cve_id
                  LEFT JOIN cve_kev k ON k.cve_id = m.cve_id
                 WHERE m.vendor = ? AND m.product = ?
                """;

        List<CveMatchRow> rows = new ArrayList<>();

        try (Connection connection = manager.connect();
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setString(1, vendor);
            statement.setString(2, product);

            try (ResultSet rs = statement.executeQuery()) {
                while (rs.next()) {
                    rows.add(toRow(rs));
                }
            }

        } catch (SQLException e) {
            throw new RepositoryException(
                    "Could not query the CVE index for "
                    + vendor + ":" + product
                    + ": " + e.getMessage(), e);
        }

        return rows;
    }

    /**
     * True when the index has been built and contains data.
     */
    @Override
    public boolean isPopulated() throws RepositoryException {
        try (Connection connection = manager.connect();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(
                     "SELECT EXISTS(SELECT 1 FROM cve_match)")) {

            return rs.next() && rs.getInt(1) == 1;

        } catch (SQLException e) {
            throw new RepositoryException(
                    "Could not read the CVE index: " + e.getMessage(), e);
        }
    }

    /**
     * What the index is and how old, or empty if it has never been built.
     */
    public Optional<IndexMetadata> metadata() throws RepositoryException {
        String sql = """
                SELECT feed_timestamp, built_at, source, cve_count, match_count,
                       first_year, last_year
                  FROM index_metadata
                 WHERE id = 1
                """;

        try (Connection connection = manager.connect();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(sql)) {

            if (!rs.next()) {
                return Optional.empty();
            }

            return Optional.of(new IndexMetadata(
                    parseInstant(rs.getString("feed_timestamp")),
                    parseInstant(rs.getString("built_at")),
                    rs.getString("source"),
                    rs.getInt("cve_count"),
                    rs.getInt("match_count"),
                    rs.getInt("first_year"),
                    rs.getInt("last_year")));

        } catch (SQLException e) {
            throw new RepositoryException(
                    "Could not read the CVE index metadata: "
                    + e.getMessage(), e);
        }
    }

    /**
     * What one exploitation feed holds and how old it is,
     * or empty if it has never been loaded.
     */
    public Optional<FeedMetadata> feedMetadata(String source)
            throws RepositoryException {

        String sql = """
                SELECT source, fetched_at, source_timestamp, record_count, source_url
                  FROM feed_metadata
                 WHERE source = ?
                """;

        try (Connection connection = manager.connect();
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setString(1, source);

            try (ResultSet rs = statement.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }

                return Optional.of(new FeedMetadata(
                        rs.getString("source"),
                        parseInstant(rs.getString("fetched_at")),
                        parseInstant(rs.getString("source_timestamp")),
                        rs.getInt("record_count"),
                        rs.getString("source_url")));
            }

        } catch (SQLException e) {
            throw new RepositoryException(
                    "Could not read the " + source
                    + " feed metadata: " + e.getMessage(), e);
        }
    }

    /**
     * True when exploitation data has been loaded at all.
     *
     * <p>This checks EPSS specifically. A populated CVE index without an EPSS
     * feed is therefore distinguishable from an index that has exploitation
     * enrichment loaded.
     */
    public boolean hasExploitSignals() throws RepositoryException {
        try (Connection connection = manager.connect();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(
                     "SELECT EXISTS(SELECT 1 FROM cve_epss)")) {

            return rs.next() && rs.getInt(1) == 1;

        } catch (SQLException e) {
            throw new RepositoryException(
                    "Could not read exploitation data: "
                    + e.getMessage(), e);
        }
    }

    /**
     * How many distinct products the index knows about.
     * Used by the status output.
     */
    public int productCount() throws RepositoryException {
        try (Connection connection = manager.connect();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(
                     "SELECT COUNT(*) FROM " +
                     "(SELECT DISTINCT vendor, product FROM cve_match)")) {

            return rs.next() ? rs.getInt(1) : 0;

        } catch (SQLException e) {
            throw new RepositoryException(
                    "Could not count products: " + e.getMessage(), e);
        }
    }

    /**
 * Converts one SQL row into the repository's flat result object.
 *
 * <p>The EPSS and KEV columns come from LEFT JOINs, so SQL NULL has to remain
 * distinguishable from a legitimate EPSS value of 0.0. JDBC otherwise
 * returns 0.0 for both.
 */
private static CveMatchRow toRow(ResultSet rs) throws SQLException {

    double score = rs.getDouble("cvss_score");
    Double boxedScore = rs.wasNull() ? null : score;

    VersionRange range = new VersionRange(
            rs.getString("version"),
            rs.getString("start_incl"),
            rs.getString("start_excl"),
            rs.getString("end_incl"),
            rs.getString("end_excl"));

    ExploitSignal signal = toSignal(rs);

    return new CveMatchRow(
            rs.getString("cve_id"),
            boxedScore,
            rs.getString("cvss_severity"),
            rs.getString("cvss_vector"),
            rs.getString("cvss_version"),
            parseInstant(rs.getString("published")),
            rs.getString("description"),
            rs.getString("vendor"),
            rs.getString("product"),
            range,
            signal);
}

    /**
     * Builds the exploitation signal from the two LEFT JOINs.
     *
     * <p>Both {@code wasNull()} calls matter. An EPSS score of 0.0 is a real
     * value -- the model saying exploitation is very unlikely -- and JDBC returns
     * 0.0 for SQL NULL as well, so without the check every unscored CVE would be
     * recorded as "almost certainly safe" rather than as "not modelled".
     *
     * <p>KEV presence is detected on {@code kev_present} rather than on
     * {@code ransomware}: the ransomware column is {@code NOT NULL DEFAULT 0},
     * so reading 0 cannot distinguish "listed, not ransomware" from
     * "not listed".
     */
    private static ExploitSignal toSignal(ResultSet rs) throws SQLException {

        double epss = rs.getDouble("epss");
        Double epssScore = rs.wasNull() ? null : epss;

        double pct = rs.getDouble("epss_pct");
        Double epssPercentile = rs.wasNull() ? null : pct;

        rs.getString("kev_present");
        boolean inKev = !rs.wasNull();

        KevStatus status = KevStatus.NOT_LISTED;

        if (inKev) {
            status = rs.getInt("ransomware") == 1
                    ? KevStatus.RANSOMWARE
                    : KevStatus.LISTED;
        }

        return new ExploitSignal(
                epssScore,
                epssPercentile,
                status,
                inKev
                        ? ExploitFeedLoader.parseDate(
                                rs.getString("kev_added"))
                        : null,
                inKev
                        ? ExploitFeedLoader.parseDate(
                                rs.getString("kev_due"))
                        : null);
    }

    /**
     * NVD writes local date-times with no zone, e.g.
     * {@code 2024-07-01T00:00:00.000}.
     *
     * <p>They are UTC by NVD's own documentation but carry no offset, so
     * {@code Instant.parse} rejects them outright. Returning null on a value we
     * cannot interpret is better than inventing a timestamp.
     */
    private static Instant parseInstant(String text) {

        if (text == null || text.isBlank()) {
            return null;
        }

        try {
            return Instant.parse(text);

        } catch (DateTimeParseException withoutOffset) {

            try {
                return java.time.LocalDateTime
                        .parse(text)
                        .toInstant(java.time.ZoneOffset.UTC);

            } catch (DateTimeParseException e) {
                return null;
            }
        }
    }
}