package com.cyberscope.repository;

import java.util.List;

/**
 * The only thing {@code service/vuln/} needs from the CVE index.
 *
 * <p>Two methods, because two is all the matcher asks: <em>is there an index</em>
 * and <em>what is filed under this product</em>. {@link CveRepository} implements
 * it against the local SQLite index.
 *
 * <p>Introduced for two reasons, and the second is the one that matters:
 *
 * <ol>
 *   <li>It lets {@code VulnerabilityService} be tested without a 328 MB database.
 *       A test that must build an index to check that a table-detected service is
 *       reported {@code NOT_APPLICABLE} is a test nobody runs.</li>
 *   <li>It keeps the door open for the hybrid design set aside in Part 0. Adding a
 *       live-NVD lookup that resolves a CPE the offline index missed becomes a
 *       second implementation of this interface, not an edit to the matcher.</li>
 * </ol>
 *
 * <p>Note what is <em>not</em> here. No method returns a verdict, a severity or a
 * "is this vulnerable" boolean. A lookup returns rows; deciding what they mean is
 * domain logic and lives above this line.
 */
public interface CveLookup {

    /**
     * Every applicability statement filed against {@code vendor:product}.
     *
     * <p>Arguments must be normalised the way {@code model.Cpe} normalises them --
     * unescaped and lower-cased.
     *
     * @return possibly empty, never null. <b>Empty means the index has nothing
     *         under this vendor and product at all</b>, which the caller must
     *         report as {@code UNRESOLVED} rather than as an absence of
     *         vulnerabilities
     */
    List<CveMatchRow> findByProduct(String vendor, String product) throws RepositoryException;

    /** True when an index exists and contains data. */
    boolean isPopulated() throws RepositoryException;
}