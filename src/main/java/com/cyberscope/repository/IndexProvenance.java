package com.cyberscope.repository;

import java.util.Optional;

/**
 * Read-only access to what the CVE index knows about itself.
 *
 * <p>Exists so {@code service/report} can stamp a report with the data it was
 * scored against, without depending on {@link CveRepository} -- a rule
 * {@code ArchitectureTest} enforces, and for a good reason: the report layer has
 * no business holding something that can open a database connection.
 *
 * <p>Deliberately three methods and no more. A wider interface would let the
 * report layer start querying the index, which is the vulnerability service's
 * job, and the boundary would stop meaning anything.
 */
public interface IndexProvenance {

    /** The corpus itself: when it was built, from which feed, how many records. */
    Optional<IndexMetadata> metadata() throws RepositoryException;

    /** @param source {@code "kev"} or {@code "epss"} */
    Optional<FeedMetadata> feedMetadata(String source) throws RepositoryException;

    boolean isPopulated() throws RepositoryException;
}
