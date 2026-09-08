package com.cyberscope.service.report;

import com.cyberscope.model.ReportProvenance;
import com.cyberscope.repository.FeedMetadata;
import com.cyberscope.repository.IndexMetadata;
import com.cyberscope.repository.IndexProvenance;
import com.cyberscope.repository.RepositoryException;

import java.time.Instant;

/**
 * Asks the index what it knows about itself, so a report can say so.
 *
 * <p>Takes {@link IndexProvenance}, not the repository -- the report layer must
 * not hold something that can run a query, and {@code ArchitectureTest} enforces
 * it.
 *
 * <h2>Every failure here produces a report, never an exception</h2>
 *
 * A missing index, an unreadable one, a feed that was never loaded: all of them
 * are states this application already treats as recoverable, and none of them is
 * a reason to refuse to write a report. The scan evidence is still real and
 * still worth having on paper.
 *
 * <p>What they must never do is disappear. Each one becomes an absent
 * {@link ReportProvenance.Source}, which {@code ReportProvenance.warnings}
 * turns into a sentence saying what could not be checked and what that does to
 * the conclusions. <b>Degrading quietly is the failure mode this whole project
 * exists to argue against</b>, so the degradation is the thing that gets
 * printed.
 */
public final class ProvenanceReader {

    private final IndexProvenance index;      // nullable: no index at all

    /** @param index may be null when no CVE index could be opened */
    public ProvenanceReader(IndexProvenance index) {
        this.index = index;
    }

    public ReportProvenance read(Instant now, String applicationVersion) {
        if (index == null) {
            return ReportProvenance.withoutIndex(now, applicationVersion);
        }
        return new ReportProvenance(now, corpus(), feed("kev", "CISA KEV"),
                feed("epss", "EPSS"), applicationVersion);
    }

    private ReportProvenance.Source corpus() {
        try {
            IndexMetadata metadata = index.metadata().orElse(null);
            if (metadata == null) {
                return null;
            }
            // The FEED timestamp, not the build time. "Built at" says when this
            // machine ran the import; the feed timestamp says how current the
            // data in it actually is, and those differ by however long the file
            // sat on disk before someone imported it.
            return new ReportProvenance.Source("NVD corpus",
                    metadata.feedTimestamp(), metadata.cveCount());
        } catch (RepositoryException e) {
            return null;
        }
    }

    private ReportProvenance.Source feed(String key, String displayName) {
        try {
            FeedMetadata metadata = index.feedMetadata(key).orElse(null);
            if (metadata == null) {
                return null;
            }
            // Same reasoning: prefer the publisher's timestamp, fall back to when
            // we fetched it. EPSS recomputes daily, so "when it was published" is
            // the number that decides whether a score has drifted.
            Instant asOf = metadata.sourceTimestamp() != null
                    ? metadata.sourceTimestamp() : metadata.fetchedAt();
            return new ReportProvenance.Source(displayName, asOf, metadata.recordCount());
        } catch (RepositoryException e) {
            return null;
        }
    }
}
