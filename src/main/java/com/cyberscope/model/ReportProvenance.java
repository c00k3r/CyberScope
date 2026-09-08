package com.cyberscope.model;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * What the vulnerability data looked like when a report was written.
 *
 * <h2>Why a report cannot exist without this</h2>
 *
 * v0.6.0 made a deliberate choice: stored scans are re-scored against the index
 * <i>as it stands today</i>, so a CVE added to CISA KEV this morning changes the
 * dashboard this afternoon without anyone re-scanning. That is right for a live
 * screen.
 *
 * <p>It is a problem for a report. A report is a point-in-time artefact that
 * someone reads later, forwards, attaches to a ticket, or brings to a meeting
 * three weeks after it was written. <b>Two reports of the same scan, generated a
 * week apart, will legitimately disagree</b> -- and a reader with no way to tell
 * which index each was scored against cannot reconcile them, cannot reproduce
 * either, and cannot tell an improvement from a data refresh.
 *
 * <p>So this record is mandatory on every report. It is the difference between a
 * finding and an assertion.
 *
 * @param generatedAt      when the report was written
 * @param corpus           the NVD corpus state, or null if no index was available
 * @param kev              CISA KEV feed state, or null if never loaded
 * @param epss             EPSS feed state, or null if never loaded
 * @param applicationVersion the build that produced the report
 */
public record ReportProvenance(Instant generatedAt, Source corpus, Source kev, Source epss,
                               String applicationVersion) {

    private static final DateTimeFormatter WHEN =
            DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm z");

    /** A data source that goes stale, with the timestamp that matters for it. */
    public record Source(String name, Instant asOf, int recordCount) {

        public Source {
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(asOf, "asOf");
        }

        public Duration age(Instant now) {
            Duration age = Duration.between(asOf, now);
            return age.isNegative() ? Duration.ZERO : age;
        }

        public boolean isStale(Instant now) {
            return age(now).compareTo(STALE_AFTER) >= 0;
        }

        /** e.g. {@code NVD corpus: 384,678 records, as of 31 Aug 2026, 05:30 UTC}. */
        public String describe(ZoneId zone) {
            return String.format("%s: %,d records, as of %s",
                    name, recordCount, WHEN.format(asOf.atZone(zone)));
        }
    }

    /**
     * Seven days, the same threshold the index and feeds already use.
     *
     * <p>Not chosen for roundness: at the measured ~584 new CVEs per day, a
     * week-old corpus is missing on the order of four thousand advisories.
     */
    public static final Duration STALE_AFTER = Duration.ofDays(7);

    public ReportProvenance {
        Objects.requireNonNull(generatedAt, "generatedAt");
        applicationVersion = applicationVersion == null || applicationVersion.isBlank()
                ? "unknown" : applicationVersion;
    }

    /**
     * No CVE index at all.
     *
     * <p>Constructible on purpose. A report produced with no index is a valid
     * thing to want -- it still records open ports, service evidence and the scan
     * command -- but it must be unmistakable that nothing was checked, which is
     * what {@link #hasVulnerabilityData()} and {@link #warnings} exist to say.
     */
    public static ReportProvenance withoutIndex(Instant generatedAt, String version) {
        return new ReportProvenance(generatedAt, null, null, null, version);
    }

    public boolean hasVulnerabilityData() {
        return corpus != null;
    }

    public boolean hasExploitData() {
        return kev != null || epss != null;
    }

    /**
     * Everything a reader needs in order to distrust this report appropriately.
     *
     * <p>Returned as a list rather than a boolean because a report renders them
     * verbatim. Each entry is a complete sentence stating what is missing or old
     * and what that does to the conclusions -- a warning that says "index stale"
     * and nothing else tells the reader a fact but not its consequence.
     */
    public List<String> warnings(Instant now) {
        List<String> warnings = new ArrayList<>();
        if (corpus == null) {
            warnings.add("No CVE index was available. No service was checked against any "
                       + "vulnerability data, so the absence of findings in this report "
                       + "says nothing about the security of these hosts.");
            return warnings;
        }
        if (corpus.isStale(now)) {
            warnings.add("The CVE corpus was " + describeAge(corpus.age(now))
                       + " old when this report was written. At roughly 584 new advisories "
                       + "per day it was missing several thousand records, so a finding "
                       + "count here is a floor, not a total.");
        }
        if (kev == null && epss == null) {
            warnings.add("No exploitation data was loaded. Findings are ordered by CVSS "
                       + "severity alone, which is a measure of how bad a flaw would be "
                       + "and not of whether anyone is exploiting it.");
        } else {
            if (kev == null) {
                warnings.add("The CISA KEV catalogue was not loaded, so no finding in this "
                           + "report is marked as known to be exploited.");
            } else if (kev.isStale(now)) {
                warnings.add("The CISA KEV catalogue was " + describeAge(kev.age(now))
                           + " old. Entries added since are not reflected here.");
            }
            if (epss == null) {
                warnings.add("EPSS scores were not loaded, so exploitation probability is "
                           + "absent from every finding.");
            } else if (epss.isStale(now)) {
                warnings.add("EPSS scores were " + describeAge(epss.age(now))
                           + " old. EPSS is recomputed daily, so every probability in this "
                           + "report has drifted by that much.");
            }
        }
        return List.copyOf(warnings);
    }

    /** True when a reader should treat the figures with extra caution. */
    public boolean isDegraded(Instant now) {
        return !warnings(now).isEmpty();
    }

    /** Shared with the report renderer, which prints the same phrasing. */
    public static String describeAge(Duration age) {
        long days = age.toDays();
        if (days >= 1) {
            return days + (days == 1 ? " day" : " days");
        }
        long hours = age.toHours();
        return hours <= 1 ? "less than an hour" : hours + " hours";
    }

    /** The one-line footer: what produced this and when. */
    public String describe(ZoneId zone) {
        return "CyberScope " + applicationVersion + " - generated "
             + WHEN.format(generatedAt.atZone(zone));
    }
}
