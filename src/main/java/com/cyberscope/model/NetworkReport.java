package com.cyberscope.model;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * One report covering every target that has been scanned.
 *
 * <h2>What a network report cannot say</h2>
 *
 * The obvious design is five scan reports stapled together with a summary on
 * top. That produces a document which quietly makes three claims it has no basis
 * for, and each one is worth stating.
 *
 * <p><b>1. It is not a report about your network.</b> CyberScope has no idea how
 * many machines exist. It knows how many targets someone typed into the scan
 * box. A host nobody has ever scanned is not "clear" and is not "0% covered" --
 * it is absent, and absent from a denominator that does not exist. So the
 * headline says <i>"4 targets you have scanned"</i> and never <i>"your
 * network"</i>. That distinction is the whole difference between a finding and a
 * reassurance.
 *
 * <p><b>2. It has an age range, not an age.</b> A scan report has one scan and
 * therefore one age. This has several, and averaging them would hide the
 * three-week-old one behind four fresh ones. The oldest is named.
 *
 * <p><b>3. Its coverage is service-weighted, so one busy host can dominate.</b>
 * A target with eighteen open services and one with a single service do not
 * contribute equally to "8 of 14 services checked". When one target supplies
 * more than half the services in the figure, the report says so -- otherwise a
 * reader takes a network-wide percentage as a statement about every host in it.
 *
 * @param posture     the roll-up, already ordered worst-first
 * @param provenance  what the vulnerability data looked like at generation time
 * @param generatedAt when this report was written
 */
public record NetworkReport(NetworkPosture posture, ReportProvenance provenance,
                            Instant generatedAt) {

    /** A single target contributing more than this share of the services is called out. */
    static final double DOMINANT_SHARE = 0.5;

    public NetworkReport {
        Objects.requireNonNull(posture, "posture");
        Objects.requireNonNull(provenance, "provenance -- a report must record the "
                + "vulnerability data it was scored against");
        Objects.requireNonNull(generatedAt, "generatedAt");
    }

    public List<TargetPosture> targets() {
        return posture.targets();
    }

    public ExposureBand band() {
        return posture.band();
    }

    public Coverage coverage() {
        return posture.coverage();
    }

    /**
     * The summary sentence.
     *
     * <p>Always scoped to the targets that were scanned, always carrying the
     * coverage alongside any count, and leading with coverage when the coverage
     * is what makes the rest untrustworthy -- the same rule as
     * {@link ScanReport#headline}, one level up.
     */
    public String headline() {
        int count = targets().size();
        if (count == 0) {
            return "No scans yet - nothing to report.";
        }
        String scope = count + (count == 1 ? " target" : " targets")
                + " scanned, " + coverage().describe()
                + " (" + coverage().percent() + "% coverage)";

        if (band() == ExposureBand.INDETERMINATE) {
            return "INDETERMINATE across " + scope;
        }
        int findings = posture.findingCount();
        if (findings == 0) {
            return band().label().toUpperCase(java.util.Locale.ROOT)
                 + " - nothing found across " + scope;
        }
        return band().label().toUpperCase(java.util.Locale.ROOT) + " exposure - "
             + findings + " finding" + (findings == 1 ? "" : "s")
             + " across " + scope;
    }

    /** The target whose scan is oldest, which is the one that dates the report. */
    public Optional<TargetPosture> oldest() {
        return targets().stream().min(Comparator.comparing(TargetPosture::scannedAt));
    }

    public List<TargetPosture> staleTargets(Instant now) {
        return targets().stream().filter(target -> target.isStale(now)).toList();
    }

    /**
     * The target supplying more than half the services in the coverage figure.
     *
     * <p>Empty when no single target dominates, which is the common case and the
     * one where the network percentage means what a reader thinks it means.
     */
    public Optional<TargetPosture> dominantTarget() {
        int total = coverage().examined();
        if (total == 0) {
            return Optional.empty();
        }
        return targets().stream()
                .filter(t -> t.coverage().examined() > total * DOMINANT_SHARE)
                .findFirst();
    }

    /**
     * Everything that qualifies this report.
     *
     * <p>Ordered the same way {@link ScanReport#caveats} orders them: what is
     * wrong with the evidence first, what is wrong with the interpretation
     * second. A reader who gets one line should get the one about the evidence.
     */
    public List<String> caveats(Instant now) {
        List<String> caveats = new ArrayList<>();

        caveats.add("This report covers the " + targets().size()
                + (targets().size() == 1 ? " target" : " targets")
                + " that have been scanned with CyberScope. It is not a survey of "
                + "your network: a host that has never been scanned does not appear "
                + "here and is not counted as clear.");

        List<TargetPosture> stale = staleTargets(now);
        if (!stale.isEmpty()) {
            StringBuilder names = new StringBuilder();
            for (int i = 0; i < stale.size(); i++) {
                names.append(i == 0 ? "" : ", ").append(stale.get(i).target())
                     .append(" (").append(stale.get(i).describeAge(now)).append(')');
            }
            caveats.add("Scanned more than a week ago, so these describe hosts as they "
                    + "were rather than as they are: " + names + ".");
        }

        dominantTarget().ifPresent(target -> caveats.add(
                "The coverage figure is weighted by service count, and "
                + target.target() + " supplies " + target.coverage().examined()
                + " of the " + coverage().examined() + " services in it. A network-wide "
                + "percentage is not a statement about every host in the list."));

        int unchecked = coverage().unchecked();
        if (unchecked > 0) {
            caveats.add(unchecked + " open service" + (unchecked == 1 ? " was" : "s were")
                    + " not checked against the index, usually because no version could "
                    + "be probed. Those services carry no findings, which is not the same "
                    + "as having none.");
        }

        caveats.addAll(provenance.warnings(now));
        return List.copyOf(caveats);
    }

    /** The highest-priority findings anywhere, already ranked across all targets. */
    public List<NetworkPosture.Action> topActions(int limit) {
        return posture.topActions(limit);
    }

    /** How far apart the oldest and newest scans are. */
    public Duration ageSpread() {
        if (targets().size() < 2) {
            return Duration.ZERO;
        }
        Instant oldest = targets().stream().map(TargetPosture::scannedAt)
                .min(Instant::compareTo).orElseThrow();
        Instant newest = targets().stream().map(TargetPosture::scannedAt)
                .max(Instant::compareTo).orElseThrow();
        return Duration.between(oldest, newest);
    }
}
