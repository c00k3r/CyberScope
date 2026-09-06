package com.cyberscope.model;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Every target's latest scan, rolled into one view.
 *
 * <p>The same rule as {@link com.cyberscope.service.score.PostureScorer} applies
 * one level up: <b>the network's band is the worst single target's band, not an
 * average.</b> Averaging exposure across hosts produces the reassuring nonsense
 * where nine clean machines dilute one that is being actively exploited, which
 * is precisely backwards -- an attacker needs one.
 *
 * @param band        the worst band across every target
 * @param coverage    services checked / services seen, summed over all targets
 * @param targets     one row per target, worst first
 * @param actions     the highest-priority findings anywhere, already ranked
 * @param bySeverity  histogram over every finding on every target
 * @param openPorts   total open services across all targets
 * @param unchecked   open services no lookup could be performed for
 */
public record NetworkPosture(ExposureBand band, Coverage coverage,
                             List<TargetPosture> targets, List<Action> actions,
                             Map<Severity, Integer> bySeverity,
                             int openPorts, int unchecked) {

    /**
     * A finding, with the target it was found on.
     *
     * <p>{@link RankedFinding} knows its port and product but not its host,
     * because at the point it is built there is only one host. On the dashboard
     * there are several, and "22/tcp -- CVE-2024-6387" without a machine name is
     * not an action anyone can take.
     */
    public record Action(String target, RankedFinding finding) {

        /** e.g. {@code 192.168.1.14 · openssh 9.6 on 22/tcp — CVE-2024-6387 (actively exploited)}. */
        public String describe() {
            return target + " · " + finding.describe();
        }
    }

    public NetworkPosture {
        targets = List.copyOf(targets);
        actions = List.copyOf(actions);
        bySeverity = Map.copyOf(bySeverity);
    }

    /** No scans at all. Distinct from "scans that found nothing". */
    public static NetworkPosture empty() {
        return new NetworkPosture(ExposureBand.INDETERMINATE, Coverage.NONE,
                List.of(), List.of(), Map.of(), 0, 0);
    }

    public boolean isEmpty() {
        return targets.isEmpty();
    }

    public int findingCount() {
        return bySeverity.values().stream().mapToInt(Integer::intValue).sum();
    }

    public int count(Severity severity) {
        return bySeverity.getOrDefault(severity, 0);
    }

    /** Targets whose band calls for action today. */
    public long targetsNeedingAction() {
        return targets.stream().filter(t -> t.band().needsAction()).count();
    }

    /**
     * Builds the roll-up.
     *
     * <p>Ordering is the part with a decision in it. Targets are sorted by band,
     * then by how many of their findings are known-exploited, then by finding
     * count, then by name so the list is stable between refreshes. Finding count
     * is <b>third</b>, for the reason measured in Part 1: mysql showed 73
     * findings with a maximum EPSS of 0.0111 and nginx showed 2 with an EPSS of
     * 1.0000. Sorting on the count puts the wrong machine at the top.
     */
    public static NetworkPosture of(List<TargetPosture> assessed) {
        if (assessed.isEmpty()) {
            return empty();
        }

        ExposureBand worst = ExposureBand.CLEAR;
        int checked = 0;
        int examined = 0;
        int openPorts = 0;
        Map<Severity, Integer> bySeverity = new EnumMap<>(Severity.class);
        List<Action> actions = new ArrayList<>();

        for (TargetPosture target : assessed) {
            PostureAssessment assessment = target.assessment();
            if (assessment.band().rank() > worst.rank()) {
                worst = assessment.band();
            }
            checked += assessment.coverage().checked();
            examined += assessment.coverage().examined();
            openPorts += assessment.openPorts();
            assessment.findingsBySeverity()
                      .forEach((severity, n) -> bySeverity.merge(severity, n, Integer::sum));
            for (RankedFinding finding : assessment.ranked()) {
                actions.add(new Action(target.target(), finding));
            }
        }

        // Every target INDETERMINATE means the network is too, not CLEAR.
        boolean anythingAssessed = assessed.stream()
                .anyMatch(t -> t.band() != ExposureBand.INDETERMINATE);
        if (!anythingAssessed) {
            worst = ExposureBand.INDETERMINATE;
        }

        actions.sort(Comparator.comparing(Action::finding, RankedFinding.ACTION_ORDER)
                .thenComparing(Action::target));

        List<TargetPosture> ordered = new ArrayList<>(assessed);
        ordered.sort(Comparator
                .comparingInt((TargetPosture t) -> t.band().rank()).reversed()
                .thenComparing(Comparator.comparingInt(
                        (TargetPosture t) -> t.assessment().exploitedCount()).reversed())
                .thenComparing(Comparator.comparingInt(
                        (TargetPosture t) -> t.assessment().findingCount()).reversed())
                .thenComparing(TargetPosture::target));

        Coverage coverage = new Coverage(checked, examined);
        return new NetworkPosture(worst, coverage, ordered, actions, bySeverity,
                openPorts, coverage.unchecked());
    }

    /** The first {@code limit} actions, for the recommended-actions card. */
    public List<Action> topActions(int limit) {
        return actions.subList(0, Math.min(limit, actions.size()));
    }
}
