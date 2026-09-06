package com.cyberscope.service.score;

import com.cyberscope.model.Coverage;
import com.cyberscope.model.ExposureBand;
import com.cyberscope.model.MappingOutcome;
import com.cyberscope.model.Port;
import com.cyberscope.model.PostureAssessment;
import com.cyberscope.model.RankedFinding;
import com.cyberscope.model.Severity;
import com.cyberscope.model.VulnAssessment;
import com.cyberscope.model.Vulnerability;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Turns a scan's per-port assessments into one host-level posture.
 *
 * <p>Pure. No SQL, no I/O, no clock. Hand it the map {@code VulnerabilityService}
 * already produces and it returns two figures and a ranked list.
 *
 * <h2>The rule, and why it is not a sum</h2>
 *
 * The band comes from the <b>strongest single piece of evidence</b> anywhere on
 * the host. Not a total, not an average, not a weighted count. Measured against
 * the real index, a count gets the answer backwards:
 *
 * <pre>
 *   oracle:mysql       73 findings, max EPSS 0.0111, 0 in KEV
 *   f5:nginx            2 findings, max EPSS 1.0000, 1 in KEV
 * </pre>
 *
 * Seventy-three quiet vulnerabilities are not worse than one that is being
 * exploited today, and no arithmetic over counts can express that. A person
 * triaging this list looks for the worst thing and starts there, so that is what
 * the band reports.
 */
public final class PostureScorer {

    /**
     * EPSS at or above this is treated as "very likely to be exploited".
     *
     * <p>A judgement, not a measurement -- EPSS is a probability and there is no
     * threshold in the data that separates urgent from not. 0.5 is used because
     * it is the point at which the model considers exploitation more likely than
     * not, which is at least a defensible sentence.
     */
    static final double EPSS_HIGH = 0.5;

    /** Above this, exploitation is unlikely but no longer negligible. */
    static final double EPSS_ELEVATED = 0.1;

    private PostureScorer() {
    }

    /**
     * Scores one host.
     *
     * @param assessments per-port results, as {@code VulnerabilityService.assess}
     *                    returns them; only open ports are present
     */
    public static PostureAssessment score(Map<Port, VulnAssessment> assessments) {
        if (assessments == null || assessments.isEmpty()) {
            return PostureAssessment.empty();
        }

        int checked = 0;
        int findingCount = 0;
        int exploitedCount = 0;
        Map<Severity, Integer> bySeverity = new EnumMap<>(Severity.class);
        List<RankedFinding> ranked = new ArrayList<>();

        for (Map.Entry<Port, VulnAssessment> entry : assessments.entrySet()) {
            VulnAssessment assessment = entry.getValue();
            if (assessment.outcome() == MappingOutcome.MAPPED) {
                checked++;
            }
            String product = assessment.lookedUp()
                    .map(cpe -> cpe.productKey() + " " + cpe.version())
                    .orElseGet(() -> entry.getKey().service().describe());

            for (Vulnerability vulnerability : assessment.vulnerabilities()) {
                findingCount++;
                bySeverity.merge(vulnerability.severity(), 1, Integer::sum);
                if (vulnerability.isKnownExploited()) {
                    exploitedCount++;
                }
                ranked.add(new RankedFinding(entry.getKey(), product, vulnerability));
            }
        }

        Coverage coverage = new Coverage(checked, assessments.size());
        ranked.sort(RankedFinding.ACTION_ORDER);

        return new PostureAssessment(
                bandFor(ranked, coverage),
                coverage,
                assessments.size(),
                findingCount,
                exploitedCount,
                bySeverity,
                List.copyOf(ranked));
    }

    /**
     * The band.
     *
     * <p>Two rules, and the second is the one that matters.
     *
     * <p><b>1. Strongest evidence wins.</b> The worst individual finding sets the
     * band, ignoring findings matched only through an unbounded "all versions"
     * claim -- the class that puts a 2008 Red Hat packaging incident on a 2024
     * OpenSSH. Those are reported; they do not get a vote.
     *
     * <p><b>2. Positive findings survive low coverage; reassurance does not.</b>
     * Discovering an exploited service does not become less true because three
     * other services could not be checked, so CRITICAL, HIGH and ELEVATED stand
     * regardless. But "we found nothing" is a claim that depends entirely on how
     * much was looked at, so CLEAR and LOW degrade to
     * {@link ExposureBand#INDETERMINATE} when coverage is inadequate.
     *
     * <p>Getting that asymmetry backwards is how a scanner reassures someone
     * about a host it never saw.
     *
     * <h2>The guard that used to be here</h2>
     *
     * An earlier version opened with {@code if (checked == 0) return
     * INDETERMINATE} -- "nothing was looked up, so there is no evidence in
     * either direction". Mutation testing removed it and no test noticed, which
     * turned out to be correct rather than a gap in the suite:
     *
     * <ul>
     *   <li>{@code VulnAssessment} rejects a non-MAPPED outcome that carries
     *       findings, so {@code checked == 0} implies the ranked list is empty
     *       and {@code worst} is {@link ExposureBand#CLEAR}.</li>
     *   <li>{@code checked == 0} with any open service gives
     *       {@code fraction() == 0.0}, which is below {@code ADEQUATE}, so the
     *       last line already returns {@code INDETERMINATE}.</li>
     *   <li>{@code checked == 0} with <i>no</i> open service never arrives:
     *       {@code score} returns {@code PostureAssessment.empty()} first.</li>
     * </ul>
     *
     * <p>So it was dead. It was also placed above the positive-findings branch,
     * which means that if the {@code VulnAssessment} invariant were ever
     * loosened, the guard would have suppressed an actively-exploited finding on
     * a barely-covered host -- inverting the one asymmetry this method exists to
     * enforce. Deleted, with the behaviour kept in a test so the intent survives
     * the code.
     */
    static ExposureBand bandFor(List<RankedFinding> ranked, Coverage coverage) {
        ExposureBand worst = ExposureBand.CLEAR;
        for (RankedFinding finding : ranked) {
            ExposureBand urgency = finding.urgency();
            if (urgency.rank() > worst.rank()) {
                worst = urgency;
            }
        }

        // Order matters. Evidence of exposure is reported whatever the coverage;
        // only the absence of evidence is qualified by it.
        if (worst.rank() >= ExposureBand.ELEVATED.rank()) {
            return worst;
        }
        return coverage.isAdequate() ? worst : ExposureBand.INDETERMINATE;
    }

}
