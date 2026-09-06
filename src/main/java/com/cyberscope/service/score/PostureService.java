package com.cyberscope.service.score;

import com.cyberscope.model.ExposureBand;
import com.cyberscope.model.Host;
import com.cyberscope.model.NetworkPosture;
import com.cyberscope.model.Port;
import com.cyberscope.model.PostureAssessment;
import com.cyberscope.model.PostureTrend;
import com.cyberscope.model.TargetPosture;
import com.cyberscope.model.VulnAssessment;
import com.cyberscope.service.scanner.ScanOutcome;
import com.cyberscope.service.vuln.VulnerabilityService;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Scores stored scans.
 *
 * <h2>The decision this class embodies</h2>
 *
 * A stored scan keeps its ports and its version banners. It does <b>not</b> keep
 * the CVEs that were matched against it, and v0.6.0 chose not to add them.
 * Instead the dashboard re-runs the lookup against the index <i>as it stands
 * today</i>, every time it is opened.
 *
 * <p>The alternative was a schema migration storing each finding at scan time.
 * That gives a figure that never moves on its own, which is genuinely valuable
 * for a report. It also means a CVE published tomorrow is invisible until you
 * scan again -- and this project's whole argument is that a scanner's dangerous
 * failure is the false negative, not the false positive. regreSSHion was present
 * on every affected host for years before NVD had a record of it. A posture
 * dashboard that cannot say "this became urgent overnight without you touching
 * anything" is answering the wrong question.
 *
 * <p>The cost is real and has to be shown, not hidden: <b>the evidence is as old
 * as the scan, the intelligence is current.</b> Those two ages are different and
 * the dashboard prints both. A CLEAR band on a three-week-old scan means "three
 * weeks ago, this host had nothing that today's index knows about" -- which is
 * a useful sentence and not the same as "this host is fine".
 *
 * <h2>Threading</h2>
 *
 * Every method here does database work and must not be called on the FX thread.
 * A target with 18 open services costs roughly 18 index lookups; the UI runs
 * this on {@code AppContext.worker()} through a {@code Task}.
 */
public final class PostureService {

    private final VulnerabilityService vulnerabilities;

    /** @param vulnerabilities may be null when no CVE index is available */
    public PostureService(VulnerabilityService vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    /**
     * Scores one stored scan.
     *
     * <p>A scan can hold several hosts -- a CIDR range is one scan of many
     * machines. Their ports are merged into a single assessment, because the
     * dashboard's unit is the <i>target</i> the user typed, which is what they
     * will act on. The per-host breakdown is what the scan page is for.
     */
    public PostureAssessment score(ScanOutcome outcome) {
        if (vulnerabilities == null) {
            // No index. Every service is unchecked, coverage is 0, and the band
            // is INDETERMINATE -- not CLEAR. Reporting "clear" here would be a
            // statement about the index, not the host.
            return PostureAssessment.empty();
        }
        Map<Port, VulnAssessment> merged = new LinkedHashMap<>();
        for (Host host : outcome.hosts()) {
            merged.putAll(vulnerabilities.assess(host));
        }
        return PostureScorer.score(merged);
    }

    /**
     * Scores a target's latest scan, with the one before it for the trend.
     *
     * @param target   the target string
     * @param latest   its most recent scan
     * @param previous the scan before that, or null if there is none
     */
    public TargetPosture score(String target, long scanId,
                               ScanOutcome latest, ScanOutcome previous) {
        PostureAssessment assessment = score(latest);
        ExposureBand previousBand = previous == null ? null : score(previous).band();
        return new TargetPosture(target, scanId, latest.run().startedAt(), assessment,
                PostureTrend.between(previousBand, assessment.band()));
    }

    /**
     * Scores every target and rolls the results into the network view.
     *
     * <p>One method, not an overload pair. {@code network(List<TargetPosture>)}
     * and {@code network(List<ScoreRequest>)} erase to the same signature and
     * will not compile together -- generics are erased, so a {@code List} of one
     * is a {@code List} of the other at the bytecode level. Callers that already
     * hold scored targets use {@link NetworkPosture#of} directly.
     *
     * @param scans latest scan first in each request; the previous may be null
     */
    public NetworkPosture network(List<ScoreRequest> scans) {
        List<TargetPosture> scored = new ArrayList<>(scans.size());
        for (ScoreRequest request : scans) {
            scored.add(score(request.target(), request.scanId(),
                             request.latest(), request.previous()));
        }
        return NetworkPosture.of(scored);
    }

    /** @param previous nullable -- a target scanned only once has no predecessor */
    public record ScoreRequest(String target, long scanId,
                               ScanOutcome latest, ScanOutcome previous) {
    }
}
