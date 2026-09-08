package com.cyberscope.ui;

import com.cyberscope.model.Host;
import com.cyberscope.model.Port;
import com.cyberscope.model.VulnAssessment;
import com.cyberscope.service.scanner.ScanOutcome;
import com.cyberscope.service.vuln.VulnerabilityService;
import javafx.concurrent.Task;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Scores one stored scan against the current index, off the FX thread.
 *
 * <h2>The defect this closes</h2>
 *
 * Until v0.7.0 the Scan history page rendered a stored scan with
 * {@code Map.of()}, so every cell in its Vulnerabilities column read "not
 * checked". The Dashboard, meanwhile, re-scored the <b>same stored scan</b> and
 * reported its findings. Two pages, one scan, two different answers -- and the
 * one that said "not checked" was the more reassuring of the two.
 *
 * <p>The comment defending it said re-running the lookup "would stamp an old
 * scan with today's index". That was a coherent position in v0.5.0. It stopped
 * being one in v0.6.0 Part 3, when scoring stored scans against today's index
 * became the deliberate design of the dashboard. The comment survived the
 * decision that invalidated it, which is how a stale rationale keeps a stale
 * behaviour alive.
 *
 * <p>Both pages now score the same way. The evidence is as old as the scan and
 * the intelligence is current, on every page that shows either.
 */
final class ScoreScanTask extends Task<Map<Port, VulnAssessment>> {

    private final AppContext context;
    private final ScanOutcome outcome;

    ScoreScanTask(AppContext context, ScanOutcome outcome) {
        this.context = context;
        this.outcome = outcome;
    }

    @Override
    protected Map<Port, VulnAssessment> call() {
        if (context.cveIndex() == null) {
            // An empty map is not the same as Map.of() being a placeholder: with
            // no index there genuinely is nothing checked, and the column saying
            // so is correct rather than a stand-in for work not done.
            return Map.of();
        }
        VulnerabilityService vulnerabilities = new VulnerabilityService(context.cveIndex());
        Map<Port, VulnAssessment> merged = new LinkedHashMap<>();
        for (Host host : outcome.hosts()) {
            if (isCancelled()) {
                return Map.of();
            }
            merged.putAll(vulnerabilities.assess(host));
        }
        return merged;
    }
}
