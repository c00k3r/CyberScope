package com.cyberscope.ui;

import com.cyberscope.model.NetworkPosture;
import com.cyberscope.repository.ScanSummary;
import com.cyberscope.service.scanner.ScanOutcome;
import com.cyberscope.service.score.PostureService;
import com.cyberscope.service.vuln.VulnerabilityService;
import javafx.concurrent.Task;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Loads and scores every target's latest scan, off the FX thread.
 *
 * <h2>Why this cannot run on the FX thread</h2>
 *
 * Rendering the dashboard means, per target: one query for the summary, one
 * full {@code load} of the scan, one query for the previous scan, another full
 * load, and then a CVE index lookup for <b>every open service in both</b>. A
 * single 18-port host is 36 index lookups at roughly 2.6 ms each. Ten targets is
 * comfortably over a second of blocking, and a UI thread blocked for a second is
 * a UI that has visibly hung.
 *
 * <p>{@code updateMessage} is used rather than a spinner alone, because a
 * progress bar that says nothing during a two-second wait teaches people the
 * application is slow, while "scoring 192.168.1.14 (3 of 7)" teaches them it is
 * working.
 */
final class DashboardTask extends Task<NetworkPosture> {

    /**
     * How many targets the dashboard summarises.
     *
     * <p>A cap, not a page size: there is no "next page" and there should not
     * be. A dashboard is a thing you take in at a glance, and the ordering
     * already puts the worst first, so the 41st target by exposure is not
     * something anyone is scrolling to find. The Vulnerabilities page in Part 4
     * is where the complete list lives.
     */
    static final int MAX_TARGETS = 40;

    private final AppContext context;

    DashboardTask(AppContext context) {
        this.context = context;
    }

    @Override
    protected NetworkPosture call() throws Exception {
        updateMessage("Reading scan history...");
        List<ScanSummary> latest = context.scans().latestPerTarget(MAX_TARGETS);
        if (latest.isEmpty()) {
            return NetworkPosture.empty();
        }

        // Null when there is no CVE index. PostureService handles that by
        // reporting INDETERMINATE rather than inventing a clean result.
        VulnerabilityService vulnerabilities = context.cveIndex() == null
                ? null : new VulnerabilityService(context.cveIndex());
        PostureService scorer = new PostureService(vulnerabilities);

        List<PostureService.ScoreRequest> requests = new ArrayList<>(latest.size());
        int done = 0;
        for (ScanSummary summary : latest) {
            if (isCancelled()) {
                return NetworkPosture.empty();
            }
            done++;
            updateMessage("Scoring " + summary.target() + "  (" + done
                    + " of " + latest.size() + ")");
            updateProgress(done, latest.size());

            Optional<ScanOutcome> current = context.scans().load(summary.id());
            if (current.isEmpty()) {
                // Deleted between the listing query and this load. Not an error:
                // skip it rather than failing the whole dashboard for one row.
                continue;
            }
            requests.add(new PostureService.ScoreRequest(
                    summary.target(), summary.id(), current.get(),
                    previousScan(summary).orElse(null)));
        }

        updateMessage("");
        return scorer.network(requests);
    }

    /**
     * The scan before {@code summary}, for this same target.
     *
     * <p>Asks for two and takes the one that is not the current id, rather than
     * asking for index 1. {@code findByTarget} orders by started_at then id, and
     * two scans saved inside the same second -- which a script can easily do --
     * are not guaranteed to come back with the latest first by timestamp alone.
     * Matching on the id is exact.
     */
    private Optional<ScanOutcome> previousScan(ScanSummary summary) throws Exception {
        List<ScanSummary> recent = context.scans().findByTarget(summary.target(), 2);
        for (ScanSummary candidate : recent) {
            if (candidate.id() != summary.id()) {
                return context.scans().load(candidate.id());
            }
        }
        return Optional.empty();
    }
}
