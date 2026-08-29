package com.cyberscope.ui;

import com.cyberscope.model.Port;
import com.cyberscope.model.VulnAssessment;
import com.cyberscope.repository.CveLookup;
import com.cyberscope.service.vuln.VulnerabilityService;
import java.util.LinkedHashMap;
import java.util.Map;
import com.cyberscope.model.Host;
import com.cyberscope.model.ScanType;
import com.cyberscope.repository.RepositoryException;
import com.cyberscope.repository.ScanRepository;
import com.cyberscope.service.scanner.NmapDetector;
import com.cyberscope.service.scanner.NmapExecutor;
import com.cyberscope.service.scanner.NmapRunResult;
import com.cyberscope.service.scanner.NmapXmlParser;
import com.cyberscope.service.scanner.ScanOutcome;
import com.cyberscope.util.TargetValidator;
import com.cyberscope.util.ValidatedTarget;
import javafx.concurrent.Task;

import java.util.List;

/**
 * Runs one scan off the JavaFX Application Thread.
 *
 * <p>{@link #call()} executes on a background thread. It must never touch the scene
 * graph; it reports progress through {@code updateMessage}, which is thread-safe,
 * and returns a value that JavaFX delivers to {@code setOnSucceeded} back on the
 * FX thread.
 *
 * <p>This class is the only bridge between JavaFX and the service layer, which is
 * why no class under {@code service/} or {@code repository/} imports anything from
 * {@code javafx}.
 */
public final class ScanTask extends Task<ScanOutcome> {

    private final ScanType scanType;
    private final String rawTarget;
    private final ScanRepository repository;    // null = do not persist
    private final CveLookup cveIndex;           // null = no vulnerability lookup

    /**
     * Written on the background thread in {@link #call()}, read on the FX thread in
     * the success handler.
     *
     * <p>{@code volatile} is not decoration here. Without it the Java Memory Model
     * makes no promise that the writing thread's value is visible to the reading
     * thread, and the bug that produces -- a scan that was saved but intermittently
     * reports as unsaved -- is timing-dependent and close to impossible to reproduce
     * on demand. JavaFX publishes the Task's own {@code value} safely; these extra
     * fields are not part of that machinery, so they have to say so themselves.
     */
    private volatile long savedId = -1;
    private volatile String saveError;

        public ScanTask(ScanType scanType, String rawTarget, ScanRepository repository) {
        this(scanType, rawTarget, repository, null);
    }

    public ScanTask(ScanType scanType, String rawTarget, ScanRepository repository,
                    CveLookup cveIndex) {
        this.scanType = scanType;
        this.rawTarget = rawTarget;
        this.repository = repository;
        this.cveIndex = cveIndex;
    }

    /** Assessments by port. Empty until {@link #call()} has finished. */
    public Map<Port, VulnAssessment> assessments() {
        return assessments;
    }

    /** The id this scan was stored under, or -1 if it was not stored. */
    public long savedId() {
        return savedId;
    }

    /** Why the save failed, or null if it succeeded or was never attempted. */
    public String saveError() {
        return saveError;
    }
     
         /**
     * Assessments, keyed by port, written on the background thread.
     *
     * <p>Same {@code volatile} reasoning as the two fields above, and the same
     * reason this work happens here rather than in the success handler: assessing
     * a twelve-service host takes about 216 ms against the real index, and a /24
     * with three open ports per host would be roughly fourteen seconds. On the FX
     * thread that is a frozen window; here it is time the user is already
     * spending watching a scan run.
     */
    private volatile Map<Port, VulnAssessment> assessments = Map.of();

    @Override
    protected ScanOutcome call() throws Exception {
        updateMessage("Validating target...");
        ValidatedTarget target = TargetValidator.validate(rawTarget);

        updateMessage("Checking for Nmap...");
        NmapDetector.detectVersion();

        updateMessage("Scanning " + target.describe() + " (" + scanType.displayName() + ")...");
        NmapRunResult run = NmapExecutor.execute(scanType, target);

        updateMessage("Parsing results...");
        List<Host> hosts = NmapXmlParser.parse(run.xml());
        ScanOutcome outcome = new ScanOutcome(run, hosts);

        persist(outcome);
                updateMessage("Checking services against the CVE index...");
        VulnerabilityService vulnerabilities = new VulnerabilityService(cveIndex);
        Map<Port, VulnAssessment> assessed = new LinkedHashMap<>();
        for (Host host : hosts) {
            assessed.putAll(vulnerabilities.assess(host));
        }
        assessments = Map.copyOf(assessed);
        return outcome;
    }

    /**
     * Saves here, on the background thread, rather than in the success handler.
     *
     * <p>Measured: writing a /24 result -- 254 hosts, 2032 ports -- takes about
     * 91 ms. On the FX thread that is roughly six dropped frames, at the exact
     * moment the user is looking at their results.
     *
     * <p>A failed save does not fail the scan. The scan is what the user asked for
     * and it has already succeeded; losing a history entry is a smaller problem than
     * throwing the results away, so the failure is recorded and reported rather than
     * propagated.
     */
    private void persist(ScanOutcome outcome) {
        if (repository == null || isCancelled()) {
            return;
        }
        updateMessage("Saving to history...");
        try {
            savedId = repository.save(outcome);
        } catch (RepositoryException e) {
            saveError = e.getMessage();
        }
    }
}