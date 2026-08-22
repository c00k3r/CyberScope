package com.cyberscope.ui;

import com.cyberscope.model.Host;
import com.cyberscope.model.ScanType;
import com.cyberscope.service.scanner.NmapDetector;
import com.cyberscope.service.scanner.NmapExecutor;
import com.cyberscope.service.scanner.NmapRunResult;
import com.cyberscope.service.scanner.NmapXmlParser;
import com.cyberscope.util.TargetValidator;
import javafx.concurrent.Task;
import com.cyberscope.util.ValidatedTarget; 

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
 * why nothing under {@code service/} imports anything from {@code javafx}.
 */
public final class ScanTask extends Task<ScanOutcome> {

    private final ScanType scanType;
    private final String rawTarget;

    public ScanTask(ScanType scanType, String rawTarget) {
        this.scanType = scanType;
        this.rawTarget = rawTarget;
    }

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

        return new ScanOutcome(run, hosts);
    }
}
