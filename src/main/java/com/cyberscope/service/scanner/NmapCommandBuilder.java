package com.cyberscope.service.scanner;

import com.cyberscope.model.ScanType;
import com.cyberscope.util.ValidatedTarget;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Builds the exact argument list passed to Nmap.
 *
 * <p>Deliberately separate from execution: the command can be asserted in a unit
 * test without running anything.
 *
 * <p>Since v0.2 this takes a {@link ValidatedTarget} rather than a String. The
 * defensive re-validation it used to perform is gone, because the type now makes
 * an unvalidated target impossible to pass -- the compiler enforces what a runtime
 * check used to.
 */
public final class NmapCommandBuilder {

    private static final String NMAP_EXECUTABLE = "nmap";

    private NmapCommandBuilder() {
    }

    public static List<String> build(ScanType scanType, ValidatedTarget target, Path xmlOutput) {
        Objects.requireNonNull(scanType, "scanType must not be null");
        Objects.requireNonNull(target, "target must not be null");
        Objects.requireNonNull(xmlOutput, "xmlOutput must not be null");

        List<String> command = new ArrayList<>();
        command.add(NMAP_EXECUTABLE);
        command.addAll(scanType.flags());
        command.add("-oX");
        command.add(xmlOutput.toString());
        command.add(target.value());          // target last, always

        return List.copyOf(command);
    }

    /**
     * Renders a command for display or logging.
     *
     * <p><strong>Display only.</strong> Never pass the result to a shell.
     */
    public static String describe(List<String> command) {
        return String.join(" ", command);
    }
}
