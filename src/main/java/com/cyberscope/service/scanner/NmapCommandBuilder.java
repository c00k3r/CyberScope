package com.cyberscope.service.scanner;

import com.cyberscope.model.ScanType;
import com.cyberscope.util.InvalidTargetException;
import com.cyberscope.util.TargetValidator;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Builds the exact argument list passed to Nmap.
 *
 * <p>Deliberately separate from execution: the command can be asserted in a unit
 * test without running anything. Nothing in this class starts a process.
 */
public final class NmapCommandBuilder {

    private static final String NMAP_EXECUTABLE = "nmap";

    private NmapCommandBuilder() {
    }

    /**
     * Builds the command for a scan.
     *
     * @param scanType  which profile to run; a closed set, so arbitrary flags are impossible
     * @param target    the target; re-validated here as a defence in depth
     * @param xmlOutput where Nmap should write its XML report
     * @return an immutable argument list, one argument per element
     * @throws InvalidTargetException if the target fails validation
     */
    public static List<String> build(ScanType scanType, String target, Path xmlOutput)
            throws InvalidTargetException {

        Objects.requireNonNull(scanType, "scanType must not be null");
        Objects.requireNonNull(xmlOutput, "xmlOutput must not be null");

        // Re-validated even though callers are expected to have done so already.
        // This class is the last gate before ProcessBuilder.
        String safeTarget = TargetValidator.validate(target);

        List<String> command = new ArrayList<>();
        command.add(NMAP_EXECUTABLE);
        command.addAll(scanType.flags());
        command.add("-oX");
        command.add(xmlOutput.toString());
        command.add(safeTarget);          // target last, always

        return List.copyOf(command);
    }

    /**
     * Renders a command for display or logging.
     *
     * <p><strong>Display only.</strong> Never pass the result to a shell or to
     * {@code Runtime.exec(String)} — collapsing the array into a string discards
     * the argument boundaries that make the array form safe.
     */
    public static String describe(List<String> command) {
        return String.join(" ", command);
    }
}
