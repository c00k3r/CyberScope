package com.cyberscope;

import com.cyberscope.model.ScanType;
import com.cyberscope.service.scanner.NmapCommandBuilder;
import com.cyberscope.service.scanner.NmapDetector;
import com.cyberscope.service.scanner.NmapNotFoundException;
import com.cyberscope.util.InvalidTargetException;
import com.cyberscope.util.TargetValidator;

import java.nio.file.Path;
import java.util.List;

/**
 * Entry point for CyberScope.
 *
 * <p>At v0.0.4 this validates a target and shows the command that would run.
 * Nothing is executed yet.
 */
public final class App {

    public static final String VERSION = "0.0.4";

    private static final ScanType DEFAULT_SCAN = ScanType.QUICK;
    private static final int EXIT_DEPENDENCY_MISSING = 2;
    private static final int EXIT_INVALID_TARGET = 3;

    private App() {
    }

    public static void main(String[] args) {
        System.out.println("CyberScope v" + VERSION);
        System.out.println("Authorised targets only - see SCOPE.md");
        System.out.println();

        try {
            System.out.println("[ok] Nmap detected: version " + NmapDetector.detectVersion());
        } catch (NmapNotFoundException e) {
            System.err.println("[!!] " + e.getMessage());
            System.exit(EXIT_DEPENDENCY_MISSING);
        }

        if (args.length == 0) {
            System.out.println();
            System.out.println("Usage: cyberscope <target>");
            System.out.println("  <target>  a single IPv4 address or hostname"
                             + " you are authorised to scan");
            return;
        }
        if (args.length > 1) {
            System.err.println("[!!] Exactly one target expected; got " + args.length
                             + ". Quote the argument if it contains spaces.");
            System.exit(EXIT_INVALID_TARGET);
        }

        try {
            String target = TargetValidator.validate(args[0]);
            System.out.println("[ok] Target accepted: " + target);

            Path xmlOutput = Path.of(System.getProperty("java.io.tmpdir"),
                                     "cyberscope-scan.xml");
            List<String> command = NmapCommandBuilder.build(DEFAULT_SCAN, target, xmlOutput);

            System.out.println("[ok] Scan type: " + DEFAULT_SCAN.displayName()
                             + " - " + DEFAULT_SCAN.description());
            System.out.println("[--] Command:   " + NmapCommandBuilder.describe(command));
            System.out.println();
            System.out.println("Nothing was executed. Scanning arrives in v0.0.5.");

        } catch (InvalidTargetException e) {
            System.err.println("[!!] " + e.getMessage());
            System.exit(EXIT_INVALID_TARGET);
        }
    }
}
