package com.cyberscope;

import com.cyberscope.service.scanner.NmapDetector;
import com.cyberscope.service.scanner.NmapNotFoundException;
import com.cyberscope.util.InvalidTargetException;
import com.cyberscope.util.TargetValidator;

/**
 * Entry point for CyberScope.
 *
 * <p>At v0.0.3 this verifies the environment and validates a target, but does
 * not yet scan.
 */
public final class App {

    public static final String VERSION = "0.0.3";

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
            System.out.println("[ok] Target accepted: " + TargetValidator.validate(args[0]));
        } catch (InvalidTargetException e) {
            System.err.println("[!!] " + e.getMessage());
            System.exit(EXIT_INVALID_TARGET);
        }
    }
}
