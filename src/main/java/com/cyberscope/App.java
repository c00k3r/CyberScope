package com.cyberscope;

import com.cyberscope.service.scanner.NmapDetector;
import com.cyberscope.service.scanner.NmapNotFoundException;

/**
 * Entry point for CyberScope.
 *
 * <p>At v0.0.2 this verifies the environment: it confirms a usable Nmap
 * installation before any scanning capability is added.
 */
public final class App {

    /** Current application version. */
    public static final String VERSION = "0.0.2";

    /** Exit status used when a required external dependency is unavailable. */
    private static final int EXIT_DEPENDENCY_MISSING = 2;

    private App() {
    }

    public static void main(String[] args) {
        System.out.println("CyberScope v" + VERSION);
        System.out.println("Authorised targets only - see SCOPE.md");
        System.out.println();

        try {
            String nmapVersion = NmapDetector.detectVersion();
            System.out.println("[ok] Nmap detected: version " + nmapVersion);
        } catch (NmapNotFoundException e) {
            System.err.println("[!!] " + e.getMessage());
            System.exit(EXIT_DEPENDENCY_MISSING);
        }
    }
}
