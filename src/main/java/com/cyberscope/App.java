package com.cyberscope;

import com.cyberscope.model.ScanType;
import com.cyberscope.service.scanner.NmapExecutionException;
import com.cyberscope.service.scanner.NmapExecutor;
import com.cyberscope.service.scanner.NmapDetector;
import com.cyberscope.service.scanner.NmapNotFoundException;
import com.cyberscope.service.scanner.NmapRunResult;
import com.cyberscope.util.InvalidTargetException;
import com.cyberscope.util.TargetValidator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * Entry point for CyberScope.
 *
 * <p>At v0.0.5 this performs a real scan and reports that XML was received.
 * Parsing arrives in v0.0.7.
 */
public final class App {

    public static final String VERSION = "0.0.6";

    private static final ScanType DEFAULT_SCAN = ScanType.QUICK;
    private static final int EXIT_DEPENDENCY_MISSING = 2;
    private static final int EXIT_INVALID_TARGET = 3;
    private static final int EXIT_SCAN_FAILED = 4;

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

        String target;
        try {
            target = TargetValidator.validate(args[0]);
            System.out.println("[ok] Target accepted: " + target);
        } catch (InvalidTargetException e) {
            System.err.println("[!!] " + e.getMessage());
            System.exit(EXIT_INVALID_TARGET);
            return;                       // unreachable; satisfies definite assignment
        }

        if (!confirmAuthorisation(target)) {
            System.out.println("Scan cancelled.");
            return;
        }

        System.out.println();
        System.out.println("[..] Scanning " + target
                         + " (" + DEFAULT_SCAN.displayName() + ") ...");

        try {
            NmapRunResult result = NmapExecutor.execute(DEFAULT_SCAN, target);

            System.out.printf("[ok] Scan finished in %.1f s%n",
                    result.elapsed().toMillis() / 1000.0);
            System.out.println("[ok] Received " + result.xml().length()
                             + " characters of XML");

            if (result.hasWarnings()) {
                System.out.println();
                System.out.println("[!?] Nmap reported warnings:");
                result.warnings().lines().forEach(l -> System.out.println("       " + l));
            }

            System.out.println();
            System.out.println("Parsing arrives in v0.0.7.");

        } catch (NmapExecutionException e) {
            System.err.println("[!!] " + e.getMessage());
            System.exit(EXIT_SCAN_FAILED);
        } catch (InvalidTargetException e) {
            System.err.println("[!!] " + e.getMessage());
            System.exit(EXIT_INVALID_TARGET);
        }
    }

    /** Enforces the boundary declared in SCOPE.md at the moment packets would be sent. */
    private static boolean confirmAuthorisation(String target) {
        System.out.println();
        System.out.println("  Active scanning is lawful only against systems you own or");
        System.out.println("  have explicit written permission to test.");
        System.out.print("  Type 'yes' to confirm you are authorised to scan "
                       + target + ": ");
        try {
            // Deliberately not closed: closing this reader would close System.in.
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            String answer = in.readLine();
            return answer != null && answer.trim().equalsIgnoreCase("yes");
        } catch (IOException e) {
            return false;
        }
    }
}
