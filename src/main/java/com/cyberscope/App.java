package com.cyberscope;
 
import com.cyberscope.model.Host;
import com.cyberscope.model.ScanType;
import com.cyberscope.service.report.ScanReportFormatter;
import com.cyberscope.service.scanner.NmapDetector;
import com.cyberscope.service.scanner.NmapExecutionException;
import com.cyberscope.service.scanner.NmapExecutor;
import com.cyberscope.service.scanner.NmapNotFoundException;
import com.cyberscope.service.scanner.NmapRunResult;
import com.cyberscope.service.scanner.NmapXmlParser;
import com.cyberscope.service.scanner.XmlParseException;
import com.cyberscope.util.InvalidTargetException;
import com.cyberscope.util.TargetValidator;
import com.cyberscope.util.ValidatedTarget;
 
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
 
/** Command-line entry point for CyberScope. */
public final class App {
 
    public static final String VERSION = "0.2.0";
 
    private static final ScanType DEFAULT_SCAN = ScanType.QUICK;
 
    static final int EXIT_OK = 0;
    static final int EXIT_DEPENDENCY_MISSING = 2;
    static final int EXIT_INVALID_TARGET = 3;
    static final int EXIT_SCAN_FAILED = 4;
 
    private App() {
    }
 
    public static void main(String[] args) {
        System.exit(run(args));
    }
 
    static int run(String[] args) {
        boolean assumeAuthorised = false;
        boolean endOfOptions = false;
        ScanType scanType = DEFAULT_SCAN;
        List<String> targets = new ArrayList<>();
 
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (endOfOptions) {
                targets.add(arg);
                continue;
            }
            switch (arg) {
                case "--" -> endOfOptions = true;
                case "--yes", "-y" -> assumeAuthorised = true;
                case "--help", "-h" -> {
                    printUsage();
                    return EXIT_OK;
                }
                case "--version", "-V" -> {
                    System.out.println("CyberScope " + VERSION);
                    return EXIT_OK;
                }
                case "--scan-type", "-s" -> {
                    if (i + 1 >= args.length) {
                        System.err.println("[!!] --scan-type requires a value ("
                                         + ScanType.cliNames() + ")");
                        return EXIT_INVALID_TARGET;
                    }
                    String value = args[++i];
                    scanType = ScanType.fromCliName(value);
                    if (scanType == null) {
                        System.err.println("[!!] Unknown scan type '" + value
                                         + "'. Choose one of: " + ScanType.cliNames());
                        return EXIT_INVALID_TARGET;
                    }
                }
                default -> {
                    if (arg.startsWith("-")) {
                        System.err.println("[!!] Unknown option: " + arg);
                        printUsage();
                        return EXIT_INVALID_TARGET;
                    }
                    targets.add(arg);
                }
            }
        }
 
        banner();
 
        if (targets.isEmpty()) {
            printUsage();
            return EXIT_OK;
        }
        if (targets.size() > 1) {
            System.err.println("[!!] Exactly one target expected; got " + targets.size()
                             + ": " + targets);
            return EXIT_INVALID_TARGET;
        }
 
        ValidatedTarget target;
        try {
            target = TargetValidator.validate(targets.get(0));
        } catch (InvalidTargetException e) {
            System.err.println("[!!] " + e.getMessage());
            return EXIT_INVALID_TARGET;
        }
 
        try {
            System.out.println("[ok] Nmap " + NmapDetector.detectVersion() + " detected");
        } catch (NmapNotFoundException e) {
            System.err.println("[!!] " + e.getMessage());
            return EXIT_DEPENDENCY_MISSING;
        }
 
        if (!assumeAuthorised && !confirmAuthorisation(target)) {
            System.out.println("Scan cancelled.");
            return EXIT_OK;
        }
 
        System.out.println("[..] Scanning " + target.value()
                         + " (" + scanType.displayName() + ") ...");
        if (target.isRange()) {
            System.out.printf("     Timeout budget: %d s for %d addresses%n",
                    scanType.timeoutFor(target.addressCount()).toSeconds(),
                    target.addressCount());
        }
        System.out.println();
 
        try {
            NmapRunResult run = NmapExecutor.execute(scanType, target);
            List<Host> hosts = NmapXmlParser.parse(run.xml());
            System.out.print(ScanReportFormatter.format(run, hosts, ZoneId.systemDefault()));
            return EXIT_OK;
 
        } catch (NmapExecutionException | XmlParseException e) {
            System.err.println("[!!] " + e.getMessage());
            return EXIT_SCAN_FAILED;
        }
    }
 
    private static void banner() {
        System.out.println("CyberScope v" + VERSION + " - authorised targets only, see SCOPE.md");
        System.out.println();
    }
 
    private static void printUsage() {
        System.out.println("""
                Usage: cyberscope [options] <target>
 
                  <target>          an IPv4 address, a hostname, or a CIDR range
                                    (up to /24) you are authorised to scan
 
                Options:
                  -s, --scan-type   quick (default) or standard
                  -y, --yes         skip the interactive authorisation prompt
                  -h, --help        show this help
                  -V, --version     show the version
 
                Exit codes:
                  0  success
                  2  Nmap not installed
                  3  invalid target or arguments
                  4  scan or parse failed
                """);
    }
 
    private static boolean confirmAuthorisation(ValidatedTarget target) {
        System.out.println();
        System.out.println("  Active scanning is lawful only against systems you own or");
        System.out.println("  have explicit written permission to test.");
        if (target.isRange()) {
            System.out.println("  This will scan " + target.addressCount() + " addresses.");
        }
        System.out.print("  Type 'yes' to confirm you are authorised to scan "
                       + target.value() + ": ");
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            String answer = in.readLine();
            System.out.println();
            return answer != null && answer.trim().equalsIgnoreCase("yes");
        } catch (IOException e) {
            return false;
        }
    }
}
 

