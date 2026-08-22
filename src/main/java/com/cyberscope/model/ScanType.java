package com.cyberscope.model;

import java.time.Duration;
import java.util.List;
import java.util.Locale;

/**
 * The scan profiles CyberScope offers.
 *
 * <p>A closed set by design: arbitrary Nmap options cannot be requested. Each
 * profile carries its own timeout budget, because how long a scan should
 * reasonably take is a property of the scan and of how many addresses it covers,
 * not of the caller.
 */
public enum ScanType {

    QUICK("Quick", "Top 100 ports, service and version detection",
          List.of("-sV", "-T4", "-F"),
          Duration.ofSeconds(180), Duration.ofSeconds(3)),

    STANDARD("Standard", "Top 1000 ports, service and version detection",
             List.of("-sV", "-T4", "--top-ports", "1000"),
             Duration.ofSeconds(900), Duration.ofSeconds(15));

    private final String displayName;
    private final String description;
    private final List<String> flags;
    private final Duration baseTimeout;
    private final Duration perAddress;

    ScanType(String displayName, String description, List<String> flags,
             Duration baseTimeout, Duration perAddress) {
        this.displayName = displayName;
        this.description = description;
        this.flags = flags;
        this.baseTimeout = baseTimeout;
        this.perAddress = perAddress;
    }

    public String displayName() { return displayName; }
    public String description() { return description; }
    public List<String> flags() { return flags; }

    /**
     * How long this profile may run against {@code addressCount} addresses before
     * it is killed. A safety net against a hang, not a performance target, so the
     * allowance is deliberately generous.
     */
    public Duration timeoutFor(int addressCount) {
        return baseTimeout.plus(perAddress.multipliedBy(Math.max(0, addressCount - 1)));
    }

    /** Parses a command-line value such as "quick" or "standard". Null if unknown. */
    public static ScanType fromCliName(String name) {
        for (ScanType type : values()) {
            if (type.name().equalsIgnoreCase(name)) {
                return type;
            }
        }
        return null;
    }

    /** e.g. "quick, standard" -- for help text and error messages. */
    public static String cliNames() {
        StringBuilder sb = new StringBuilder();
        for (ScanType type : values()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(type.name().toLowerCase(Locale.ROOT));
        }
        return sb.toString();
    }
}
