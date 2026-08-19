package com.cyberscope.model;

import java.time.Duration;
import java.util.List;

/**
 * The scan profiles CyberScope offers.
 *
 * <p>A closed set by design: arbitrary Nmap options cannot be requested.
 * Each profile also carries its own timeout, because how long a scan should
 * reasonably take is a property of the scan, not of the caller.
 */
public enum ScanType {

    QUICK("Quick", "Top 100 ports, service and version detection",
          List.of("-sV", "-T4", "-F"), Duration.ofSeconds(180)),

    STANDARD("Standard", "Top 1000 ports, service and version detection",
             List.of("-sV", "-T4", "--top-ports", "1000"), Duration.ofSeconds(900));

    private final String displayName;
    private final String description;
    private final List<String> flags;
    private final Duration timeout;

    ScanType(String displayName, String description, List<String> flags, Duration timeout) {
        this.displayName = displayName;
        this.description = description;
        this.flags = flags;
        this.timeout = timeout;
    }

    public String displayName() { return displayName; }
    public String description() { return description; }
    public List<String> flags() { return flags; }

    /** How long this profile may run before it is killed. Deliberately generous. */
    public Duration timeout() { return timeout; }
}
