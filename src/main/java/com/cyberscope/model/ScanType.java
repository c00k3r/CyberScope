package com.cyberscope.model;

import java.util.List;

/**
 * The scan profiles CyberScope offers.
 *
 * <p>This is a closed set by design: it is not possible to request Nmap options
 * that are not listed here, which is what prevents a caller from supplying
 * arbitrary flags such as {@code --script=} or {@code -oA}.
 *
 * <p>Every flag is a separate list element. Options that take a value must be
 * two elements ({@code "--top-ports", "1000"}), never one.
 */
public enum ScanType {

    /** Top 100 ports with service and version detection. Fast enough for a demo. */
    QUICK("Quick",
          "Top 100 ports, service and version detection",
          List.of("-sV", "-T4", "-F")),

    /** Top 1000 ports with service and version detection. The default assessment. */
    STANDARD("Standard",
             "Top 1000 ports, service and version detection",
             List.of("-sV", "-T4", "--top-ports", "1000"));

    private final String displayName;
    private final String description;
    private final List<String> flags;

    ScanType(String displayName, String description, List<String> flags) {
        this.displayName = displayName;
        this.description = description;
        this.flags = flags;
    }

    /** Human-readable name, for the GUI dropdown at v0.2. */
    public String displayName() {
        return displayName;
    }

    /** One-line explanation of what this scan does. */
    public String description() {
        return description;
    }

    /** The Nmap options for this scan, one argument per element. Immutable. */
    public List<String> flags() {
        return flags;
    }
}
