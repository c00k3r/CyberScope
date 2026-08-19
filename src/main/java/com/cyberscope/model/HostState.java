package com.cyberscope.model;

import java.util.Locale;

/** Whether Nmap considered a host reachable. */
public enum HostState {
    UP, DOWN, UNKNOWN;

    public static HostState from(String xmlValue) {
        if (xmlValue == null) return UNKNOWN;
        return switch (xmlValue.trim().toLowerCase(Locale.ROOT)) {
            case "up"   -> UP;
            case "down" -> DOWN;
            default     -> UNKNOWN;
        };
    }
}
