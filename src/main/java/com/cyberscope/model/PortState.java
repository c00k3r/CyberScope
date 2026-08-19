package com.cyberscope.model;

import java.util.Locale;

/**
 * The six port states Nmap reports.
 *
 * <p>The compound states matter: {@code open|filtered} means Nmap could not tell
 * the difference, which is a weaker claim than {@code open} and must not be
 * treated as equivalent.
 */
public enum PortState {
    OPEN, CLOSED, FILTERED, UNFILTERED, OPEN_FILTERED, CLOSED_FILTERED, UNKNOWN;

    public static PortState from(String xmlValue) {
        if (xmlValue == null) return UNKNOWN;
        return switch (xmlValue.trim().toLowerCase(Locale.ROOT)) {
            case "open"            -> OPEN;
            case "closed"          -> CLOSED;
            case "filtered"        -> FILTERED;
            case "unfiltered"      -> UNFILTERED;
            case "open|filtered"   -> OPEN_FILTERED;
            case "closed|filtered" -> CLOSED_FILTERED;
            default                -> UNKNOWN;
        };
    }

    /** Renders back to Nmap's own spelling, for display. */
    @Override
    public String toString() {
        return switch (this) {
            case OPEN_FILTERED   -> "open|filtered";
            case CLOSED_FILTERED -> "closed|filtered";
            case UNKNOWN         -> "?";
            default              -> name().toLowerCase(Locale.ROOT);
        };
    }
}
