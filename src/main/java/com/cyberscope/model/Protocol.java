package com.cyberscope.model;

import java.util.Locale;

/** Transport protocol of a scanned port. */
public enum Protocol {
    TCP, UDP, SCTP, UNKNOWN;

    /** Lenient: an unrecognised value becomes UNKNOWN rather than failing the whole scan. */
    public static Protocol from(String xmlValue) {
        if (xmlValue == null) return UNKNOWN;
        return switch (xmlValue.trim().toLowerCase(Locale.ROOT)) {
            case "tcp"  -> TCP;
            case "udp"  -> UDP;
            case "sctp" -> SCTP;
            default     -> UNKNOWN;
        };
    }

    @Override
    public String toString() {
        return this == UNKNOWN ? "?" : name().toLowerCase(Locale.ROOT);
    }
}
