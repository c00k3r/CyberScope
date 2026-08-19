package com.cyberscope.model;

import java.util.Locale;

/**
 * How Nmap arrived at a service identification.
 *
 * <p>{@link #TABLE} is a lookup of the port number in {@code nmap-services} — a guess
 * that is frequently wrong (port 8080 running a Python HTTP server is reported as
 * "http-proxy"). {@link #PROBED} means Nmap actually interacted with the service.
 * Only PROBED results are safe to map to vulnerabilities.
 */
public enum DetectionMethod {
    PROBED, TABLE, NONE;

    public static DetectionMethod from(String xmlValue) {
        if (xmlValue == null) return NONE;
        return switch (xmlValue.trim().toLowerCase(Locale.ROOT)) {
            case "probed" -> PROBED;
            case "table"  -> TABLE;
            default       -> NONE;
        };
    }
}
