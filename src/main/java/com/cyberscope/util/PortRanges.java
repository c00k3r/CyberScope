package com.cyberscope.util;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Parses and formats Nmap's compressed port-range notation.
 *
 * <p>Nmap writes the ports it collapsed into an {@code <extraports>} block as a
 * comma-separated list of numbers and ranges:
 * {@code "1-4,6-9,11-12,14-35,37-42"}. That string is the only record of which
 * ports a scan actually covered, and coverage is what lets a comparison tell
 * "this port opened" apart from "this port was not scanned last time".
 *
 * <p>This is a parser for data that arrives from outside the program, so it is
 * written like one: every field is bounds-checked, and the output is capped.
 */
public final class PortRanges {

    /** TCP and UDP port numbers are unsigned 16-bit. */
    public static final int MIN_PORT = 0;
    public static final int MAX_PORT = 65_535;

    /**
     * The most ports one summary may expand to.
     *
     * <p>65,536 is every port that can exist, so this is not a restriction on
     * legitimate input -- it is a ceiling that stops a malformed or hostile
     * range string from asking for an unbounded allocation. The input is Nmap's
     * own output today, but a parser that is only safe because of who happens to
     * be calling it is not a safe parser.
     */
    private static final int MAX_EXPANDED = 65_536;

    private PortRanges() {
    }

    /**
     * Expands {@code "1-4,6,9-11"} to {@code {1,2,3,4,6,9,10,11}}.
     *
     * <p>Returns an empty set for null or blank input rather than throwing.
     * The {@code ports} attribute is {@code #IMPLIED} in Nmap's own DTD -- it is
     * genuinely optional, so its absence is a normal condition, not an error.
     * A scan whose coverage is unknown is handled by the comparison layer; it is
     * not this class's job to invent one.
     *
     * @throws IllegalArgumentException if the text is present but malformed
     */
    public static Set<Integer> parse(String text) {
        if (text == null || text.isBlank()) {
            return Set.of();
        }
        Set<Integer> ports = new LinkedHashSet<>();
        for (String piece : text.split(",")) {
            String token = piece.trim();
            if (token.isEmpty()) {
                continue;
            }
            int dash = token.indexOf('-');
            if (dash < 0) {
                add(ports, number(token));
                continue;
            }
            // Split on the FIRST dash only. "1-2-3" is malformed, and letting
            // number() reject "2-3" is better than silently reading "1-2".
            int low = number(token.substring(0, dash));
            int high = number(token.substring(dash + 1));
            if (low > high) {
                throw new IllegalArgumentException(
                        "Descending port range: '" + token + "'");
            }
            // Checked before the loop, not inside it: a range of 1-65535 would
            // otherwise allocate 65,000 entries before anyone noticed.
            if (ports.size() + (high - low + 1) > MAX_EXPANDED) {
                throw new IllegalArgumentException(
                        "Port range expands beyond " + MAX_EXPANDED + " ports");
            }
            for (int p = low; p <= high; p++) {
                add(ports, p);
            }
        }
        return Collections.unmodifiableSet(ports);
    }

    /**
     * The inverse: {@code {1,2,3,6}} becomes {@code "1-3,6"}.
     *
     * <p>Used for storage and for display. Round-tripping through
     * {@code parse(format(x))} must return {@code x}, and a test asserts it.
     */
    public static String format(Set<Integer> ports) {
        if (ports == null || ports.isEmpty()) {
            return "";
        }
        List<Integer> sorted = ports.stream().sorted().toList();
        StringBuilder out = new StringBuilder();
        int runStart = sorted.get(0);
        int previous = runStart;

        for (int i = 1; i <= sorted.size(); i++) {
            Integer current = i < sorted.size() ? sorted.get(i) : null;
            boolean runEnds = current == null || current != previous + 1;
            if (runEnds) {
                if (out.length() > 0) {
                    out.append(',');
                }
                out.append(runStart);
                // A run of exactly two is written "5,6", not "5-6": the same
                // number of characters, and one less thing to misread.
                if (previous == runStart + 1) {
                    out.append(',').append(previous);
                } else if (previous > runStart) {
                    out.append('-').append(previous);
                }
                runStart = current == null ? 0 : current;
            }
            if (current != null) {
                previous = current;
            }
        }
        return out.toString();
    }

    private static void add(Set<Integer> ports, int port) {
        if (ports.size() >= MAX_EXPANDED) {
            throw new IllegalArgumentException(
                    "Port list exceeds " + MAX_EXPANDED + " ports");
        }
        ports.add(port);
    }

    private static int number(String token) {
        String trimmed = token.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("Empty port number in range text");
        }
        // Length check before parsing: Integer.parseInt on a 10,000-digit string
        // is work we can decline to do.
        if (trimmed.length() > 5) {
            throw new IllegalArgumentException("Port number too long: '" + trimmed + "'");
        }
        int value;
        try {
            value = Integer.parseInt(trimmed);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Not a port number: '" + trimmed + "'", e);
        }
        if (value < MIN_PORT || value > MAX_PORT) {
            throw new IllegalArgumentException(
                    "Port out of range " + MIN_PORT + "-" + MAX_PORT + ": " + value);
        }
        return value;
    }
}