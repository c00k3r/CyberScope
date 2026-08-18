package com.cyberscope.util;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Validates a user-supplied scan target.
 *
 * <p>This is the trust boundary between untrusted input and the Nmap command line.
 * It accepts only a single IPv4 address or an RFC 1123 hostname; everything else is
 * rejected. Validation is allow-list based: unrecognised input fails closed.
 *
 * <p>No DNS resolution is performed. This class checks syntax only.
 */
public final class TargetValidator {

    /** Maximum length of a DNS name (RFC 1035). Also bounds the work any regex can do. */
    private static final int MAX_LENGTH = 253;

    /** Shape only: four dot-separated groups of 1-3 digits. Range is checked separately. */
    private static final Pattern IPV4_SHAPE =
            Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");

    /** One RFC 1123 label: alphanumeric ends, hyphens allowed inside, 1-63 characters. */
    private static final String LABEL = "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?";

    /** A hostname: one or more labels separated by dots. */
    private static final Pattern HOSTNAME =
            Pattern.compile("^" + LABEL + "(\\." + LABEL + ")*$");

    private static final Pattern ALL_DIGITS = Pattern.compile("^\\d+$");

    private TargetValidator() {
    }

    /**
     * Validates and canonicalises a scan target.
     *
     * @param raw the untrusted input
     * @return the canonical form, safe to pass to Nmap as a single argument
     * @throws InvalidTargetException if the input is not a valid IPv4 address or hostname
     */
    public static String validate(String raw) throws InvalidTargetException {
        if (raw == null) {
            throw new InvalidTargetException("Target must not be null.");
        }

        String target = raw.trim();

        if (target.isEmpty()) {
            throw new InvalidTargetException("Target must not be empty.");
        }

        // Bound the input BEFORE any regex runs, so a pathological string cannot
        // cause catastrophic backtracking (ReDoS).
        if (target.length() > MAX_LENGTH) {
            throw new InvalidTargetException(
                    "Target exceeds the maximum length of " + MAX_LENGTH + " characters.");
        }

        // Defence in depth. The hostname pattern already rejects a leading hyphen,
        // but this names the actual threat: Nmap would read "-iL" or "-oA" as an option.
        if (target.startsWith("-")) {
            throw new InvalidTargetException(
                    "Target must not begin with '-'; Nmap would read it as an option: "
                    + quote(target));
        }

        // Canonicalise BEFORE validating, so we validate exactly what we will use.
        target = target.toLowerCase(Locale.ROOT);
        if (target.endsWith(".")) {
            target = target.substring(0, target.length() - 1);
        }
        if (target.isEmpty()) {
            throw new InvalidTargetException("Target must not be empty.");
        }

        if (IPV4_SHAPE.matcher(target).matches()) {
            return validateIpv4(target);
        }
        if (HOSTNAME.matcher(target).matches()) {
            return validateHostname(target);
        }
        throw new InvalidTargetException(
                "Target is not a valid IPv4 address or hostname: " + quote(target));
    }

    private static String validateIpv4(String candidate) throws InvalidTargetException {
        for (String octet : candidate.split("\\.")) {
            if (octet.length() > 1 && octet.charAt(0) == '0') {
                throw new InvalidTargetException(
                        "IPv4 octets must not have leading zeros, which some resolvers "
                        + "interpret as octal: " + quote(candidate));
            }
            // Safe: the shape pattern guarantees 1-3 digits, so this cannot overflow.
            if (Integer.parseInt(octet) > 255) {
                throw new InvalidTargetException(
                        "IPv4 octet '" + octet + "' is outside the range 0-255: "
                        + quote(candidate));
            }
        }
        return candidate;
    }

    private static String validateHostname(String candidate) throws InvalidTargetException {
        String topLabel = candidate.substring(candidate.lastIndexOf('.') + 1);
        if (ALL_DIGITS.matcher(topLabel).matches()) {
            throw new InvalidTargetException(
                    "A hostname's final label must not be entirely numeric; this looks like "
                    + "a malformed or alternate-notation IP address: " + quote(candidate));
        }
        return candidate;
    }

    /**
     * Renders untrusted input for inclusion in an error message.
     * Truncates, and neutralises control characters so a crafted target cannot
     * forge log lines (log injection).
     */
    private static String quote(String value) {
        String shown = value.length() > 60 ? value.substring(0, 60) + "..." : value;
        return "'" + shown.replaceAll("\\p{Cntrl}", "?") + "'";
    }
}
