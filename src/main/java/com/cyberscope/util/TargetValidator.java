package com.cyberscope.util;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Validates a user-supplied scan target.
 *
 * <p>This is the trust boundary between untrusted input and the Nmap command line.
 * It accepts a single IPv4 address, an RFC 1123 hostname, or an IPv4 CIDR range;
 * everything else is rejected. Validation is allow-list based: unrecognised input
 * fails closed.
 *
 * <p>No DNS resolution is performed. This class checks syntax only.
 */
public final class TargetValidator {

    private static final int MAX_LENGTH = 253;

    /**
     * Smallest prefix accepted, i.e. the largest range. /24 is 256 addresses --
     * the standard LAN unit and a scan a user can reasonably wait for. Anything
     * larger needs progress reporting and resumability, which CyberScope does not
     * have yet, so it is refused rather than half-supported.
     */
    public static final int MIN_PREFIX_LENGTH = 24;

    private static final Pattern IPV4_SHAPE =
            Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");

    private static final Pattern CIDR_SHAPE =
            Pattern.compile("^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})/(\\d{1,2})$");

    private static final String LABEL = "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?";
    private static final Pattern HOSTNAME =
            Pattern.compile("^" + LABEL + "(\\." + LABEL + ")*$");

    private static final Pattern ALL_DIGITS = Pattern.compile("^\\d+$");

    private TargetValidator() {
    }

    public static ValidatedTarget validate(String raw) throws InvalidTargetException {
        if (raw == null) {
            throw new InvalidTargetException("Target must not be null.");
        }

        String target = raw.trim();

        if (target.isEmpty()) {
            throw new InvalidTargetException("Target must not be empty.");
        }
        if (target.length() > MAX_LENGTH) {
            throw new InvalidTargetException(
                    "Target exceeds the maximum length of " + MAX_LENGTH + " characters.");
        }
        if (target.startsWith("-")) {
            throw new InvalidTargetException(
                    "Target must not begin with '-'; Nmap would read it as an option: "
                    + quote(target));
        }

        target = target.toLowerCase(Locale.ROOT);
        if (target.endsWith(".")) {
            target = target.substring(0, target.length() - 1);
        }
        if (target.isEmpty()) {
            throw new InvalidTargetException("Target must not be empty.");
        }

        Matcher cidr = CIDR_SHAPE.matcher(target);
        if (cidr.matches()) {
            return validateCidr(cidr.group(1), cidr.group(2), target);
        }
        if (IPV4_SHAPE.matcher(target).matches()) {
            checkOctets(target);
            return new ValidatedTarget(target, TargetKind.IPV4, 1);
        }
        if (HOSTNAME.matcher(target).matches()) {
            return validateHostname(target);
        }
        throw new InvalidTargetException(
                "Target is not a valid IPv4 address, hostname, or CIDR range: " + quote(target));
    }

    private static ValidatedTarget validateCidr(String address, String prefixText, String original)
            throws InvalidTargetException {

        checkOctets(address);

        if (prefixText.length() > 1 && prefixText.charAt(0) == '0') {
            throw new InvalidTargetException(
                    "CIDR prefix length must not have a leading zero: " + quote(original));
        }
        int prefix = Integer.parseInt(prefixText);

        if (prefix > 32) {
            throw new InvalidTargetException(
                    "CIDR prefix length must be between " + MIN_PREFIX_LENGTH
                    + " and 32: " + quote(original));
        }
        if (prefix < MIN_PREFIX_LENGTH) {
            // 1L, not 1: an int shift count is taken modulo 32, so 1 << 32 is 1,
            // and a /0 would report "covers 1 addresses".
            long count = 1L << (32 - prefix);
            throw new InvalidTargetException(
                    "/" + prefix + " covers " + count + " addresses. CyberScope accepts at most "
                    + "/" + MIN_PREFIX_LENGTH + " (" + (1L << (32 - MIN_PREFIX_LENGTH))
                    + " addresses) so a mistyped prefix cannot start a scan you did not intend.");
        }

        // Normalise to the network address: 192.168.1.57/24 -> 192.168.1.0/24
        long bits = toLong(address);
        long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        String network = toDotted(bits & mask);

        return new ValidatedTarget(network + "/" + prefix, TargetKind.CIDR, 1 << (32 - prefix));
    }

    private static void checkOctets(String address) throws InvalidTargetException {
        for (String octet : address.split("\\.")) {
            if (octet.length() > 1 && octet.charAt(0) == '0') {
                throw new InvalidTargetException(
                        "IPv4 octets must not have leading zeros, which some resolvers "
                        + "interpret as octal: " + quote(address));
            }
            if (Integer.parseInt(octet) > 255) {
                throw new InvalidTargetException(
                        "IPv4 octet '" + octet + "' is outside the range 0-255: "
                        + quote(address));
            }
        }
    }

    private static ValidatedTarget validateHostname(String candidate) throws InvalidTargetException {
        String topLabel = candidate.substring(candidate.lastIndexOf('.') + 1);
        if (ALL_DIGITS.matcher(topLabel).matches()) {
            throw new InvalidTargetException(
                    "A hostname's final label must not be entirely numeric; this looks like "
                    + "a malformed or alternate-notation IP address: " + quote(candidate));
        }
        return new ValidatedTarget(candidate, TargetKind.HOSTNAME, 1);
    }

    private static long toLong(String address) {
        String[] o = address.split("\\.");
        return (Long.parseLong(o[0]) << 24) | (Long.parseLong(o[1]) << 16)
             | (Long.parseLong(o[2]) << 8) | Long.parseLong(o[3]);
    }

    private static String toDotted(long bits) {
        return ((bits >> 24) & 0xFF) + "." + ((bits >> 16) & 0xFF) + "."
             + ((bits >> 8) & 0xFF) + "." + (bits & 0xFF);
    }

    /**
     * Renders untrusted input for an error message. Truncates, and neutralises
     * control characters so a crafted target cannot forge log lines.
     */
    private static String quote(String value) {
        String shown = value.length() > 60 ? value.substring(0, 60) + "..." : value;
        return "'" + shown.replaceAll("\\p{Cntrl}", "?") + "'";
    }
}
