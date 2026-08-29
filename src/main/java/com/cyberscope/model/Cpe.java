package com.cyberscope.model;

import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * A parsed CPE, reduced to the four fields CyberScope can act on.
 *
 * <p>A CPE 2.3 formatted string has eleven fields. CyberScope keeps four --
 * part, vendor, product, version -- because the other seven (update, edition,
 * sw_edition, target_sw, target_hw, other, language) are {@code *} in every row
 * Nmap can produce and in the overwhelming majority of NVD rows. Storing fields
 * we never read would invite matching on them, and matching on a field that is
 * always {@code *} is a way to write a condition that is always true.
 *
 * <p><b>Values are stored unescaped and lower-cased.</b> CPE is defined to be
 * case-insensitive, and both sides of every comparison in CyberScope go through
 * this class, so normalising once here removes a class of bug where
 * {@code Apache} fails to match {@code apache}.
 *
 * <p><b>Known limitation.</b> The field splitter treats a colon preceded by a
 * backslash as escaped. That is wrong for a literal backslash immediately before
 * a separator ({@code ...\\:...}), which should split. No such value exists in
 * the NVD corpus (checked against all 121,229 distinct vendor:product pairs) or
 * in nmap-service-probes, so the rule is sound for both data sources CyberScope
 * reads. It is written down here rather than discovered later.
 *
 * @param part    a, o or h
 * @param vendor  never null; {@link #ANY} when the CPE said {@code *}
 * @param product never null; {@link #ANY} when the CPE said {@code *}
 * @param version never null; {@link #ANY} when the CPE said {@code *}
 */
public record Cpe(CpePart part, String vendor, String product, String version) {

    /** The CPE wildcard: "any value". */
    public static final String ANY = "*";

    /** The CPE "not applicable" marker. */
    public static final String NOT_APPLICABLE = "-";

    /** Split on a colon that is not backslash-escaped. See the class note. */
    private static final Pattern FIELD = Pattern.compile("(?<!\\\\):");

    private static final String PREFIX_23 = "cpe:2.3:";
    private static final String PREFIX_22 = "cpe:/";

    public Cpe {
        if (part == null) {
            throw new IllegalArgumentException("part must not be null");
        }
        vendor = normalise(vendor);
        product = normalise(product);
        version = normalise(version);
    }

    /**
     * Parses a CPE 2.3 formatted string.
     *
     * @return empty if the string is not a CPE 2.3, has fewer than six fields,
     *         or names a part other than a/o/h
     */
    public static Optional<Cpe> parse23(String text) {
        if (text == null || !text.startsWith(PREFIX_23)) {
            return Optional.empty();
        }
        String[] fields = FIELD.split(text, -1);   // -1 keeps trailing empties
        // cpe | 2.3 | part | vendor | product | version | ...
        if (fields.length < 6) {
            return Optional.empty();
        }
        return CpePart.fromCode(fields[2])
                .map(part -> new Cpe(part, fields[3], fields[4], fields[5]));
    }

    /**
     * Parses a CPE 2.2 URI -- the form Nmap emits, and the only form it emits.
     *
     * <p>2.2 has seven fields to 2.3's eleven and its trailing fields may simply
     * be absent, so this pads rather than indexing blind. {@code cpe:/a:openbsd:openssh}
     * with no version is a legitimate 2.2 URI and becomes {@link #ANY} here, which is
     * what makes {@link #hasConcreteVersion()} the right question to ask later.
     */
    public static Optional<Cpe> parse22(String text) {
        if (text == null || !text.startsWith(PREFIX_22)) {
            return Optional.empty();
        }
        String body = text.substring(PREFIX_22.length());
        // Nmap writes a trailing slash on templates: cpe:/a:openbsd:openssh/
        while (body.endsWith("/")) {
            body = body.substring(0, body.length() - 1);
        }
        String[] fields = FIELD.split(body, -1);
        // part | vendor | product | version | update | edition | language
        if (fields.length < 3) {
            return Optional.empty();
        }
        String version = fields.length > 3 ? fields[3] : ANY;
        return CpePart.fromCode(fields[0])
                .map(part -> new Cpe(part, fields[1], fields[2], version));
    }

    /** Accepts either binding. Useful where the source is not known statically. */
    public static Optional<Cpe> parse(String text) {
        if (text == null) {
            return Optional.empty();
        }
        return text.startsWith(PREFIX_23) ? parse23(text) : parse22(text);
    }

    /**
     * True when this CPE names a specific version we could match a range against.
     *
     * <p>{@code *} and {@code -} are not versions. A CPE without a concrete version
     * is the {@code NOT_APPLICABLE} outcome in Part 3 -- there is nothing to compare.
     */
    public boolean hasConcreteVersion() {
        return !ANY.equals(version) && !NOT_APPLICABLE.equals(version) && !version.isBlank();
    }

    /** True when vendor and product are both concrete enough to key a lookup. */
    public boolean isSearchable() {
        return !ANY.equals(vendor) && !vendor.isBlank()
            && !ANY.equals(product) && !product.isBlank();
    }

    /** The CPE 2.3 formatted string, padded to the full eleven fields. */
    public String to23String() {
        return PREFIX_23 + part.code() + ':' + vendor + ':' + product + ':' + version
             + ":*:*:*:*:*:*:*";
    }

    /** {@code vendor:product} -- the key every index lookup uses. */
    public String productKey() {
        return vendor + ':' + product;
    }

    private static String normalise(String value) {
        if (value == null || value.isBlank()) {
            return ANY;
        }
        // Unescape, then lower-case. Order matters: "\\:" must become ":" before
        // any further processing, and Locale.ROOT keeps the Turkish dotless-i out
        // of a security lookup. (In tr-TR, "I".toLowerCase() is not "i".)
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' && i + 1 < value.length()) {
                out.append(value.charAt(++i));
            } else {
                out.append(c);
            }
        }
        return out.toString().toLowerCase(Locale.ROOT);
    }
}