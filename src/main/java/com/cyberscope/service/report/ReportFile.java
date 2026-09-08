package com.cyberscope.service.report;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 * What a report file is called.
 *
 * <h2>A target string is not a filename</h2>
 *
 * The obvious implementation is {@code "cyberscope-" + target + ".html"}, and it
 * is wrong the first time someone scans a subnet:
 *
 * <pre>
 *   target  192.168.1.0/24
 *   name    cyberscope-192.168.1.0/24-20260907.html
 *                                   ^ a path separator
 * </pre>
 *
 * On Linux that silently writes into a directory that probably does not exist;
 * on Windows it is simply invalid. Both are the same underlying mistake:
 * <b>the target is user input being used to construct a path</b>, and every
 * character in it was chosen by someone else.
 *
 * <p>It gets worse than a CIDR slash. A hostname is validated by
 * {@code TargetValidator} before a scan runs, but this class is also handed the
 * target of a <i>stored</i> scan, which came out of a database that has been
 * through several schema versions. Treating that as trusted because it was
 * validated once, in a different version, is exactly the assumption that turns
 * into a path traversal.
 *
 * <p>So the rule here is an <b>allowlist</b>, not a blocklist. Only letters,
 * digits, dot, hyphen and underscore survive; everything else becomes an
 * underscore. A blocklist of "dangerous characters" is a list you have to keep
 * complete forever, and the first thing anyone forgets is the one that matters.
 */
public final class ReportFile {

    /** Long enough to stay readable, short enough for every filesystem. */
    static final int MAX_TARGET_CHARS = 40;

    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd-HHmm");

    private ReportFile() {
    }

    /** e.g. {@code cyberscope-192.168.1.0_24-20260907-1436.html} */
    public static String nameFor(String target, Instant when, ZoneId zone) {
        return "cyberscope-" + slug(target) + "-" + STAMP.format(when.atZone(zone)) + ".html";
    }

    /** e.g. {@code cyberscope-network-20260907-1436.html} */
    public static String networkName(Instant when, ZoneId zone) {
        return "cyberscope-network-" + STAMP.format(when.atZone(zone)) + ".html";
    }

    /**
     * The target, reduced to characters that are safe in a filename.
     *
     * <p>Three separate guards, and each one exists because of a specific way
     * the naive version fails:
     *
     * <ul>
     *   <li><b>Allowlist</b> -- a slash in a CIDR, a colon in an IPv6 address, a
     *       {@code ..} in anything hostile.</li>
     *   <li><b>Collapse and trim underscores</b> -- so {@code ../../etc} does not
     *       become the visually confusing {@code ______etc}.</li>
     *   <li><b>Non-empty fallback</b> -- a target of {@code "///"} sanitises to
     *       nothing at all, and a filename of {@code cyberscope--20260907.html}
     *       is a worse outcome than saying "unnamed".</li>
     * </ul>
     */
    static String slug(String target) {
        if (target == null || target.isBlank()) {
            return "unnamed";
        }
        StringBuilder out = new StringBuilder(target.length());
        for (char c : target.trim().toCharArray()) {
            boolean safe = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
            out.append(safe ? c : '_');
        }
        String slug = out.toString()
                .replaceAll("_{2,}", "_")     // ../../ would otherwise be a run of them
                .replaceAll("^[._-]+", "")    // a leading dot makes a hidden file
                .replaceAll("[._-]+$", "");

        if (slug.length() > MAX_TARGET_CHARS) {
            slug = slug.substring(0, MAX_TARGET_CHARS).replaceAll("[._-]+$", "");
        }
        return slug.isEmpty() ? "unnamed" : slug.toLowerCase(Locale.ROOT);
    }
}
