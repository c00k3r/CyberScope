package com.cyberscope.model;

import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Which findings the Vulnerabilities page is showing.
 *
 * <p>Pure and immutable, so the filtering rules are unit-tested and the page is
 * left with nothing but wiring. Every control on that page maps to one field
 * here, and {@link #apply} is the only place a finding is ever excluded.
 *
 * <h2>The rule that makes a filter safe in a security tool</h2>
 *
 * A filter hides evidence. That is its job, and it is also how a scanner
 * produces a false negative without a single bug: someone narrows the list,
 * forgets, and reads "3 findings" as "there are 3 findings". So the page always
 * renders <b>both</b> numbers -- showing X of Y -- and {@link #isActive} exists
 * so it can say plainly when something is being hidden.
 *
 * @param text          matched against target, product, port and CVE id
 * @param exploitedOnly only findings CISA KEV lists as exploited
 * @param minUrgency    the lowest urgency band to include, never null
 */
public record FindingFilter(String text, boolean exploitedOnly, ExposureBand minUrgency) {

    public FindingFilter {
        text = text == null ? "" : text.strip();
        minUrgency = minUrgency == null ? ExposureBand.CLEAR : minUrgency;
    }

    /** Everything. The state the page opens in. */
    public static FindingFilter none() {
        return new FindingFilter("", false, ExposureBand.CLEAR);
    }

    public FindingFilter withText(String value) {
        return new FindingFilter(value, exploitedOnly, minUrgency);
    }

    public FindingFilter withExploitedOnly(boolean value) {
        return new FindingFilter(text, value, minUrgency);
    }

    public FindingFilter withMinUrgency(ExposureBand value) {
        return new FindingFilter(text, exploitedOnly, value);
    }

    /** True when this filter can hide something, so the page can say so. */
    public boolean isActive() {
        return !text.isEmpty() || exploitedOnly || minUrgency != ExposureBand.CLEAR;
    }

    /**
     * Does one finding survive the filter?
     *
     * <p>The text match is case-insensitive and matches a <i>substring</i> of any
     * of four fields. Substring rather than prefix because the fields people
     * search are not things they know the start of: "6387" should find
     * CVE-2024-6387, and "nginx" should find "f5:nginx 1.24.0".
     */
    public boolean matches(NetworkPosture.Action action) {
        Objects.requireNonNull(action, "action");
        RankedFinding finding = action.finding();

        if (exploitedOnly && !finding.vulnerability().signal().isKnownExploited()) {
            return false;
        }
        if (finding.urgency().rank() < minUrgency.rank()) {
            return false;
        }
        if (text.isEmpty()) {
            return true;
        }
        String needle = text.toLowerCase(Locale.ROOT);
        return contains(action.target(), needle)
            || contains(finding.product(), needle)
            || contains(finding.where(), needle)
            || contains(finding.vulnerability().cveId(), needle);
    }

    private static boolean contains(String haystack, String needle) {
        return haystack != null && haystack.toLowerCase(Locale.ROOT).contains(needle);
    }

    /** @return the surviving findings, in the order they were given */
    public List<NetworkPosture.Action> apply(List<NetworkPosture.Action> all) {
        return all.stream().filter(this::matches).toList();
    }

    /** e.g. {@code showing 12 of 211 findings  ·  exploited only} */
    public String describe(int shown, int total) {
        StringBuilder out = new StringBuilder();
        out.append("showing ").append(shown).append(" of ").append(total)
           .append(total == 1 ? " finding" : " findings");
        if (!isActive()) {
            return out.toString();
        }
        out.append("  ·  filtered by");
        if (!text.isEmpty()) {
            out.append(" \"").append(text).append('"');
        }
        if (exploitedOnly) {
            out.append(text.isEmpty() ? " " : ", ").append("exploited only");
        }
        if (minUrgency != ExposureBand.CLEAR) {
            out.append(", ").append(minUrgency.label().toLowerCase(Locale.ROOT))
               .append(" and above");
        }
        return out.toString();
    }
}
