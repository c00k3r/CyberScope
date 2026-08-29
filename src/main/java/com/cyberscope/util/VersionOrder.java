package com.cyberscope.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Orders software version strings.
 *
 * <p><b>This class is approximate and says so.</b> Version strings are not numbers
 * and there is no algorithm that reads only the string and is right every time.
 * The proof is two lines long:
 *
 * <pre>
 *   1.0rc1  &lt;  1.0     "rc" means release candidate -- before
 *   9.6p1   &gt;  9.6     "p"  means portable release  -- after
 * </pre>
 *
 * <p>Same syntactic shape, opposite meaning, decided by project convention that is
 * nowhere in the string. So this class does the best a string-only comparator can:
 * it compares numerically where the tokens are numeric, and it consults a short
 * table of unambiguous pre-release markers where they are not.
 *
 * <p><b>It is deliberately not a {@link java.util.Comparator}.</b> Some pairs are
 * genuinely incomparable and this class returns {@code null} for them. A Comparator
 * that returned an answer anyway would violate the interface contract, and
 * {@code Collections.sort} punishes that with a runtime exception. Refusing to
 * implement an interface you cannot honour is safer than implementing it badly.
 *
 * <h2>The algorithm</h2>
 * <ol>
 *   <li>Tokenise into maximal runs of digits and maximal runs of letters. All other
 *       characters ({@code . - _ + ~ /}) are separators and are discarded.</li>
 *   <li>Compare token by token. Numeric tokens compare as integers, so
 *       {@code 1.10 > 1.9}. Alphabetic tokens compare lexically, lower-cased.</li>
 *   <li>A numeric token outranks an alphabetic token in the same position, so
 *       {@code 1.2 > 1.rc}.</li>
 *   <li>If one string runs out first, the longer one continues. A <em>numeric</em>
 *       continuation means later ({@code 1.0.1 > 1.0}). An <em>alphabetic</em>
 *       continuation means later too ({@code 9.6p1 > 9.6}) <b>unless</b> the token
 *       is a known pre-release marker, in which case it means earlier
 *       ({@code 1.0rc1 < 1.0}).</li>
 * </ol>
 */
public final class VersionOrder {

    /**
     * Tokens that unambiguously mean "before the release".
     *
     * <p>Every entry is multi-character on purpose. Single letters were measured
     * against the real corpus and rejected: {@code m} alone appears 8,801 times
     * across NVD's version bounds and in that data it is nearly always an OpenSSL-
     * style sequence letter ({@code 1.0.2m}, meaning <em>later</em>), not a Spring-
     * style milestone marker. Including it would have inverted thousands of
     * comparisons. See the note in the design document.
     */
    private static final Set<String> PRE_RELEASE = Set.of(
            "alpha", "beta", "rc", "pre", "dev", "snapshot",
            "milestone", "preview", "nightly");

    private static final Pattern TOKEN = Pattern.compile("\\d+|[A-Za-z]+");

    private VersionOrder() {
    }

    /**
     * Compares two version strings.
     *
     * @return negative if {@code a} is earlier, zero if equal, positive if later,
     *         or <b>{@code null} if the two cannot be compared</b> -- which happens
     *         when either string contains no digits and no letters at all. Callers
     *         must treat null as "unknown", never as "equal".
     */
    public static Integer compare(String a, String b) {
        List<Token> left = tokenise(a);
        List<Token> right = tokenise(b);
        if (left.isEmpty() || right.isEmpty()) {
            return null;
        }
        int shared = Math.min(left.size(), right.size());
        for (int i = 0; i < shared; i++) {
            int c = left.get(i).compareTo(right.get(i));
            if (c != 0) {
                return c;
            }
        }
        if (left.size() == right.size()) {
            return 0;
        }
        boolean leftIsLonger = left.size() > right.size();
        Token next = (leftIsLonger ? left : right).get(shared);
        int sign = leftIsLonger ? 1 : -1;
        if (next.numeric) {
            return sign;                                    // 1.0.1 > 1.0
        }
        return PRE_RELEASE.contains(next.text) ? -sign : sign;  // rc -> earlier, p -> later
    }

    /** {@code true} when {@code version} is inside the bounds. Null bounds are open. */
    public static boolean isWithin(String version,
                                   String startIncluding, String startExcluding,
                                   String endIncluding, String endExcluding) {
        return atLeast(version, startIncluding)
            && greaterThan(version, startExcluding)
            && atMost(version, endIncluding)
            && lessThan(version, endExcluding);
    }

    // Each guard returns true when the bound is absent (open) and false when the
    // comparison is undecidable. "We could not tell" must never widen a match --
    // a vulnerability scanner that guesses in favour of a hit produces false
    // positives, and a scanner nobody trusts gets switched off.

    private static boolean atLeast(String v, String bound) {
        if (bound == null) return true;
        Integer c = compare(v, bound);
        return c != null && c >= 0;
    }

    private static boolean greaterThan(String v, String bound) {
        if (bound == null) return true;
        Integer c = compare(v, bound);
        return c != null && c > 0;
    }

    private static boolean atMost(String v, String bound) {
        if (bound == null) return true;
        Integer c = compare(v, bound);
        return c != null && c <= 0;
    }

    private static boolean lessThan(String v, String bound) {
        if (bound == null) return true;
        Integer c = compare(v, bound);
        return c != null && c < 0;
    }

    // ------------------------------------------------------------- tokens

    private static List<Token> tokenise(String version) {
        List<Token> tokens = new ArrayList<>();
        if (version == null) {
            return tokens;
        }
        Matcher m = TOKEN.matcher(version);
        while (m.find()) {
            String text = m.group();
            if (Character.isDigit(text.charAt(0))) {
                tokens.add(Token.number(text));
            } else {
                tokens.add(Token.word(text.toLowerCase(Locale.ROOT)));
            }
        }
        return tokens;
    }

    /**
     * One run of digits or one run of letters.
     *
     * <p>Numeric values are held as {@code long} rather than {@code int}: NVD
     * contains Go module pseudo-versions such as
     * {@code 0.0.0-20200220183623-bac4c82f6975}, whose timestamp component
     * overflows a 32-bit int. There are 1,283 such bound strings in the corpus.
     * Anything longer than 18 digits falls back to length-then-lexical comparison
     * rather than overflowing a long as well.
     */
    private record Token(boolean numeric, String text, long value) {

        static Token number(String text) {
            String trimmed = text.replaceFirst("^0+(?=\\d)", "");   // 007 -> 7
            long value = trimmed.length() <= 18 ? Long.parseLong(trimmed) : -1L;
            return new Token(true, trimmed, value);
        }

        static Token word(String text) {
            return new Token(false, text, 0L);
        }

        int compareTo(Token other) {
            if (numeric != other.numeric) {
                return numeric ? 1 : -1;         // a number outranks a word
            }
            if (!numeric) {
                return text.compareTo(other.text);
            }
            if (value >= 0 && other.value >= 0) {
                return Long.compare(value, other.value);
            }
            // At least one is too long for a long. Longer digit string wins;
            // equal length falls back to lexical, which is correct for digits.
            int byLength = Integer.compare(text.length(), other.text.length());
            return byLength != 0 ? byLength : text.compareTo(other.text);
        }
    }
}