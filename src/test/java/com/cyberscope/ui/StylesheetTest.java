package com.cyberscope.ui;

import javafx.css.CssParser;
import javafx.css.Stylesheet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A linter for {@code app.css}.
 *
 * <h2>Why a stylesheet needs a test at all</h2>
 *
 * JavaFX CSS fails <b>silently</b>, in three different ways, and every one of
 * them looks identical to "the designer chose not to colour that":
 *
 * <ol>
 *   <li>A looked-up colour that was never defined is <b>ignored</b>. The
 *       declaration is dropped and the node keeps its inherited value. No
 *       warning, no exception, no entry in the log.</li>
 *   <li>A selector that matches nothing is ignored, so a style class renamed in
 *       Java and not in the CSS simply stops applying.</li>
 *   <li>A malformed value is dropped per-declaration, so the rest of the block
 *       still applies and the node looks <i>almost</i> right.</li>
 * </ol>
 *
 * This project has already paid for (1). {@code -cs-worse} and {@code -cs-better}
 * were used by the v0.4.0 comparison colours and the v0.5.0 vulnerability column
 * and defined by nothing, so both features shipped with their colour coding
 * quietly inert -- through code review, through a screenshot, through a release.
 * The tokens were misremembered names for {@code -cs-danger} and
 * {@code -cs-probed}.
 *
 * <p>The compiler cannot catch this because CSS is a resource, not code. So the
 * test suite does, by parsing the sheet the same way the renderer will.
 *
 * <h2>Rule 3 is the one that buys the dark theme</h2>
 *
 * The third test forbids colour literals outside {@code .root}. That is not
 * tidiness: it is the property that makes retheming a change to one block
 * instead of an archaeology exercise. A single {@code #fafbfd} left behind in a
 * row-striping rule is invisible in the light theme and glows in the dark one.
 */
class StylesheetTest {

    private static final String SHEET = "/css/app.css";

    /** {@code -cs-name} anywhere. */
    private static final Pattern TOKEN = Pattern.compile("-cs-[a-z0-9-]+");

    /** A declaration: {@code   -cs-bg: #fff;} or {@code   -fx-text-fill: -cs-text;} */
    private static final Pattern DECLARATION =
            Pattern.compile("^\\s*(-[a-z0-9-]+)\\s*:\\s*(.*?);?\\s*$");

    private static final Pattern HEX = Pattern.compile("#[0-9a-fA-F]{3,8}\\b");

    private static final Pattern FUNCTION =
            Pattern.compile("\\b(rgb|rgba|hsb|hsba)\\s*\\(", Pattern.CASE_INSENSITIVE);

    /**
     * CSS named colours a theme would have to change. {@code transparent} is
     * deliberately absent -- it means "draw nothing", which is theme-independent,
     * and it is used throughout to switch borders off.
     */
    private static final Set<String> NAMED_COLOURS = Set.of(
            "white", "black", "red", "green", "blue", "yellow", "orange", "purple",
            "gray", "grey", "silver", "maroon", "navy", "teal", "olive", "lime",
            "aqua", "cyan", "magenta", "fuchsia", "pink", "brown", "gold", "beige",
            "ivory", "khaki", "salmon", "coral", "crimson", "indigo", "violet",
            "turquoise", "tan", "wheat", "azure", "lavender", "plum", "orchid");

    /** A property whose value is a colour. */
    private static boolean carriesColour(String property) {
        return property.endsWith("-color") || property.endsWith("-fill");
    }

    // ------------------------------------------------------------------
    // the sheet, as the renderer sees it
    // ------------------------------------------------------------------

    /** Source with comments removed, so a colour named in prose is not a finding. */
    private static String source() {
        try (InputStream in = StylesheetTest.class.getResourceAsStream(SHEET)) {
            assertTrue(in != null, SHEET + " is not on the test classpath");
            String raw = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            // Non-greedy, DOTALL: JavaFX CSS has no // comments, only /* */.
            return raw.replaceAll("(?s)/\\*.*?\\*/", "");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Line-numbered declarations, paired with the selector block they sit in. */
    private record Decl(int line, String selector, String property, String value) {
    }

    private static List<Decl> declarations() {
        List<Decl> out = new ArrayList<>();
        String selector = "(none)";
        int line = 0;
        for (String text : source().split("\n", -1)) {
            line++;
            String trimmed = text.strip();
            if (trimmed.isEmpty()) {
                continue;
            }
            if (trimmed.endsWith("{")) {
                selector = trimmed.substring(0, trimmed.length() - 1).strip();
                continue;
            }
            if (trimmed.equals("}")) {
                selector = "(none)";
                continue;
            }
            // A multi-line selector list ends on the line with the brace; the
            // earlier lines end in a comma and carry no colon.
            Matcher m = DECLARATION.matcher(trimmed);
            if (m.matches()) {
                out.add(new Decl(line, selector, m.group(1), m.group(2).strip()));
            }
        }
        return out;
    }

    private static boolean isTokenBlock(String selector) {
        return selector.equals(".root");
    }

    // ------------------------------------------------------------------
    // 1. every token used is defined
    // ------------------------------------------------------------------

    @Test
    @DisplayName("every -cs- token that is used is also defined")
    void noUndefinedTokens() {
        Set<String> defined = new LinkedHashSet<>();
        for (Decl d : declarations()) {
            if (d.property().startsWith("-cs-")) {
                defined.add(d.property());
            }
        }
        assertFalse(defined.isEmpty(), "parser found no token definitions at all");

        List<String> problems = new ArrayList<>();
        for (Decl d : declarations()) {
            Matcher m = TOKEN.matcher(d.value());
            while (m.find()) {
                if (!defined.contains(m.group())) {
                    problems.add("line " + d.line() + "  " + d.selector()
                            + " { " + d.property() + ": ... " + m.group()
                            + " } is never defined -- JavaFX will drop this declaration");
                }
            }
        }
        assertTrue(problems.isEmpty(),
                "undefined looked-up colours:\n  " + String.join("\n  ", problems));
    }

    // ------------------------------------------------------------------
    // 2. every token defined is used
    // ------------------------------------------------------------------

    @Test
    @DisplayName("no token is defined and then never used")
    void noDeadTokens() {
        Set<String> defined = new LinkedHashSet<>();
        Set<String> used = new LinkedHashSet<>();
        for (Decl d : declarations()) {
            if (d.property().startsWith("-cs-")) {
                defined.add(d.property());
            }
            Matcher m = TOKEN.matcher(d.value());
            while (m.find()) {
                used.add(m.group());
            }
        }
        defined.removeAll(used);
        assertTrue(defined.isEmpty(),
                "tokens defined but never referenced (delete them or wire them up): " + defined);
    }

    // ------------------------------------------------------------------
    // 3. colour literals live in one block
    // ------------------------------------------------------------------

    @Test
    @DisplayName("no colour literal appears outside the .root token block")
    void allColoursAreTokenised() {
        List<String> problems = new ArrayList<>();
        for (Decl d : declarations()) {
            if (isTokenBlock(d.selector()) || !carriesColour(d.property())) {
                continue;
            }
            String value = d.value();
            Matcher hex = HEX.matcher(value);
            while (hex.find()) {
                problems.add("line " + d.line() + "  " + d.selector()
                        + " { " + d.property() + ": " + value + " }  literal " + hex.group());
            }
            Matcher fn = FUNCTION.matcher(value);
            if (fn.find()) {
                problems.add("line " + d.line() + "  " + d.selector()
                        + " { " + d.property() + ": " + value + " }  " + fn.group(1) + "()");
            }
            for (String word : value.toLowerCase(Locale.ROOT).split("[^a-z]+")) {
                if (NAMED_COLOURS.contains(word)) {
                    problems.add("line " + d.line() + "  " + d.selector()
                            + " { " + d.property() + ": " + value + " }  named colour '" + word + "'");
                }
            }
        }
        assertTrue(problems.isEmpty(),
                problems.size() + " colour literal(s) outside .root -- each one is a value a "
                        + "theme switch cannot reach:\n  " + String.join("\n  ", problems));
    }

    // ------------------------------------------------------------------
    // 4. every style class named in Java has a rule
    // ------------------------------------------------------------------

    @Test
    @DisplayName("every style class constant in Styles has a matching selector")
    void everyStyleConstantIsStyled() {
        String css = source();
        List<String> missing = new ArrayList<>();
        for (java.lang.reflect.Field field : Styles.class.getDeclaredFields()) {
            if (!java.lang.reflect.Modifier.isStatic(field.getModifiers())
                    || field.getType() != String.class) {
                continue;
            }
            field.setAccessible(true);
            String name;
            try {
                name = (String) field.get(null);
            } catch (IllegalAccessException e) {
                throw new AssertionError(e);
            }
            if (name == null || name.startsWith("/")) {
                continue;   // the stylesheet path, not a style class
            }
            if (!Pattern.compile("\\." + Pattern.quote(name) + "\\b").matcher(css).find()) {
                missing.add(Styles.class.getSimpleName() + "." + field.getName()
                        + " = \"" + name + "\" -- no `." + name + "` rule; the class applies nothing");
            }
        }
        assertTrue(missing.isEmpty(),
                "style classes with no rule:\n  " + String.join("\n  ", missing));
    }

    // ------------------------------------------------------------------
    // 5. the renderer's own parser keeps every rule
    // ------------------------------------------------------------------

    /**
     * The rule that would have caught the worst CSS bug this project has had.
     *
     * <p>The four rules above are enforced by the hand-written parser in this
     * class. That parser is not the one JavaFX uses, and the gap between them is
     * where a whole stylesheet went missing:
     *
     * <pre>
     *   WARNING: CSS Error parsing app.css: Expected LBRACE at [295,4]
     *   rules parsed by JavaFX: 31
     *   blocks in the file    : 117
     * </pre>
     *
     * A selector broken across two lines at a combinator -- legal in web CSS,
     * rejected by JavaFX -- made the parser <b>abandon the remainder of the
     * file</b>. Eighty-six rules vanished, the application rendered from line 295
     * down in Modena's light defaults, and every check in this class still
     * passed, because a text parser reading line by line does not care where the
     * renderer gave up.
     *
     * <p>The fix is to stop guessing and ask the renderer. {@link CssParser} is
     * public API in {@code javafx.css} and needs no toolkit and no display, so
     * the real parser runs in a plain unit test. If it keeps fewer rules than the
     * file has blocks, something was dropped -- and the message says where it
     * stopped, which is the line to look at.
     */
    @Test
    @DisplayName("JavaFX's own parser keeps every rule in the file")
    void javaFxParsesEveryRule() throws IOException {
        URL url = StylesheetTest.class.getResource(SHEET);
        assertTrue(url != null, SHEET + " is not on the test classpath");

        Stylesheet parsed = new CssParser().parse(url);
        long blocks = source().chars().filter(c -> c == '{').count();
        int kept = parsed.getRules().size();

        String lastKept = kept == 0 ? "(nothing)"
                : String.valueOf(parsed.getRules().get(kept - 1).getSelectors());
        assertEquals(blocks, kept,
                "JavaFX kept " + kept + " of " + blocks + " rules. It stops at the first "
              + "selector it cannot parse and DISCARDS THE REST OF THE FILE, at WARNING "
              + "level only. The last rule it accepted was " + lastKept
              + " -- the breakage is immediately after it. A selector split across "
              + "lines at a combinator is the usual cause.");
    }

    // ------------------------------------------------------------------
    // 6. the parser in this file
    // ------------------------------------------------------------------

    @Test
    @DisplayName("the parser attributes declarations to the right block")
    void parserAttributesDeclarationsToBlocks() {
        List<Decl> decls = declarations();
        assertTrue(decls.stream().anyMatch(d -> d.property().equals("-cs-bg")
                        && isTokenBlock(d.selector())),
                "-cs-bg should have been found inside .root");
        assertEquals(0, decls.stream().filter(d -> d.selector().equals("(none)")).count(),
                "every declaration should sit inside a block");
    }
}
