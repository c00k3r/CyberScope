package com.cyberscope;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The layering rules, as a build gate rather than a habit.
 *
 * <p>Every rule below has been checked by hand with {@code grep} at the end of
 * each version since v0.2.0. That works exactly as long as someone remembers,
 * and the value of a boundary is that it holds on the day nobody is thinking
 * about it. The check costs about 40 ms; running it by hand costs a decision
 * every release.
 *
 * <pre>
 *   ui/  ->  service/  ->  repository/  ->  SQLite
 *            model/ and util/ are shared and depend on nothing above them
 * </pre>
 *
 * <p>These are all "does this file import that" rules, which is why plain text
 * is enough and there is no ArchUnit dependency. The imports are the boundary;
 * anything subtler than an import is not something a static rule was going to
 * catch anyway.
 */
class ArchitectureTest {

    private static final Path SOURCE = Path.of("src", "main", "java", "com", "cyberscope");

    /** Every .java file under a package, with comments stripped. */
    private record Source(Path path, String text) {
    }

    private static List<Source> sourcesIn(String... packages) {
        List<Source> out = new ArrayList<>();
        assertTrue(Files.isDirectory(SOURCE),
                "expected to run from the project root; " + SOURCE.toAbsolutePath()
              + " is not a directory");
        for (String pkg : packages) {
            Path dir = SOURCE.resolve(pkg);
            if (!Files.isDirectory(dir)) {
                continue;
            }
            try (Stream<Path> walk = Files.walk(dir)) {
                walk.filter(p -> p.toString().endsWith(".java")).forEach(p -> {
                    try {
                        // Comments are stripped everywhere: this file is full of
                        // prose that names the very things the rules forbid, and
                        // a rule that fires on its own explanation is useless.
                        String text = Files.readString(p)
                                .replaceAll("(?s)/\\*.*?\\*/", "")
                                .replaceAll("(?m)//.*$", "");
                        out.add(new Source(p, text));
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                });
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        assertTrue(!out.isEmpty(), "no sources found under " + List.of(packages));
        return out;
    }

    /** Line-by-line. Right for import rules, which are always one line. */
    private static void forbid(String rule, Pattern forbidden, String... packages) {
        List<String> violations = new ArrayList<>();
        for (Source source : sourcesIn(packages)) {
            source.text().lines().forEach(line -> {
                if (forbidden.matcher(line).find()) {
                    violations.add(source.path() + "\n      " + line.strip());
                }
            });
        }
        report(rule, violations);
    }

    /**
     * Whole-file. Right for SQL, which is routinely split across concatenated
     * string literals, so {@code "SELECT id, target"} and {@code "FROM scans"}
     * are two lines and neither is a statement on its own.
     */
    private static void forbidAnywhere(String rule, Pattern forbidden, String... packages) {
        List<String> violations = new ArrayList<>();
        for (Source source : sourcesIn(packages)) {
            java.util.regex.Matcher m = forbidden.matcher(source.text());
            while (m.find()) {
                violations.add(source.path() + "\n      "
                        + m.group().replaceAll("\\s+", " ").strip());
            }
        }
        report(rule, violations);
    }

    private static void report(String rule, List<String> violations) {
        assertTrue(violations.isEmpty(),
                rule + "\n  " + violations.size() + " violation(s):\n    "
                + String.join("\n    ", violations));
    }

    @Test
    @DisplayName("no JavaFX below ui/ -- the domain must be runnable without a display")
    void noJavaFxBelowUi() {
        forbid("Only ui/ may import javafx. Everything below it has to run in a "
             + "test, in the CLI, and on a machine with no display -- which is not "
             + "hypothetical: the JavaFX toolkit will not start in this project's "
             + "own test environment.",
                Pattern.compile("^\\s*import\\s+javafx\\."),
                "model", "repository", "service", "util");
    }

    /**
     * SQL statement <b>shapes</b>, not SQL keywords.
     *
     * <p>The first version of this matched the keywords alone, and failed on
     * three lines of UI copy: "Select a scan to see its results." A rule that
     * fires on its own product's English is a rule that gets an
     * {@code @Disabled} on it within a week, so it has to be tight enough to
     * mean something. Every branch below requires a second clause -- a FROM, an
     * INTO, a SET -- which prose does not have.
     *
     * <p>{@code DOTALL} because a query is usually several concatenated
     * literals, and the reluctant {@code .{0,300}?} keeps a stray SELECT from
     * pairing with a FROM four methods away.
     */
    private static final Pattern SQL_STATEMENT = Pattern.compile(
            "\\bSELECT\\b.{0,300}?\\bFROM\\b"
          + "|\\bINSERT\\s+INTO\\s+\\w"
          + "|\\bUPDATE\\s+\\w+\\s+SET\\b"
          + "|\\bDELETE\\s+FROM\\s+\\w"
          + "|\\bCREATE\\s+(TABLE|INDEX|UNIQUE\\s+INDEX|VIEW)\\b"
          + "|\\bALTER\\s+TABLE\\s+\\w"
          + "|\\bDROP\\s+TABLE\\b"
          + "|\\bPRAGMA\\s+\\w+",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    @Test
    @DisplayName("no SQL outside repository/ -- persistence stays behind the repository")
    void noSqlOutsideRepository() {
        forbidAnywhere("SQL belongs in repository/. A query anywhere else means the "
             + "schema has leaked into code that is supposed to be able to ignore it.",
                SQL_STATEMENT, "model", "service", "ui", "util");
    }

    @Test
    @DisplayName("the SQL rule matches statements, not the English word 'select'")
    void sqlRuleIsNotFooledByProse() {
        List<String> prose = List.of(
                "\"Select a scan to see its results.\"",
                "\"Select two scans to compare them.\"",
                "\"No results yet. Update the index, then scan.\"",
                "\"Delete removes the scan and its ports.\"");
        for (String line : prose) {
            assertTrue(!SQL_STATEMENT.matcher(line).find(),
                    "the SQL rule fires on ordinary UI copy: " + line);
        }
        List<String> sql = List.of(
                "\"SELECT id, target FROM scans WHERE id = ?\"",
                "\"SELECT id, target\"\n + \" FROM scans\"",     // split literal
                "\"insert into ports (scan_id) values (?)\"",
                "\"PRAGMA foreign_keys = ON\"",
                "\"UPDATE scans SET target = ?\"");
        for (String line : sql) {
            assertTrue(SQL_STATEMENT.matcher(line).find(),
                    "the SQL rule misses real SQL: " + line);
        }
    }

    @Test
    @DisplayName("no JDBC types outside repository/")
    void noJdbcOutsideRepository() {
        forbid("java.sql belongs in repository/.",
                Pattern.compile("^\\s*import\\s+java\\.sql\\."),
                "model", "service", "ui", "util");
    }

    @Test
    @DisplayName("model/ depends on nothing in this project except model/")
    void modelIsTheBottomLayer() {
        forbid("model/ is the bottom layer. It is imported by every other package, "
             + "so anything it imports becomes universal -- including into the CLI, "
             + "the tests and any future consumer.",
                Pattern.compile("^\\s*import\\s+com\\.cyberscope\\.(?!model\\.)"),
                "model");
    }

    @Test
    @DisplayName("feed-parsing libraries stay inside repository/")
    void feedLibrariesStayInRepository() {
        forbid("jackson and tukaani are how the NVD, KEV and EPSS feeds are read. "
             + "They are file-format concerns and must not reach the domain -- if "
             + "they do, swapping a feed format becomes a change to service/.",
                Pattern.compile("^\\s*import\\s+(com\\.fasterxml|org\\.tukaani)\\."),
                "model", "service", "ui", "util");
    }

    @Test
    @DisplayName("service/ depends on the CveLookup interface, never on CveRepository")
    void serviceDependsOnTheInterface() {
        forbid("service/ takes CveLookup, not CveRepository. That is what lets the "
             + "vulnerability tests run against an in-memory stub instead of a "
             + "350 MB SQLite file, and it is the seam a second index source would "
             + "plug into.",
                Pattern.compile("\\bCveRepository\\b"),
                "service");
    }

    @Test
    @DisplayName("the navigation model has no JavaFX, so the shell's rules can be tested")
    void navigationIsTestableWithoutADisplay() {
        List<String> offenders = new ArrayList<>();
        for (Source source : sourcesIn("ui")) {
            String name = source.path().getFileName().toString();
            if (!name.equals("Navigation.java") && !name.equals("PageId.java")) {
                continue;
            }
            if (source.text().contains("import javafx.")) {
                offenders.add(name);
            }
        }
        assertTrue(offenders.isEmpty(),
                "Navigation and PageId hold every rule about which page can be "
              + "opened. They are the one part of ui/ that is unit-tested, and that "
              + "is only possible because they import no JavaFX -- the toolkit "
              + "cannot start headless here and Monocle is not in the Maven "
              + "artifact. JavaFX crept into: " + offenders);
    }
}
