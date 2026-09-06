package com.cyberscope.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("filtering the vulnerability list")
class FindingFilterTest {

    private static final Instant WHEN = Instant.parse("2026-09-01T10:00:00Z");

    // ------------------------------------------------------------- fixtures

    private static ExploitSignal kev() {
        return new ExploitSignal(0.9, 0.99, KevStatus.LISTED, null, null);
    }

    private static ExploitSignal quiet() {
        return new ExploitSignal(0.001, 0.05, KevStatus.NOT_LISTED, null, null);
    }

    private static NetworkPosture.Action action(String target, int port, String product,
                                                String cveId, Severity severity,
                                                ExploitSignal signal) {
        Port p = new Port(port, Protocol.TCP, PortState.OPEN, "syn-ack",
                new Service("http", product, "1.0", "", List.of(),
                            DetectionMethod.PROBED, 10));
        Vulnerability v = new Vulnerability(cveId, severity, 7.5, "AV:N", "3.1", WHEN,
                "description", MatchPrecision.VERSION_EXACT, "cpe", signal);
        return new NetworkPosture.Action(target, new RankedFinding(p, product, v));
    }

    private static final NetworkPosture.Action NGINX_KEV =
            action("192.168.1.14", 443, "f5:nginx 1.24.0", "CVE-2023-44487",
                   Severity.HIGH, kev());
    private static final NetworkPosture.Action SSH_QUIET =
            action("192.168.1.14", 22, "openbsd:openssh 9.6", "CVE-2024-0001",
                   Severity.CRITICAL, quiet());
    private static final NetworkPosture.Action MYSQL_QUIET =
            action("10.0.0.5", 3306, "oracle:mysql 8.0.36", "CVE-2021-9999",
                   Severity.LOW, quiet());

    private static final List<NetworkPosture.Action> ALL =
            List.of(NGINX_KEV, SSH_QUIET, MYSQL_QUIET);

    // ----------------------------------------------------------------- tests

    @Test
    @DisplayName("the default filter hides nothing and says so")
    void defaultShowsEverything() {
        FindingFilter filter = FindingFilter.none();
        assertAll(
                () -> assertEquals(3, filter.apply(ALL).size()),
                () -> assertFalse(filter.isActive()),
                () -> assertEquals("showing 3 of 3 findings", filter.describe(3, 3)));
    }

    @Nested
    @DisplayName("text search")
    class TextSearch {

        @Test
        @DisplayName("matches target, product, port and CVE id")
        void matchesAnyOfFourFields() {
            assertAll(
                    () -> assertEquals(List.of(MYSQL_QUIET),
                            FindingFilter.none().withText("10.0.0.5").apply(ALL), "target"),
                    () -> assertEquals(List.of(SSH_QUIET),
                            FindingFilter.none().withText("openssh").apply(ALL), "product"),
                    () -> assertEquals(List.of(SSH_QUIET),
                            FindingFilter.none().withText("22/tcp").apply(ALL), "port"),
                    () -> assertEquals(List.of(NGINX_KEV),
                            FindingFilter.none().withText("CVE-2023-44487").apply(ALL), "cve"));
        }

        @Test
        @DisplayName("matches a substring, not just a prefix")
        void substringNotPrefix() {
            // The fields people search are not ones they know the start of.
            assertAll(
                    () -> assertEquals(List.of(NGINX_KEV),
                            FindingFilter.none().withText("44487").apply(ALL),
                            "a bare CVE number should find its CVE"),
                    () -> assertEquals(List.of(NGINX_KEV),
                            FindingFilter.none().withText("nginx").apply(ALL),
                            "a product name inside 'f5:nginx 1.24.0' should match"));
        }

        @Test
        void caseInsensitive() {
            assertEquals(FindingFilter.none().withText("OPENSSH").apply(ALL),
                         FindingFilter.none().withText("openssh").apply(ALL));
        }

        @Test
        @DisplayName("whitespace-only text is not a filter")
        void blankTextIsNotAFilter() {
            FindingFilter filter = FindingFilter.none().withText("   ");
            assertAll(
                    () -> assertFalse(filter.isActive()),
                    () -> assertEquals(3, filter.apply(ALL).size()));
        }

        @Test
        void noMatchIsEmptyNotEverything() {
            assertTrue(FindingFilter.none().withText("zzzz").apply(ALL).isEmpty(),
                    "a filter that matches nothing must hide everything, not fall "
                  + "back to showing everything");
        }
    }

    @Nested
    @DisplayName("exploitation and urgency")
    class Exploitation {

        @Test
        void exploitedOnlyKeepsKevEntries() {
            assertEquals(List.of(NGINX_KEV),
                    FindingFilter.none().withExploitedOnly(true).apply(ALL));
        }

        @Test
        @DisplayName("a CVSS CRITICAL that nobody is exploiting is excluded")
        void severityDoesNotSurviveTheExploitedFilter() {
            // SSH_QUIET is CVSS CRITICAL. That is exactly the finding this filter
            // exists to get out of the way.
            assertFalse(FindingFilter.none().withExploitedOnly(true).matches(SSH_QUIET));
        }

        @Test
        void minimumUrgencyExcludesLowerBands() {
            FindingFilter high = FindingFilter.none().withMinUrgency(ExposureBand.HIGH);
            assertAll(
                    () -> assertTrue(high.matches(NGINX_KEV), "KEV ranks HIGH"),
                    () -> assertFalse(high.matches(MYSQL_QUIET)),
                    () -> assertTrue(high.isActive()));
        }

        @Test
        @DisplayName("CLEAR as the minimum excludes nothing")
        void clearIsTheNoMinimumOption() {
            FindingFilter filter = FindingFilter.none().withMinUrgency(ExposureBand.CLEAR);
            assertAll(
                    () -> assertEquals(3, filter.apply(ALL).size()),
                    () -> assertFalse(filter.isActive(),
                            "'Any urgency' must not read as an active filter"));
        }

        @Test
        void filtersCombineWithAnd() {
            FindingFilter filter = FindingFilter.none()
                    .withText("192.168.1.14")
                    .withExploitedOnly(true);
            assertEquals(List.of(NGINX_KEV), filter.apply(ALL));
        }
    }

    @Nested
    @DisplayName("the count line, which is what stops a filter becoming a false negative")
    class CountLine {

        @Test
        void namesBothNumbers() {
            String described = FindingFilter.none().describe(3, 211);
            assertAll(
                    () -> assertTrue(described.contains("3 of 211"), described),
                    () -> assertFalse(described.contains("filtered"),
                            "an unfiltered list must not claim to be filtered: " + described));
        }

        @Test
        @DisplayName("an active filter is named, not just implied")
        void activeFilterIsSpelledOut() {
            String described = FindingFilter.none()
                    .withText("nginx")
                    .withExploitedOnly(true)
                    .withMinUrgency(ExposureBand.HIGH)
                    .describe(1, 211);

            assertAll(
                    () -> assertTrue(described.contains("1 of 211"), described),
                    // The word that tells the reader rows are being hidden. Without
                    // this assertion, deleting it broke no test -- the individual
                    // filter names still appeared and the sentence read as a list of
                    // nothing in particular.
                    () -> assertTrue(described.contains("filtered"),
                            "the count line must say the list is filtered, not merely "
                          + "mention the terms: " + described),
                    () -> assertTrue(described.contains("nginx"), described),
                    () -> assertTrue(described.contains("exploited only"), described),
                    () -> assertTrue(described.toLowerCase().contains("high"), described));
        }

        @Test
        void singularReadsCorrectly() {
            assertTrue(FindingFilter.none().describe(1, 1).endsWith("1 of 1 finding"));
        }
    }

    @Test
    @DisplayName("null text and null band are normalised, not stored")
    void nullsAreNormalised() {
        FindingFilter filter = new FindingFilter(null, false, null);
        assertAll(
                () -> assertEquals("", filter.text()),
                () -> assertEquals(ExposureBand.CLEAR, filter.minUrgency()),
                () -> assertFalse(filter.isActive()),
                () -> assertEquals(3, filter.apply(ALL).size()));
    }

    @Test
    @DisplayName("filtering preserves the ranking order it was given")
    void orderIsPreserved() {
        List<NetworkPosture.Action> reversed = List.of(MYSQL_QUIET, SSH_QUIET, NGINX_KEV);
        assertEquals(reversed, FindingFilter.none().apply(reversed),
                "the list arrives ranked by exploitation; a filter must not reorder it");
    }
}
