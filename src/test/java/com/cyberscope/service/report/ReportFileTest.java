package com.cyberscope.service.report;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A target string is user input being used to construct a path.
 */
class ReportFileTest {

    private static final Instant WHEN = Instant.parse("2026-09-07T14:36:00Z");

    private static String name(String target) {
        return ReportFile.nameFor(target, WHEN, ZoneOffset.UTC);
    }

    @Test
    @DisplayName("an ordinary address keeps its shape")
    void plainTargetIsReadable() {
        assertEquals("cyberscope-192.168.1.14-20260907-1436.html", name("192.168.1.14"));
    }

    @Test
    @DisplayName("a CIDR slash does not become a directory")
    void cidrDoesNotCreateAPath() {
        // The failure the naive version has on the first subnet anyone scans.
        String filename = name("192.168.1.0/24");
        assertAll(
                () -> assertEquals("cyberscope-192.168.1.0_24-20260907-1436.html", filename),
                () -> assertFalse(filename.contains("/"), filename),
                () -> assertEquals(filename, Path.of(filename).getFileName().toString(),
                        "the name must be a single path element"));
    }

    @Test
    @DisplayName("traversal sequences cannot survive into a filename")
    void traversalIsNeutralised() {
        // The target of a STORED scan comes out of a database that has been
        // through several schema versions. Treating it as trusted because
        // TargetValidator checked it once, in an earlier version, is the
        // assumption that turns into a path traversal.
        for (String hostile : new String[] {
                "../../etc/passwd", "..\\..\\windows\\system32", "/etc/shadow",
                "....//....//x", "~/.ssh/id_rsa" }) {
            String filename = name(hostile);
            assertAll(hostile,
                    () -> assertFalse(filename.contains("/"), filename),
                    () -> assertFalse(filename.contains("\\"), filename),
                    () -> assertFalse(filename.contains(".."), filename),
                    () -> assertEquals(filename, Path.of(filename).getFileName().toString(),
                            filename));
        }
    }

    @Test
    @DisplayName("an IPv6 address does not produce colons")
    void ipv6IsSafe() {
        // Legal in a filename on Linux, illegal on Windows, and a drive-letter
        // separator besides.
        String filename = name("fe80::1ff:fe23:4567:890a");
        assertAll(
                () -> assertFalse(filename.contains(":"), filename),
                () -> assertTrue(filename.startsWith("cyberscope-fe80_1ff"), filename));
    }

    @Test
    @DisplayName("a run of unsafe characters collapses rather than repeating")
    void underscoresAreCollapsed() {
        assertAll(
                () -> assertEquals("etc_passwd", ReportFile.slug("../../etc/passwd")),
                () -> assertEquals("a_b", ReportFile.slug("a///////b")));
    }

    @Test
    @DisplayName("a leading dot cannot make a hidden file")
    void noHiddenFiles() {
        assertAll(
                () -> assertFalse(ReportFile.slug(".hidden").startsWith(".")),
                () -> assertFalse(name(".bashrc").contains("-.")));
    }

    @Test
    @DisplayName("a target that sanitises away still produces a usable name")
    void emptySlugFallsBack() {
        for (String nothing : new String[] {"///", "...", "", "   ", "___"}) {
            assertAll(nothing,
                    () -> assertEquals("unnamed", ReportFile.slug(nothing)),
                    () -> assertFalse(name(nothing).contains("--"),
                            "an empty slug must not leave a double hyphen: " + name(nothing)));
        }
        assertEquals("unnamed", ReportFile.slug(null));
    }

    @Test
    @DisplayName("a very long target is truncated to a bounded length")
    void longTargetsAreBounded() {
        String slug = ReportFile.slug("a".repeat(200) + ".example.com");
        assertEquals(ReportFile.MAX_TARGET_CHARS, slug.length());
    }

    @Test
    @DisplayName("truncation that lands on a separator does not leave it dangling")
    void truncationDoesNotLeaveASeparator() {
        // The fixture matters. An earlier version used 200 identical letters, so
        // the cut never landed on a separator and a mutation removing the cleanup
        // survived. Here character 40 IS the dot, which is the only case the
        // cleanup exists for.
        String slug = ReportFile.slug("a".repeat(ReportFile.MAX_TARGET_CHARS - 1)
                + ".example.com");
        assertAll(
                () -> assertFalse(slug.endsWith(".") || slug.endsWith("_")
                                || slug.endsWith("-"),
                        "a name ending in a separator reads as a truncated mistake: " + slug),
                () -> assertEquals(ReportFile.MAX_TARGET_CHARS - 1, slug.length()));
    }

    @Test
    @DisplayName("names sort chronologically as text")
    void namesSortByTime() {
        // yyyyMMdd-HHmm, so `ls` in a reports directory is in scan order.
        String earlier = name("10.0.0.1");
        String later = ReportFile.nameFor("10.0.0.1",
                WHEN.plusSeconds(3600), ZoneOffset.UTC);
        assertTrue(earlier.compareTo(later) < 0, earlier + " vs " + later);
    }

    @Test
    @DisplayName("the network report has its own name and needs no target")
    void networkNameIsDistinct() {
        assertEquals("cyberscope-network-20260907-1436.html",
                ReportFile.networkName(WHEN, ZoneOffset.UTC));
    }

    @Test
    @DisplayName("the allowlist keeps the characters real targets are made of")
    void legitimateCharactersSurvive() {
        assertEquals("web-01.example.com", ReportFile.slug("web-01.example.com"));
    }
}
