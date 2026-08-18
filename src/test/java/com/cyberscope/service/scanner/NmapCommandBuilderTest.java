package com.cyberscope.service.scanner;

import com.cyberscope.model.ScanType;
import com.cyberscope.util.InvalidTargetException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class NmapCommandBuilderTest {

    private static final Path OUT = Path.of("/tmp/scan.xml");

    @Test
    @DisplayName("QUICK produces the exact expected argument list")
    void quickCommand() throws Exception {
        assertEquals(
                List.of("nmap", "-sV", "-T4", "-F", "-oX", "/tmp/scan.xml", "127.0.0.1"),
                NmapCommandBuilder.build(ScanType.QUICK, "127.0.0.1", OUT));
    }

    @Test
    @DisplayName("STANDARD produces the exact expected argument list")
    void standardCommand() throws Exception {
        assertEquals(
                List.of("nmap", "-sV", "-T4", "--top-ports", "1000",
                        "-oX", "/tmp/scan.xml", "scanme.nmap.org"),
                NmapCommandBuilder.build(ScanType.STANDARD, "scanme.nmap.org", OUT));
    }

    @ParameterizedTest
    @EnumSource(ScanType.class)
    @DisplayName("every scan type puts nmap first and the target last")
    void targetIsAlwaysLast(ScanType type) throws Exception {
        List<String> cmd = NmapCommandBuilder.build(type, "127.0.0.1", OUT);
        assertEquals("nmap", cmd.get(0));
        assertEquals("127.0.0.1", cmd.get(cmd.size() - 1));
    }

    @ParameterizedTest
    @EnumSource(ScanType.class)
    @DisplayName("every scan type requests XML output to the given path")
    void alwaysRequestsXml(ScanType type) throws Exception {
        List<String> cmd = NmapCommandBuilder.build(type, "127.0.0.1", OUT);
        int i = cmd.indexOf("-oX");
        assertTrue(i > 0, "-oX must be present");
        assertEquals("/tmp/scan.xml", cmd.get(i + 1), "-oX must be followed by the path");
    }

    @ParameterizedTest
    @EnumSource(ScanType.class)
    @DisplayName("no argument contains a space: each flag is a separate element")
    void argumentsAreNotBundled(ScanType type) throws Exception {
        for (String arg : NmapCommandBuilder.build(type, "127.0.0.1", OUT)) {
            assertFalse(arg.contains(" "), "bundled argument found: '" + arg + "'");
        }
    }

    @Test
    @DisplayName("the target is normalised before it reaches the command")
    void normalisesTarget() throws Exception {
        List<String> cmd = NmapCommandBuilder.build(ScanType.QUICK, "  SCANME.NMAP.ORG  ", OUT);
        assertEquals("scanme.nmap.org", cmd.get(cmd.size() - 1));
    }

    @Test
    @DisplayName("a path containing spaces stays a single argument")
    void pathWithSpacesStaysOneArgument() throws Exception {
        List<String> cmd = NmapCommandBuilder.build(
                ScanType.QUICK, "127.0.0.1", Path.of("/tmp/my scans/out.xml"));
        assertEquals("/tmp/my scans/out.xml", cmd.get(cmd.indexOf("-oX") + 1));
    }

    @ParameterizedTest
    @ValueSource(strings = {"-iL /etc/passwd", "--script=evil", "256.1.1.1",
                            "2130706433", "1.1.1.1; rm -rf /"})
    @DisplayName("rejects any target the validator rejects")
    void rejectsInvalidTargets(String target) {
        assertThrows(InvalidTargetException.class,
                () -> NmapCommandBuilder.build(ScanType.QUICK, target, OUT));
    }

    @Test
    @DisplayName("rejects a null scan type")
    void rejectsNullScanType() {
        assertThrows(NullPointerException.class,
                () -> NmapCommandBuilder.build(null, "127.0.0.1", OUT));
    }

    @Test
    @DisplayName("rejects a null output path")
    void rejectsNullPath() {
        assertThrows(NullPointerException.class,
                () -> NmapCommandBuilder.build(ScanType.QUICK, "127.0.0.1", null));
    }

    @Test
    @DisplayName("the returned command is immutable")
    void commandIsImmutable() throws Exception {
        List<String> cmd = NmapCommandBuilder.build(ScanType.QUICK, "127.0.0.1", OUT);
        assertThrows(UnsupportedOperationException.class, () -> cmd.add("--script=evil"));
        assertThrows(UnsupportedOperationException.class, () -> cmd.set(0, "rm"));
    }

    @Test
    @DisplayName("describe() renders the command for display")
    void describeRendersCommand() throws Exception {
        assertEquals("nmap -sV -T4 -F -oX /tmp/scan.xml 127.0.0.1",
                NmapCommandBuilder.describe(
                        NmapCommandBuilder.build(ScanType.QUICK, "127.0.0.1", OUT)));
    }

    @ParameterizedTest
    @EnumSource(ScanType.class)
    @DisplayName("every scan type has a display name, description and immutable flags")
    void scanTypeMetadataIsPopulated(ScanType type) {
        assertNotNull(type.displayName());
        assertFalse(type.displayName().isBlank());
        assertFalse(type.description().isBlank());
        assertFalse(type.flags().isEmpty());
        assertThrows(UnsupportedOperationException.class, () -> type.flags().add("-sS"));
    }
}
