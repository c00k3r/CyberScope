package com.cyberscope.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ModelTest {

    @Nested @DisplayName("enum parsing from XML attribute values")
    class EnumParsing {

        @ParameterizedTest
        @CsvSource({"tcp,TCP", "TCP,TCP", " udp ,UDP", "sctp,SCTP", "wat,UNKNOWN"})
        void protocolFrom(String xml, Protocol expected) {
            assertEquals(expected, Protocol.from(xml));
        }

        @ParameterizedTest @NullSource
        void protocolFromNull(String xml) {
            assertEquals(Protocol.UNKNOWN, Protocol.from(xml));
        }

        @ParameterizedTest
        @CsvSource({
                "open,OPEN", "closed,CLOSED", "filtered,FILTERED", "unfiltered,UNFILTERED",
                "open|filtered,OPEN_FILTERED", "closed|filtered,CLOSED_FILTERED",
                "weird,UNKNOWN"})
        void portStateFrom(String xml, PortState expected) {
            assertEquals(expected, PortState.from(xml));
        }

        @Test
        @DisplayName("compound states round-trip back to Nmap's spelling")
        void compoundStatesRoundTrip() {
            assertEquals("open|filtered", PortState.OPEN_FILTERED.toString());
            assertEquals("closed|filtered", PortState.CLOSED_FILTERED.toString());
            assertEquals("open", PortState.OPEN.toString());
        }

        @ParameterizedTest
        @CsvSource({"up,UP", "down,DOWN", "sideways,UNKNOWN"})
        void hostStateFrom(String xml, HostState expected) {
            assertEquals(expected, HostState.from(xml));
        }

        @ParameterizedTest
        @CsvSource({"probed,PROBED", "table,TABLE", "other,NONE"})
        void detectionMethodFrom(String xml, DetectionMethod expected) {
            assertEquals(expected, DetectionMethod.from(xml));
        }

        @ParameterizedTest @NullSource
        void detectionMethodFromNull(String xml) {
            assertEquals(DetectionMethod.NONE, DetectionMethod.from(xml));
        }
    }

    @Nested @DisplayName("Service")
    class ServiceTests {

        private final Service probed = new Service("http", "SimpleHTTPServer", "0.6",
                "Python 3.11.15", List.of("cpe:/a:python:simplehttpserver:0.6"),
                DetectionMethod.PROBED, 10);

        private final Service guessed = new Service("http-proxy", "", "", "",
                List.of(), DetectionMethod.TABLE, 3);

        @Test
        @DisplayName("a probed service is identified and fingerprinted")
        void probedIsFingerprinted() {
            assertTrue(probed.isIdentified());
            assertTrue(probed.isFingerprinted());
            assertTrue(probed.hasVersion());
            assertTrue(probed.hasCpe());
        }

        @Test
        @DisplayName("a table lookup is identified but NOT fingerprinted")
        void tableIsNotFingerprinted() {
            assertTrue(guessed.isIdentified());
            assertFalse(guessed.isFingerprinted(),
                    "a port-number guess must never count as evidence");
            assertFalse(guessed.hasVersion());
            assertFalse(guessed.hasCpe());
        }

        @Test
        @DisplayName("UNKNOWN is neither identified nor fingerprinted")
        void unknownService() {
            assertFalse(Service.UNKNOWN.isIdentified());
            assertFalse(Service.UNKNOWN.isFingerprinted());
            assertEquals("unknown", Service.UNKNOWN.describe());
        }

        @Test
        @DisplayName("describe() prefers product, version and extra info")
        void describeUsesProduct() {
            assertEquals("SimpleHTTPServer 0.6 (Python 3.11.15)", probed.describe());
        }

        @Test
        @DisplayName("describe() falls back to the service name")
        void describeFallsBackToName() {
            assertEquals("http-proxy", guessed.describe());
        }

        @Test
        @DisplayName("nulls are normalised to blanks and an empty cpe list")
        void normalisesNulls() {
            Service s = new Service(null, null, null, null, null, null, 5);
            assertEquals("", s.name());
            assertEquals("", s.product());
            assertTrue(s.cpes().isEmpty());
            assertEquals(DetectionMethod.NONE, s.method());
        }

        @ParameterizedTest
        @CsvSource({"-5,0", "0,0", "7,7", "10,10", "99,10"})
        @DisplayName("confidence is clamped to Nmap's 0-10 range")
        void clampsConfidence(int given, int expected) {
            assertEquals(expected, new Service("x", "", "", "", List.of(),
                    DetectionMethod.TABLE, given).confidence());
        }

        @Test
        @DisplayName("the cpe list is defensively copied")
        void cpesAreImmutable() {
            List<String> mutable = new ArrayList<>(List.of("cpe:/a:x:y"));
            Service s = new Service("x", "", "", "", mutable, DetectionMethod.PROBED, 10);
            mutable.add("cpe:/a:injected:z");
            assertEquals(1, s.cpes().size(), "the record must not see later mutations");
            assertThrows(UnsupportedOperationException.class, () -> s.cpes().add("nope"));
        }
    }

    @Nested @DisplayName("Port")
    class PortTests {

        @ParameterizedTest @ValueSource(ints = {0, 1, 80, 8080, 65535})
        void acceptsValidPortNumbers(int number) {
            assertDoesNotThrow(() ->
                    new Port(number, Protocol.TCP, PortState.OPEN, "syn-ack", null));
        }

        @ParameterizedTest @ValueSource(ints = {-1, 65536, 999999})
        void rejectsOutOfRangePortNumbers(int number) {
            assertThrows(IllegalArgumentException.class,
                    () -> new Port(number, Protocol.TCP, PortState.OPEN, "", null));
        }

        @Test
        @DisplayName("a null service becomes Service.UNKNOWN, never null")
        void nullServiceBecomesUnknown() {
            Port p = new Port(80, Protocol.TCP, PortState.OPEN, "syn-ack", null);
            assertSame(Service.UNKNOWN, p.service());
            assertNotNull(p.service());
        }

        @Test
        @DisplayName("isOpen() is true only for OPEN, not for open|filtered")
        void isOpenIsStrict() {
            assertTrue(new Port(80, Protocol.TCP, PortState.OPEN, "", null).isOpen());
            assertFalse(new Port(80, Protocol.TCP, PortState.OPEN_FILTERED, "", null).isOpen());
            assertFalse(new Port(80, Protocol.TCP, PortState.FILTERED, "", null).isOpen());
        }
    }

    @Nested @DisplayName("Host")
    class HostTests {

        private Port open(int n) {
            return new Port(n, Protocol.TCP, PortState.OPEN, "syn-ack", null);
        }

        private Port closed(int n) {
            return new Port(n, Protocol.TCP, PortState.CLOSED, "reset", null);
        }

        @Test
        @DisplayName("openPorts() filters to open ports only")
        void filtersOpenPorts() {
            Host h = new Host("127.0.0.1", "localhost", HostState.UP,
                    List.of(open(22), closed(23), open(8080)));
            assertEquals(List.of(22, 8080), h.openPorts().stream().map(Port::number).toList());
        }

        @Test
        @DisplayName("an empty hostnames element leaves the hostname blank")
        void handlesMissingHostname() {
            Host h = new Host("10.0.0.1", null, HostState.UP, List.of());
            assertFalse(h.hasHostname());
            assertEquals("10.0.0.1", h.displayName());
        }

        @Test
        @DisplayName("displayName() combines hostname and address when both are known")
        void displayNameCombines() {
            Host h = new Host("127.0.0.1", "localhost", HostState.UP, List.of());
            assertEquals("localhost (127.0.0.1)", h.displayName());
        }

        @Test
        @DisplayName("a null ip address is a programming error")
        void requiresIpAddress() {
            assertThrows(NullPointerException.class,
                    () -> new Host(null, "x", HostState.UP, List.of()));
        }

        @Test
        @DisplayName("the port list is defensively copied")
        void portsAreImmutable() {
            List<Port> mutable = new ArrayList<>(List.of(open(22)));
            Host h = new Host("127.0.0.1", "", HostState.UP, mutable);
            mutable.add(open(23));
            assertEquals(1, h.ports().size());
            assertThrows(UnsupportedOperationException.class, () -> h.ports().add(open(80)));
        }

        @Test
        @DisplayName("records give value equality for free")
        void valueEquality() {
            Host a = new Host("127.0.0.1", "localhost", HostState.UP, List.of(open(22)));
            Host b = new Host("127.0.0.1", "localhost", HostState.UP, List.of(open(22)));
            assertEquals(a, b);
            assertEquals(a.hashCode(), b.hashCode());
        }
    }
}
