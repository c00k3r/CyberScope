package com.cyberscope.service.scanner;

import com.cyberscope.model.DetectionMethod;
import com.cyberscope.model.Host;
import com.cyberscope.model.HostState;
import com.cyberscope.model.Port;
import com.cyberscope.model.PortState;
import com.cyberscope.model.Protocol;
import com.cyberscope.model.Service;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class NmapXmlParserTest {

    private static String fixture(String name) {
        String path = "/fixtures/" + name;
        try (InputStream in = NmapXmlParserTest.class.getResourceAsStream(path)) {
            assertNotNull(in, "missing fixture: " + path);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Nested @DisplayName("real Nmap output")
    class RealOutput {

        @Test
        @DisplayName("parses a probed service with product, version and CPE")
        void parsesProbedService() throws Exception {
            List<Host> hosts = NmapXmlParser.parse(fixture("nmap-single-host.xml"));

            assertEquals(1, hosts.size());
            Host host = hosts.get(0);
            assertEquals("127.0.0.1", host.ipAddress());
            assertEquals("localhost", host.hostname());
            assertEquals(HostState.UP, host.state());
            assertTrue(host.isUp());

            assertEquals(1, host.openPorts().size());
            Port port = host.openPorts().get(0);
            assertEquals(8080, port.number());
            assertEquals(Protocol.TCP, port.protocol());
            assertEquals(PortState.OPEN, port.state());
            assertEquals("syn-ack", port.reason());

            Service service = port.service();
            assertEquals("http", service.name());
            assertEquals("SimpleHTTPServer", service.product());
            assertEquals("0.6", service.version());
            assertEquals(DetectionMethod.PROBED, service.method());
            assertEquals(10, service.confidence());
            assertTrue(service.isFingerprinted());
            assertEquals(List.of("cpe:/a:python:simplehttpserver:0.6"), service.cpes());
        }

        @Test
        @DisplayName("a scan without -sV yields a TABLE guess with no version or CPE")
        void parsesTableLookup() throws Exception {
            Service service = NmapXmlParser.parse(fixture("nmap-no-version-detection.xml"))
                    .get(0).openPorts().get(0).service();

            assertEquals("http-proxy", service.name(), "Nmap guesses from the port number");
            assertEquals(DetectionMethod.TABLE, service.method());
            assertFalse(service.isFingerprinted(), "must not be usable for CVE mapping");
            assertFalse(service.hasVersion());
            assertFalse(service.hasCpe());
            assertEquals(3, service.confidence());
        }

        @Test
        @DisplayName("picks the IPv4 address, not the MAC, regardless of document order")
        void prefersIpv4OverMac() throws Exception {
            Host host = NmapXmlParser.parse(fixture("nmap-multiple-addresses.xml")).get(0);
            assertFalse(host.ipAddress().contains(":"),
                    "a MAC address must never be used as the IP: " + host.ipAddress());
        }

        @Test
        @DisplayName("an empty <hostnames> element leaves the hostname blank")
        void handlesEmptyHostnames() throws Exception {
            Host host = NmapXmlParser.parse(fixture("nmap-multiple-addresses.xml")).get(0);
            assertEquals("", host.hostname());
            assertFalse(host.hasHostname());
        }
    }

    @Nested @DisplayName("edge cases")
    class EdgeCases {

        @Test
        @DisplayName("a down host parses without error and reports no open ports")
        void parsesDownHost() throws Exception {
            List<Host> hosts = NmapXmlParser.parse(fixture("nmap-host-down.xml"));
            assertEquals(1, hosts.size());
            assertEquals(HostState.DOWN, hosts.get(0).state());
            assertFalse(hosts.get(0).isUp());
            assertTrue(hosts.get(0).openPorts().isEmpty());
        }

        @Test
        @DisplayName("a scan that found nothing yields an empty list, not an exception")
        void parsesNoHosts() throws Exception {
            assertEquals(List.of(), NmapXmlParser.parse(fixture("nmap-no-hosts.xml")));
        }

        @Test
        @DisplayName("truncated XML is rejected with a clear message")
        void rejectsMalformedXml() {
            XmlParseException e = assertThrows(XmlParseException.class,
                    () -> NmapXmlParser.parse(fixture("malformed-truncated.xml")));
            assertTrue(e.getMessage().startsWith("Could not parse Nmap XML"), e.getMessage());
            assertNotNull(e.getCause(), "the underlying SAX error must be preserved");
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"   ", "\n\t "})
        @DisplayName("null, empty and blank input are rejected")
        void rejectsEmptyInput(String xml) {
            assertThrows(XmlParseException.class, () -> NmapXmlParser.parse(xml));
        }

        @Test
        @DisplayName("the returned host list is immutable")
        void resultIsImmutable() throws Exception {
            List<Host> hosts = NmapXmlParser.parse(fixture("nmap-single-host.xml"));
            assertThrows(UnsupportedOperationException.class,
                    () -> hosts.add(new Host("1.1.1.1", "", HostState.UP, List.of())));
        }
    }

    @Nested @DisplayName("security")
    class Security {

        @Test
        @DisplayName("an XXE payload does not leak file contents into the result")
        void blocksXxe() throws Exception {
            List<Host> hosts = NmapXmlParser.parse(fixture("malicious-xxe.xml"));
            Service service = hosts.get(0).ports().get(0).service();
            assertTrue(service.cpes().isEmpty(),
                    "the external entity must not resolve; leaked: " + service.cpes());
        }

        @Test
        @DisplayName("an entity-expansion bomb is rejected rather than exhausting memory")
        void blocksBillionLaughs() {
            long start = System.currentTimeMillis();
            assertThrows(XmlParseException.class,
                    () -> NmapXmlParser.parse(fixture("malicious-billion-laughs.xml")));
            assertTrue(System.currentTimeMillis() - start < 10_000, "must fail fast, not grind");
        }
    }
}
