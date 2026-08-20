package com.cyberscope.service.report;

import com.cyberscope.model.DetectionMethod;
import com.cyberscope.model.Host;
import com.cyberscope.model.HostState;
import com.cyberscope.model.Port;
import com.cyberscope.model.PortState;
import com.cyberscope.model.Protocol;
import com.cyberscope.model.ScanType;
import com.cyberscope.model.Service;
import com.cyberscope.service.scanner.NmapRunResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ScanReportFormatterTest {

    private static final Instant STARTED = Instant.parse("2026-08-19T15:42:11Z");

    private static final Service PROBED = new Service("http", "SimpleHTTPServer", "0.6",
            "Python 3.11.15", List.of("cpe:/a:python:simplehttpserver:0.6"),
            DetectionMethod.PROBED, 10);

    private static final Service GUESSED = new Service("http-proxy", "", "", "",
            List.of(), DetectionMethod.TABLE, 3);

    private static NmapRunResult run(String warnings) {
        return new NmapRunResult("127.0.0.1", ScanType.QUICK,
                List.of("nmap", "-sV", "-T4", "-F", "-oX", "/tmp/x.xml", "127.0.0.1"),
                "<nmaprun/>", STARTED, Duration.ofMillis(6450), warnings);
    }

    private static Host hostWith(Service service) {
        return new Host("127.0.0.1", "localhost", HostState.UP,
                List.of(new Port(8080, Protocol.TCP, PortState.OPEN, "syn-ack", service)));
    }

    private static String format(List<Host> hosts, String warnings) {
        return ScanReportFormatter.format(run(warnings), hosts, ZoneOffset.UTC);
    }

    @Test
    @DisplayName("the header states target, scan type, time, duration and exact command")
    void headerIsComplete() {
        String out = format(List.of(hostWith(PROBED)), "");
        assertTrue(out.contains("Target      : 127.0.0.1"), out);
        assertTrue(out.contains("Scan type   : Quick"), out);
        assertTrue(out.contains("2026-08-19 15:42:11"), out);
        assertTrue(out.contains("Duration    : 6.5 s"), out);
        assertTrue(out.contains("nmap -sV -T4 -F -oX /tmp/x.xml 127.0.0.1"), out);
    }

    @Test
    @DisplayName("a probed service shows its version and confidence")
    void rendersProbedService() {
        String out = format(List.of(hostWith(PROBED)), "");
        assertTrue(out.contains("8080/tcp"), out);
        assertTrue(out.contains("SimpleHTTPServer 0.6 (Python 3.11.15)"), out);
        assertTrue(out.contains("probed (conf 10)"), out);
        assertFalse(out.contains("Note: services marked 'table'"),
                "no footnote when every service was probed");
    }

    @Test
    @DisplayName("a table guess shows no version and triggers the footnote")
    void rendersTableGuessWithWarningFootnote() {
        String out = format(List.of(hostWith(GUESSED)), "");
        assertTrue(out.contains("http-proxy"), out);
        assertTrue(out.contains("table  (conf 3)"), out);
        assertTrue(out.contains("Note: services marked 'table'"),
                "an unconfirmed service must be called out");
        assertFalse(out.contains("http-proxy  http-proxy"),
                "the version column must not repeat the service name");
    }

    @Test
    @DisplayName("an empty result explains itself instead of printing nothing")
    void rendersNoHosts() {
        String out = format(List.of(), "");
        assertTrue(out.contains("No hosts were found"), out);
        assertTrue(out.contains("0 hosts scanned, 0 up, 0 open ports total"), out);
    }

    @Test
    @DisplayName("a host with no open ports says so")
    void rendersHostWithNoOpenPorts() {
        Host down = new Host("10.0.0.99", "", HostState.DOWN, List.of());
        String out = format(List.of(down), "");
        assertTrue(out.contains("10.0.0.99  [DOWN]"), out);
        assertTrue(out.contains("No open ports found."), out);
        assertTrue(out.contains("1 host scanned, 0 up"), out);
    }

    @Test
    @DisplayName("Nmap warnings are surfaced, not swallowed")
    void rendersWarnings() {
        String out = format(List.of(), "Failed to resolve \"nope.invalid\".");
        assertTrue(out.contains("Nmap warnings:"), out);
        assertTrue(out.contains("! Failed to resolve \"nope.invalid\"."), out);
    }

    @Test
    @DisplayName("columns are sized to the widest cell, so nothing is truncated")
    void columnsAreAligned() {
        Service longName = new Service("http", "A".repeat(60), "1.0", "",
                List.of(), DetectionMethod.PROBED, 10);
        String out = format(List.of(hostWith(longName)), "");
        assertTrue(out.contains("A".repeat(60) + " 1.0"), "long product must not be truncated");

        List<String> tableLines = out.lines()
                .filter(l -> l.startsWith("   ") && !l.isBlank())
                .toList();
        assertEquals(3, tableLines.size(), "header, rule and one data row");
        assertTrue(tableLines.get(1).startsWith("   --------  -----"),
                "the rule row must match the column layout: " + tableLines.get(1));
    }

    @Test
    @DisplayName("the same inputs always produce the same output")
    void isDeterministic() {
        assertEquals(format(List.of(hostWith(PROBED)), ""),
                     format(List.of(hostWith(PROBED)), ""));
    }
}
