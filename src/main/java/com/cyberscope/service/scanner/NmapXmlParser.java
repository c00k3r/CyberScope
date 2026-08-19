package com.cyberscope.service.scanner;

import com.cyberscope.model.DetectionMethod;
import com.cyberscope.model.Host;
import com.cyberscope.model.HostState;
import com.cyberscope.model.Port;
import com.cyberscope.model.PortState;
import com.cyberscope.model.Protocol;
import com.cyberscope.model.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses Nmap XML into domain objects.
 *
 * <p>Pure: takes a string, performs no I/O, returns immutable records. The parser
 * is hardened against XXE and entity-expansion attacks because scan XML contains
 * data controlled by the scanned host, and because CyberScope will eventually
 * import scan files it did not produce.
 */
public final class NmapXmlParser {

    private NmapXmlParser() {
    }

    /**
     * Parses an Nmap XML report.
     *
     * @param xml the complete XML document
     * @return one {@link Host} per {@code <host>} element; empty if nothing was found
     * @throws XmlParseException if the document is empty, malformed, or structurally unusable
     */
    public static List<Host> parse(String xml) throws XmlParseException {
        if (xml == null || xml.isBlank()) {
            throw new XmlParseException("Nmap produced no XML to parse.");
        }
        try {
            Document document = newSecureBuilder()
                    .parse(new InputSource(new StringReader(xml)));

            NodeList hostNodes = document.getElementsByTagName("host");
            List<Host> hosts = new ArrayList<>(hostNodes.getLength());
            for (int i = 0; i < hostNodes.getLength(); i++) {
                hosts.add(parseHost((Element) hostNodes.item(i)));
            }
            return List.copyOf(hosts);

        } catch (SAXException | IOException | ParserConfigurationException e) {
            throw new XmlParseException("Could not parse Nmap XML: " + e.getMessage(), e);
        }
    }

    /**
     * Builds a parser that will not reach outside the document.
     *
     * <p>Note we deliberately do NOT set {@code disallow-doctype-decl}: Nmap emits
     * {@code <!DOCTYPE nmaprun>}, and that feature would reject Nmap's own output.
     * External entity resolution is disabled instead, which blocks XXE while
     * leaving the harmless declaration alone.
     */
    private static DocumentBuilder newSecureBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

        // Caps entity expansion: defeats "billion laughs" style bombs.
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        // XXE: refuse to fetch anything the document points at.
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setNamespaceAware(false);

        DocumentBuilder builder = factory.newDocumentBuilder();

        // Belt and braces: even if a feature above were unsupported by another JAXP
        // implementation, this resolver returns nothing for every external reference.
        builder.setEntityResolver((publicId, systemId) ->
                new InputSource(new StringReader("")));

        return builder;
    }

    private static Host parseHost(Element hostElement) throws XmlParseException {
        String ipAddress = extractAddress(hostElement);
        String hostname = firstAttribute(hostElement, "hostname", "name");
        HostState state = HostState.from(firstAttribute(hostElement, "status", "state"));

        NodeList portNodes = hostElement.getElementsByTagName("port");
        List<Port> ports = new ArrayList<>(portNodes.getLength());
        for (int i = 0; i < portNodes.getLength(); i++) {
            ports.add(parsePort((Element) portNodes.item(i)));
        }
        return new Host(ipAddress, hostname, state, ports);
    }

    /**
     * A host may carry several addresses (ipv4, ipv6, mac) and document order is not
     * a contract, so we select by addrtype rather than taking the first.
     */
    private static String extractAddress(Element hostElement) throws XmlParseException {
        NodeList addresses = hostElement.getElementsByTagName("address");
        String ipv6 = null;
        for (int i = 0; i < addresses.getLength(); i++) {
            Element address = (Element) addresses.item(i);
            String type = address.getAttribute("addrtype");
            if ("ipv4".equals(type)) {
                return address.getAttribute("addr");
            }
            if ("ipv6".equals(type) && ipv6 == null) {
                ipv6 = address.getAttribute("addr");
            }
        }
        if (ipv6 != null) {
            return ipv6;
        }
        throw new XmlParseException("A <host> element carried no IPv4 or IPv6 address.");
    }

    private static Port parsePort(Element portElement) throws XmlParseException {
        int number = parsePortNumber(portElement.getAttribute("portid"));
        Protocol protocol = Protocol.from(portElement.getAttribute("protocol"));
        PortState state = PortState.from(firstAttribute(portElement, "state", "state"));
        String reason = firstAttribute(portElement, "state", "reason");

        Element serviceElement = firstElement(portElement, "service");
        Service service = serviceElement == null ? Service.UNKNOWN : parseService(serviceElement);

        return new Port(number, protocol, state, reason, service);
    }

    /** A port number we cannot read means the document is not what we think it is. */
    private static int parsePortNumber(String portid) throws XmlParseException {
        try {
            return Integer.parseInt(portid.trim());
        } catch (NumberFormatException e) {
            throw new XmlParseException("Unparseable portid attribute: '" + portid + "'", e);
        }
    }

    private static Service parseService(Element serviceElement) {
        NodeList cpeNodes = serviceElement.getElementsByTagName("cpe");
        List<String> cpes = new ArrayList<>(cpeNodes.getLength());
        for (int i = 0; i < cpeNodes.getLength(); i++) {
            String cpe = cpeNodes.item(i).getTextContent();
            if (cpe != null && !cpe.isBlank()) {
                cpes.add(cpe.trim());
            }
        }
        return new Service(
                serviceElement.getAttribute("name"),
                serviceElement.getAttribute("product"),
                serviceElement.getAttribute("version"),
                serviceElement.getAttribute("extrainfo"),
                cpes,
                DetectionMethod.from(serviceElement.getAttribute("method")),
                parseConfidence(serviceElement.getAttribute("conf")));
    }

    /** Confidence is cosmetic; a malformed value must not fail an otherwise good scan. */
    private static int parseConfidence(String conf) {
        try {
            return Integer.parseInt(conf.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /** First descendant element with this tag name, or null. */
    private static Element firstElement(Element parent, String tagName) {
        Node node = parent.getElementsByTagName(tagName).item(0);
        return node instanceof Element element ? element : null;
    }

    /** Attribute of the first descendant element with this tag name, or "". */
    private static String firstAttribute(Element parent, String tagName, String attribute) {
        Element element = firstElement(parent, tagName);
        return element == null ? "" : element.getAttribute(attribute);
    }
}
