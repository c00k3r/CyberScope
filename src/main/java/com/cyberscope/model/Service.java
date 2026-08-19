package com.cyberscope.model;

import java.util.List;

/**
 * A service Nmap identified on a port.
 *
 * @param name       Nmap's service name, e.g. "http"
 * @param product    the software, e.g. "SimpleHTTPServer". Empty unless probed.
 * @param version    the version string, e.g. "0.6". Empty unless probed.
 * @param extraInfo  supplementary detail, e.g. "Python 3.11.15"
 * @param cpes       CPE identifiers Nmap emitted; the matching key for NVD at v0.5
 * @param method     how the identification was made — see {@link DetectionMethod}
 * @param confidence Nmap's own confidence, 0-10
 */
public record Service(String name, String product, String version, String extraInfo,
                      List<String> cpes, DetectionMethod method, int confidence) {

    /** Null Object: used when a port carries no service element at all. */
    public static final Service UNKNOWN =
            new Service("", "", "", "", List.of(), DetectionMethod.NONE, 0);

    public Service {
        name       = blankIfNull(name);
        product    = blankIfNull(product);
        version    = blankIfNull(version);
        extraInfo  = blankIfNull(extraInfo);
        cpes       = cpes == null ? List.of() : List.copyOf(cpes);
        method     = method == null ? DetectionMethod.NONE : method;
        confidence = Math.clamp(confidence, 0, 10);
    }

    private static String blankIfNull(String value) {
        return value == null ? "" : value.trim();
    }

    /** True if Nmap named the service at all, by any method. */
    public boolean isIdentified() {
        return method != DetectionMethod.NONE;
    }

    /**
     * True only if Nmap actually interacted with the service.
     * Vulnerability mapping must require this; a table lookup is a guess.
     */
    public boolean isFingerprinted() {
        return method == DetectionMethod.PROBED;
    }

    public boolean hasVersion() {
        return !version.isBlank();
    }

    public boolean hasCpe() {
        return !cpes.isEmpty();
    }

    /** Human-readable summary, e.g. "SimpleHTTPServer 0.6 (Python 3.11.15)". */
    public String describe() {
        if (!product.isBlank()) {
            StringBuilder sb = new StringBuilder(product);
            if (!version.isBlank())   sb.append(' ').append(version);
            if (!extraInfo.isBlank()) sb.append(" (").append(extraInfo).append(')');
            return sb.toString();
        }
        return name.isBlank() ? "unknown" : name;
    }
}
