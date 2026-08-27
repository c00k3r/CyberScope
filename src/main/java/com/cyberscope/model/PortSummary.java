package com.cyberscope.model;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The ports Nmap scanned but did not report individually.
 *
 * <p>Nmap does not emit a {@code <port>} element for every port it scanned. When
 * one state dominates, it collapses those ports into a single
 * {@code <extraports>} block. A default Quick scan of a quiet host produces
 * <em>one</em> {@code <port>} element and this:
 *
 * <pre>
 * &lt;extraports state="closed" count="99"&gt;
 *   &lt;extrareasons reason="reset" count="99" proto="tcp" ports="7,9,13,21-23,..."/&gt;
 * &lt;/extraports&gt;
 * </pre>
 *
 * <p>Ignoring that block -- which CyberScope did until v0.4.0 -- means the
 * program believes a 100-port scan examined one port. Two consequences follow,
 * and the second is the serious one:
 *
 * <ol>
 *   <li>The report cannot say how much was actually looked at.</li>
 *   <li>A comparison between two scans cannot tell <em>"this port opened"</em>
 *       from <em>"this port was not scanned last time"</em>. Reporting the
 *       second as the first is a fabricated finding, which is precisely the
 *       failure this project exists to avoid.</li>
 * </ol>
 *
 * <p>The collapsed ports are deliberately <em>not</em> materialised as {@link Port}
 * objects. Ninety-nine closed ports are not ninety-nine findings; they are one
 * fact with a count. Expanding them would put 25,000 rows of "closed" in the
 * database for a single /24 and bury the open ports in the UI.
 *
 * @param state  the state all these ports were in
 * @param count  how many ports Nmap collapsed, as Nmap reported it
 * @param reasons why, and how many for each reason -- e.g. {@code {reset=99}} or
 *                {@code {no-response=110, host-unreach=10}}
 * @param ports  which port numbers these were. <strong>May be empty:</strong> the
 *               {@code ports} attribute is {@code #IMPLIED} in Nmap's DTD, so its
 *               absence is a normal condition rather than an error. Callers must
 *               treat an empty set as "coverage unknown", never as "no ports".
 */
public record PortSummary(PortState state, int count,
                          Map<String, Integer> reasons, Set<Integer> ports) {

    public PortSummary {
        Objects.requireNonNull(state, "state must not be null");
        if (count < 0) {
            throw new IllegalArgumentException("count must not be negative: " + count);
        }
        reasons = reasons == null ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(reasons));
        ports = ports == null ? Set.of() : Set.copyOf(ports);
    }

    /** True when Nmap named at least some of these ports. */
    public boolean hasPortNumbers() {
        return !ports.isEmpty();
    }

    /**
     * True when every port this summary counts can also be named.
     *
     * <p>Not the same question as {@link #hasPortNumbers()}, and the difference
     * is not academic. One {@code <extraports>} block can carry several
     * {@code <extrareasons>} children, and the {@code ports} attribute is
     * optional on each of them independently. A real black-holed scan produced a
     * single block of 120 filtered ports where one reason named its 110 and the
     * other named none of its 10 -- so the summary has port numbers, and is
     * still missing ten ports of coverage.
     *
     * <p>The comparison layer must use this one. Asking only whether any ports
     * were named would let it conclude something about a port it cannot see.
     */
    public boolean isFullyEnumerated() {
        return ports.size() == count;
    }

    /** e.g. {@code "reset"} or {@code "no-response, host-unreach"}. */
    public String reasonNames() {
        return String.join(", ", reasons.keySet());
    }
}