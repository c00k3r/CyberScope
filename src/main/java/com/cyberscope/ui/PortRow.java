package com.cyberscope.ui;

import com.cyberscope.model.Port;
import com.cyberscope.model.VulnAssessment;

/**
 * One row of the results table.
 *
 * <p>A range scan returns several hosts, so a row has to carry which host its port
 * belongs to. For a single-host scan the Host column is hidden rather than
 * repeating the same value on every line.
 *
 * @param vulns the assessment for this port, or null when the CVE lookup has not
 *              run. Null and {@code INDEX_UNAVAILABLE} are different states: the
 *              first means "not asked yet", the second means "asked, no index".
 */
public record PortRow(String host, Port port, VulnAssessment vulns) {

    /** Kept so every existing call site still compiles; the lookup is optional. */
    public PortRow(String host, Port port) {
        this(host, port, null);
    }
}