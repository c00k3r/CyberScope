package com.cyberscope.ui;

import com.cyberscope.model.Port;

/**
 * One row of the results table.
 *
 * <p>A range scan returns several hosts, so a row has to carry which host its port
 * belongs to. For a single-host scan the Host column is hidden rather than
 * repeating the same value on every line.
 */
public record PortRow(String host, Port port) {
}
