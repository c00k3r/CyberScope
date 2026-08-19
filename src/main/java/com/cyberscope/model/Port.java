package com.cyberscope.model;

/**
 * A single scanned port.
 *
 * @param reason Nmap's evidence for the state, e.g. "syn-ack" or "no-response".
 *               "open because we saw a SYN/ACK" is a stronger claim than
 *               "open|filtered because we saw nothing".
 */
public record Port(int number, Protocol protocol, PortState state,
                   String reason, Service service) {

    public static final int MIN_PORT = 0;
    public static final int MAX_PORT = 65535;

    public Port {
        if (number < MIN_PORT || number > MAX_PORT) {
            throw new IllegalArgumentException(
                    "Port number out of range " + MIN_PORT + "-" + MAX_PORT + ": " + number);
        }
        protocol = protocol == null ? Protocol.UNKNOWN  : protocol;
        state    = state    == null ? PortState.UNKNOWN : state;
        reason   = reason   == null ? ""                : reason.trim();
        service  = service  == null ? Service.UNKNOWN   : service;   // Null Object
    }

    /** Strictly OPEN. {@code open|filtered} is a weaker claim and does not count. */
    public boolean isOpen() {
        return state == PortState.OPEN;
    }
}
