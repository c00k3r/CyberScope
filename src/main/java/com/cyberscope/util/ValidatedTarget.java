package com.cyberscope.util;

import java.util.Objects;

/**
 * A target that has passed validation.
 *
 * <p>A method that takes a {@code ValidatedTarget} cannot be handed a raw string
 * by mistake -- the compiler refuses. That is the difference between checking a
 * string and parsing it into a type that carries the result.
 *
 * <p>Note the guarantee is "not by accident", not "not at all": a record's
 * canonical constructor cannot be less accessible than the record, so this cannot
 * be locked to {@link TargetValidator} alone. Enforcing that would mean a final
 * class with a private constructor and a static factory, trading away everything
 * a record gives you for a guarantee against deliberate misuse by your own code.
 *
 * @param value        the canonical form to pass to Nmap
 * @param kind         what it is
 * @param addressCount how many addresses it covers; 1 for a single host
 */
public record ValidatedTarget(String value, TargetKind kind, int addressCount) {

    public ValidatedTarget {
        Objects.requireNonNull(value, "value must not be null");
        Objects.requireNonNull(kind, "kind must not be null");
        if (addressCount < 1) {
            throw new IllegalArgumentException("addressCount must be at least 1");
        }
    }

    public boolean isRange() {
        return kind == TargetKind.CIDR;
    }

    /** e.g. "192.168.1.0/24 (256 addresses)" or "127.0.0.1". */
    public String describe() {
        if (!isRange()) {
            return value;
        }
        return value + " (" + addressCount + (addressCount == 1 ? " address)" : " addresses)");
    }

    @Override
    public String toString() {
        return value;
    }
}
