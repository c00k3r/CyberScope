package com.cyberscope.model;

import java.util.Optional;

/**
 * The {@code part} field of a CPE: what kind of thing is being identified.
 *
 * <p>CyberScope only ever acts on {@link #APPLICATION} and {@link #OPERATING_SYSTEM}.
 * {@link #HARDWARE} is parsed rather than rejected because Nmap emits 1,240 hardware
 * CPE templates and discarding them at the parser would make a hardware match look
 * like a parse failure -- two different states we have gone to some trouble to keep
 * apart everywhere else.
 */
public enum CpePart {

    APPLICATION("a"),
    OPERATING_SYSTEM("o"),
    HARDWARE("h");

    private final String code;

    CpePart(String code) {
        this.code = code;
    }

    /** The single letter as it appears in a CPE string. */
    public String code() {
        return code;
    }

    /**
     * @return the part for {@code code}, or empty if it is not one of the three.
     *         Empty rather than an exception: a malformed CPE from a third-party
     *         tool is data we did not create, not a programming error.
     */
    public static Optional<CpePart> fromCode(String code) {
        if (code == null) {
            return Optional.empty();
        }
        for (CpePart part : values()) {
            if (part.code.equals(code)) {
                return Optional.of(part);
            }
        }
        return Optional.empty();
    }
}