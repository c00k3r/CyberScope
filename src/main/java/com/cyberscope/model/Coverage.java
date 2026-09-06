package com.cyberscope.model;

/**
 * How much of a host could actually be assessed.
 *
 * <p>The figure that qualifies every other figure on the screen. A host with no
 * findings and 40% coverage has not been given a clean bill of health; it has
 * been given one opinion about two fifths of itself.
 *
 * @param checked  services whose CVE lookup succeeded ({@code MAPPED})
 * @param examined open services considered in total
 */
public record Coverage(int checked, int examined) {

    /**
     * The point below which an absence of findings stops being informative.
     *
     * <p><b>This number is a judgement, not a measurement.</b> Unlike
     * {@code IndexMetadata.STALE_AFTER}, which comes from the observed rate of
     * ~584 new CVEs a day, nothing in the data says where the line belongs. 80%
     * is chosen because a fifth of a host being invisible is roughly the point
     * at which "nothing found" stops carrying information -- and it is written
     * down as an opinion so that the next person can argue with it rather than
     * mistake it for a result.
     */
    public static final double ADEQUATE = 0.80;

    public static final Coverage NONE = new Coverage(0, 0);

    public Coverage {
        if (checked < 0 || examined < 0) {
            throw new IllegalArgumentException("counts must not be negative");
        }
        if (checked > examined) {
            throw new IllegalArgumentException(
                    "checked (" + checked + ") cannot exceed examined (" + examined + ")");
        }
    }

    /** Services that could not be looked up, for whatever reason. */
    public int unchecked() {
        return examined - checked;
    }

    /**
     * Fraction assessed, from 0.0 to 1.0.
     *
     * <p>A host with no open services returns 1.0 rather than dividing by zero:
     * nothing was missed, because there was nothing to miss.
     */
    public double fraction() {
        return examined == 0 ? 1.0 : (double) checked / examined;
    }

    /** Rounded to a whole percent, for display. */
    public int percent() {
        return (int) Math.round(fraction() * 100);
    }

    public boolean isAdequate() {
        return fraction() >= ADEQUATE;
    }

    public boolean isComplete() {
        return checked == examined;
    }

    /** e.g. {@code 11 of 14 services checked}. */
    public String describe() {
        if (examined == 0) {
            return "no open services";
        }
        return checked + " of " + examined + " service" + (examined == 1 ? "" : "s")
               + " checked";
    }
}
