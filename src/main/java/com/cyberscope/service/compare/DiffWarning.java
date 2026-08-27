package com.cyberscope.service.compare;
 
import java.util.Objects;
 
/**
 * A reason to read a comparison with less confidence.
 *
 * <p>Warnings are separate from changes on purpose. A change says something
 * about the target; a warning says something about the comparison itself, and
 * conflating them would let "I am not sure these are the same machine" appear
 * in a list of findings as though it were one.
 */
public record DiffWarning(Kind kind, String detail) {
 
    public enum Kind {
        /**
         * The two scans left this machine by different routes, so the same
         * address may not be the same host. The strongest warning here: it
         * invalidates every difference below it rather than qualifying one.
         */
        PATH_DIFFERS,
 
        /** The scans used different profiles, so they examined different ports. */
        SCAN_TYPE_DIFFERS,
 
        /** At least one scan counted ports it could not name. */
        COVERAGE_INCOMPLETE,
 
        /** The scans were of different target strings. Almost certainly a mistake. */
        TARGET_DIFFERS,
 
        /** Some ports were covered by only one of the two scans. */
        PARTIAL_OVERLAP
    }
 
    public DiffWarning {
        Objects.requireNonNull(kind, "kind must not be null");
        detail = detail == null ? "" : detail;
    }
 
    /**
     * True when this warning means the differences below it should not be read
     * as changes at all.
     *
     * <p>Only {@code PATH_DIFFERS} qualifies. The others narrow what a
     * comparison covers; this one undermines whether the two scans were even
     * looking at the same machine.
     */
    public boolean invalidatesComparison() {
        return kind == Kind.PATH_DIFFERS;
    }
}
 

