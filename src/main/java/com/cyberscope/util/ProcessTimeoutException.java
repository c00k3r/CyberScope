package com.cyberscope.util;

import java.time.Duration;
import java.util.List;

/** Thrown when a command exceeded its timeout and was forcibly killed. */
public class ProcessTimeoutException extends Exception {

    public ProcessTimeoutException(List<String> command, Duration timeout) {
        super("Command timed out after " + format(timeout) + " and was killed: "
              + String.join(" ", command));
    }

    /** Sub-second timeouts must not render as "0s"; that reads as a bug during debugging. */
    private static String format(Duration timeout) {
        long millis = timeout.toMillis();
        return millis < 1000 ? millis + "ms" : timeout.toSeconds() + "s";
    }
}
