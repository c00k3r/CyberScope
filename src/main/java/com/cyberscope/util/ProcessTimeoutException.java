package com.cyberscope.util;

import java.time.Duration;
import java.util.List;

/** Thrown when a command exceeded its timeout and was forcibly killed. */
public class ProcessTimeoutException extends Exception {

    public ProcessTimeoutException(List<String> command, Duration timeout) {
        super("Command timed out after " + timeout.toSeconds() + "s and was killed: "
              + String.join(" ", command));
    }
}
