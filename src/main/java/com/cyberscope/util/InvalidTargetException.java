package com.cyberscope.util;

/** Thrown when a user-supplied scan target fails validation. */
public class InvalidTargetException extends Exception {

    public InvalidTargetException(String message) {
        super(message);
    }
}
