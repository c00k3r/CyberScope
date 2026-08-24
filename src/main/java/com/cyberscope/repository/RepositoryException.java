package com.cyberscope.repository;

/** Thrown when scan history could not be read or written. */
public class RepositoryException extends Exception {

    public RepositoryException(String message, Throwable cause) {
        super(message, cause);
    }

    public RepositoryException(String message) {
        super(message);
    }
}
