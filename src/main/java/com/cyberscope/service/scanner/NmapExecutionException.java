package com.cyberscope.service.scanner;

/** Thrown when Nmap could not complete a scan. Not used when a host is simply down. */
public class NmapExecutionException extends Exception {

    public NmapExecutionException(String message) {
        super(message);
    }

    public NmapExecutionException(String message, Throwable cause) {
        super(message, cause);
    }
}
