package com.cyberscope.service.scanner;

/** Thrown when a usable Nmap installation could not be found or interrogated. */
public class NmapNotFoundException extends Exception {

    public NmapNotFoundException(String message) {
        super(message);
    }

    public NmapNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
