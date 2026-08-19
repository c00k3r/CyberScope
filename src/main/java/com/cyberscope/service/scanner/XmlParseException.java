package com.cyberscope.service.scanner;

/** Thrown when Nmap's XML output could not be parsed into domain objects. */
public class XmlParseException extends Exception {

    public XmlParseException(String message) {
        super(message);
    }

    public XmlParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
