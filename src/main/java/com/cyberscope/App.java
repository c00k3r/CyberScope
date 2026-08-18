package com.cyberscope;

/**
 * Entry point for CyberScope.
 *
 * <p>At v0.0.1 this exists purely to prove the build and run chain works.
 * From v0.0.8 it becomes the CLI entry point for the scan pipeline.
 */
public final class App {

    /** Current application version. */
    public static final String VERSION = "0.0.1";

    /** Not instantiable: this class is an entry point, not an object. */
    private App() {
    }

    public static void main(String[] args) {
        System.out.println("CyberScope v" + VERSION);
        System.out.println("Authorised targets only - see SCOPE.md");
    }
}
