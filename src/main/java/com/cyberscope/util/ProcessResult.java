package com.cyberscope.util;

/**
 * The outcome of running an external command.
 *
 * @param exitCode the process exit status; 0 conventionally means success
 * @param stdout   everything the process wrote to standard output
 * @param stderr   everything the process wrote to standard error
 */
public record ProcessResult(int exitCode, String stdout, String stderr) {

    /** True if the process reported success. */
    public boolean isSuccess() {
        return exitCode == 0;
    }
}
