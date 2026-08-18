package com.cyberscope.service.scanner;

import com.cyberscope.util.ProcessResult;
import com.cyberscope.util.ProcessRunner;
import com.cyberscope.util.ProcessTimeoutException;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Verifies that a usable Nmap installation is available and reports its version. */
public final class NmapDetector {

    private static final String NMAP_EXECUTABLE = "nmap";
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    /** Matches the first line of `nmap --version`, e.g. "Nmap version 7.99 ( https://nmap.org )". */
    private static final Pattern VERSION_PATTERN =
            Pattern.compile("^Nmap version (\\S+)", Pattern.MULTILINE);

    private static final String NOT_ON_PATH =
            "Nmap was not found on the system PATH. CyberScope requires Nmap 7.x."
            + System.lineSeparator()
            + "  Debian/Ubuntu: sudo apt install nmap"
            + System.lineSeparator()
            + "  Verify with:   nmap --version";

    private NmapDetector() {
    }

    /**
     * Runs {@code nmap --version} and extracts the version string.
     *
     * @throws NmapNotFoundException if Nmap is absent, unresponsive, or unrecognised
     */
    public static String detectVersion() throws NmapNotFoundException {
        ProcessResult result;
        try {
            result = ProcessRunner.run(List.of(NMAP_EXECUTABLE, "--version"), TIMEOUT);
        } catch (IOException e) {
            throw new NmapNotFoundException(NOT_ON_PATH, e);
        } catch (ProcessTimeoutException e) {
            throw new NmapNotFoundException(
                    "Nmap was found but did not respond to '--version' within "
                    + TIMEOUT.toSeconds() + " seconds.", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new NmapNotFoundException("Interrupted while detecting Nmap.", e);
        }

        if (!result.isSuccess()) {
            throw new NmapNotFoundException(
                    "'nmap --version' exited with code " + result.exitCode()
                    + ". stderr: " + result.stderr());
        }

        return parseVersion(result.stdout()).orElseThrow(() -> new NmapNotFoundException(
                "Could not parse an Nmap version from the output: " + result.stdout()));
    }

    /**
     * Extracts the version from {@code nmap --version} output.
     * Package-private and side-effect free so it can be unit tested without running Nmap.
     */
    static Optional<String> parseVersion(String stdout) {
        if (stdout == null || stdout.isBlank()) {
            return Optional.empty();
        }
        Matcher matcher = VERSION_PATTERN.matcher(stdout);
        return matcher.find() ? Optional.of(matcher.group(1)) : Optional.empty();
    }
}
