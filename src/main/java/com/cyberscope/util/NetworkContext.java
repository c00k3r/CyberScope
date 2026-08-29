package com.cyberscope.util;
 
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.nio.channels.DatagramChannel;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
 
/**
 * Which way out of this machine a scan of a given target would go.
 *
 * <p>CyberScope stores the target string and, until v0.4.0, nothing about the
 * path a scan took to reach it. That is fine until two scans of the same string
 * reach two different machines -- which RFC 1918 space makes routine:
 * {@code 10.0.0.5} on a home LAN is a router, and {@code 10.0.0.5} over a
 * corporate VPN is somebody's production server. Comparing those two scans and
 * announcing "this host changed" is a fabricated finding.
 *
 * <p><strong>This deliberately does not detect VPNs.</strong> WireGuard,
 * OpenVPN, IPsec, Tailscale and corporate SSL VPNs all look different, and any
 * heuristic that claims to recognise them is wrong within a year. What a
 * comparison actually needs is not "was a VPN in use" but "did the path change
 * between these two scans", and that question has a deterministic answer:
 * the source address and the interface the kernel picked.
 *
 * @param sourceAddress the local address the OS would send from, or {@code ""}
 * @param interfaceName the egress interface, e.g. {@code eth0}, {@code tun0}
 * @param pointToPoint  true for a point-to-point interface. Most tunnels are;
 *                      this is a weak hint for display, never an assertion that
 *                      a VPN is present
 */
public record NetworkContext(String sourceAddress, String interfaceName, boolean pointToPoint) {
 
    /**
     * Null Object, for scans made before v0.4.0 and for hosts that could not be
     * resolved. Same pattern as {@code Service.UNKNOWN}: callers get an object
     * whose emptiness they can ask about, rather than a null they must remember
     * to check.
     */
    public static final NetworkContext UNKNOWN = new NetworkContext("", "", false);
 
    /**
     * How long a route lookup may take before it is abandoned.
     *
     * <p>Two seconds is generous for a healthy resolver answering from cache or
     * a local server, and short enough that a broken one costs a scan almost
     * nothing.
     */
    private static final Duration LOOKUP_TIMEOUT = Duration.ofSeconds(2);
 
    public NetworkContext {
        sourceAddress = sourceAddress == null ? "" : sourceAddress.trim();
        interfaceName = interfaceName == null ? "" : interfaceName.trim();
    }
 
    public boolean isKnown() {
        return !sourceAddress.isEmpty() || !interfaceName.isEmpty();
    }
 
    /**
     * True when two scans left this machine by a route that looks different.
     *
     * <p>Returns {@code false} when either side is unknown. An unknown context
     * is not evidence that the path changed, and treating it as such would put a
     * warning on every scan recorded before v0.4.0.
     */
    public boolean differsFrom(NetworkContext other) {
        if (other == null || !isKnown() || !other.isKnown()) {
            return false;
        }
        return !Objects.equals(sourceAddress, other.sourceAddress)
            || !Objects.equals(interfaceName, other.interfaceName);
    }
 
    public String describe() {
        if (!isKnown()) {
            return "unknown";
        }
        String route = sourceAddress.isEmpty() ? interfaceName
                     : sourceAddress + " via " + (interfaceName.isEmpty() ? "?" : interfaceName);
        return pointToPoint ? route + " (point-to-point)" : route;
    }
 
    /**
     * Works out the route to a target <em>without sending anything</em>.
     *
     * <p>{@code DatagramChannel.connect} on a UDP channel transmits no packets.
     * UDP has no handshake, so "connecting" only asks the kernel to run its
     * routing table, choose an interface and bind a local source address. The
     * chosen address is then readable through {@code getLocalAddress()}.
     *
     * <p>That matters for a scanner specifically: <strong>this must not put a
     * single byte on the wire.</strong> A tool that quietly emits traffic to a
     * target before its authorisation gate has been satisfied is doing exactly
     * what it tells its users not to do. Port 9 (discard) is used as the nominal
     * destination and is never contacted.
     *
     * <p>Never throws, and never blocks for long. A context that could not be
     * determined is a missing convenience, not a reason to fail -- or to
     * delay -- a scan the user asked for.
     */
    public static NetworkContext forTarget(String target) {
        return forTarget(target, LOOKUP_TIMEOUT);
    }
 
    /**
     * Bounded because name resolution is not.
     *
     * <p>Measured on this project: {@code forTarget("not a host name at all")}
     * blocked for <strong>10,009 ms</strong> waiting for a resolver that was
     * never going to answer. This runs in {@code NmapExecutor} <em>before</em>
     * the scan's own timeout budget starts, so an unresponsive DNS server would
     * have added ten seconds to a scan before Nmap was even launched -- and none
     * of it would have appeared in the reported duration.
     *
     * <p>The lookup runs on a daemon thread and the caller waits at most
     * {@code timeout}. {@code InetAddress.getByName} does not respond to
     * interruption, so a stranded lookup keeps running until the resolver gives
     * up; making the thread a daemon means it can never hold the JVM open, and
     * the result is simply discarded. Leaking a short-lived daemon thread is the
     * right trade against blocking a scan.
     */
    static NetworkContext forTarget(String target, Duration timeout) {
        if (target == null || target.isBlank()) {
            return UNKNOWN;
        }
        FutureTask<NetworkContext> task = new FutureTask<>(() -> resolve(target));
        Thread worker = new Thread(task, "cyberscope-route-lookup");
        worker.setDaemon(true);
        worker.start();
        try {
            return task.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            task.cancel(true);
            return UNKNOWN;
        } catch (InterruptedException e) {
            // The scan is being cancelled. Restore the flag and let the caller
            // notice; do not swallow it.
            Thread.currentThread().interrupt();
            return UNKNOWN;
        } catch (ExecutionException e) {
            return UNKNOWN;
        }
    }
 
    private static NetworkContext resolve(String target) {
        try (DatagramChannel channel = DatagramChannel.open()) {
            // A CIDR target is a network address; routing to it is the same
            // decision the kernel makes for any address inside it.
            String host = target.contains("/") ? target.substring(0, target.indexOf('/')) : target;
 
            // InetAddress.getByName("") returns the LOOPBACK address rather than
            // throwing -- documented JDK behaviour, and a trap. Without this
            // guard a malformed target of "/24" would strip to "" and report a
            // confident route to 127.0.0.1, describing a path to a target that
            // does not exist.
            if (host.isBlank()) {
                return UNKNOWN;
            }
 
            channel.connect(new InetSocketAddress(InetAddress.getByName(host), 9));
            InetSocketAddress local = (InetSocketAddress) channel.getLocalAddress();
            if (local == null || local.getAddress() == null) {
                return UNKNOWN;
            }
            InetAddress source = local.getAddress();
            NetworkInterface nif = NetworkInterface.getByInetAddress(source);
 
            return new NetworkContext(
                    source.getHostAddress(),
                    nif == null ? "" : nif.getName(),
                    nif != null && nif.isPointToPoint());
 
        } catch (UnknownHostException e) {
            // A hostname that does not resolve is the scan's problem to report,
            // not this method's. Nmap will produce a far better message.
            return UNKNOWN;
        } catch (IOException | RuntimeException e) {
            // Broad on purpose. NetworkInterface can throw a SocketException,
            // a SecurityManager can refuse, and a malformed target can produce
            // a RuntimeException from deep inside the JDK. None of those is a
            // reason to fail a scan over a piece of optional metadata.
            return UNKNOWN;
        }
    }
}
 
