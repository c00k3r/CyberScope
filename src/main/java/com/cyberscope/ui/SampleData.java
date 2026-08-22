package com.cyberscope.ui;

import com.cyberscope.model.DetectionMethod;
import com.cyberscope.model.Host;
import com.cyberscope.model.HostState;
import com.cyberscope.model.Port;
import com.cyberscope.model.PortState;
import com.cyberscope.model.Protocol;
import com.cyberscope.model.Service;

import java.util.List;

/**
 * Static data used by v0.0.9 to prove the table renders.
 * Deleted at v0.1.0 when a real scan supplies the rows.
 */
final class SampleData {

    private SampleData() {
    }

    static Host host() {
        Service http = new Service("http", "SimpleHTTPServer", "0.6", "Python 3.11.15",
                List.of("cpe:/a:python:simplehttpserver:0.6"), DetectionMethod.PROBED, 10);
        Service ssh = new Service("ssh", "OpenSSH", "9.6p1", "Ubuntu",
                List.of("cpe:/a:openbsd:openssh:9.6p1"), DetectionMethod.PROBED, 10);
        Service guess = new Service("http-proxy", "", "", "",
                List.of(), DetectionMethod.TABLE, 3);

        return new Host("127.0.0.1", "localhost", HostState.UP, List.of(
                new Port(22,   Protocol.TCP, PortState.OPEN,   "syn-ack", ssh),
                new Port(8080, Protocol.TCP, PortState.OPEN,   "syn-ack", http),
                new Port(3128, Protocol.TCP, PortState.OPEN,   "syn-ack", guess),
                new Port(23,   Protocol.TCP, PortState.CLOSED, "reset",   null)));
    }
}
