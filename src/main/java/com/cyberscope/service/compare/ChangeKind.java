package com.cyberscope.service.compare;
 
/**
 * What kind of difference was found between two observations of one port.
 *
 * <p>The division that matters is {@link #isHostChange()}. Some of these mean
 * <em>the target changed</em>; others mean <em>what CyberScope knows about the
 * target changed</em>. Presenting the second kind as the first is the failure
 * this whole version exists to avoid — it sends somebody to investigate a host
 * where nothing happened.
 */
public enum ChangeKind {
 
    // ---- the host changed --------------------------------------------------
 
    /** A port that was not open is now open. Usually the most significant. */
    PORT_OPENED(true),
 
    /** A port that was open no longer is. */
    PORT_CLOSED(true),
 
    /** Any other transition, e.g. {@code closed -> filtered}: a firewall moved. */
    STATE_CHANGED(true),
 
    /** Both scans probed the port and got a different service back. */
    SERVICE_CHANGED(true),
 
    /** Both scans probed the same service and the version moved. */
    VERSION_CHANGED(true),
 
    // ---- what we know changed ----------------------------------------------
 
    /**
     * The port was inferred from its number before and properly probed now.
     * The host may not have changed at all; CyberScope simply learned more.
     */
    EVIDENCE_GAINED(false),
 
    /**
     * The port was probed before and could only be inferred now.
     *
     * <p>Worth surfacing, and worth <em>not</em> calling a host change. The
     * service may be identical; what is gone is the ability to confirm it.
     * A plausible cause is that something is now filtering the probe — which
     * is a lead, not a finding.
     */
    EVIDENCE_LOST(false);
 
    private final boolean hostChange;
 
    ChangeKind(boolean hostChange) {
        this.hostChange = hostChange;
    }
 
    /**
     * True when this describes the target, false when it describes our view of
     * the target.
     *
     * <p>A report must be able to separate the two without inspecting each
     * constant, so the distinction lives on the enum rather than in a
     * {@code switch} somewhere that will be forgotten when a constant is added.
     */
    public boolean isHostChange() {
        return hostChange;
    }
}
 

