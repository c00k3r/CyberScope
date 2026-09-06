package com.cyberscope.ui;

import com.cyberscope.repository.CveIndexManager;
import com.cyberscope.repository.CveRepository;
import com.cyberscope.repository.Preferences;
import com.cyberscope.repository.RepositoryException;
import com.cyberscope.repository.ScanRepository;

import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The services every page shares, opened once.
 *
 * <h2>What this replaces</h2>
 *
 * Until v0.6.0 there was one view, so it owned everything: {@code ScanView}
 * opened the CVE index in its constructor, created the background executor, and
 * held the scan repository it was handed. With six pages that does not scale --
 * the dashboard, the vulnerability list and the scan page all need the same
 * index, and three copies of a 350 MB SQLite connection is not a design.
 *
 * <p>So the resources are opened here, once, and passed down. Pages hold a
 * reference; they do not open or close anything.
 *
 * <h2>Everything here is allowed to be missing</h2>
 *
 * Both repositories are nullable and both failures are recoverable, which is the
 * whole reason this class carries reasons as well as handles:
 *
 * <ul>
 *   <li>No <b>scan repository</b> (read-only home directory, full disk, corrupt
 *       file): scanning still works, history and everything derived from it does
 *       not.</li>
 *   <li>No <b>CVE index</b> (never built, or unreadable): scanning and history
 *       still work, the vulnerability column reports "no index" rather than
 *       lying with a blank.</li>
 * </ul>
 *
 * <p>{@link #blockedPages()} turns those two facts into the map
 * {@link Navigation} needs, in one place, so no page has to remember to
 * null-check before it draws.
 */
public final class AppContext {

    private final ScanRepository scans;              // nullable
    private final String scansUnavailable;
    private final CveIndexManager indexManager;      // nullable
    private final CveRepository cveIndex;            // nullable
    private final String indexUnavailable;

    /** Never null: every read falls back to a documented default. */
    private final Preferences preferences = new Preferences(Preferences.defaultLocation());

    /** One background thread for scans and index rebuilds. Daemon, named, single. */
    private final ExecutorService worker = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "cyberscope-worker");
        thread.setDaemon(true);
        return thread;
    });

    /**
     * @param scans            may be null; history and the dashboard degrade
     * @param scansUnavailable why, in a sentence shown to the user
     */
    public AppContext(ScanRepository scans, String scansUnavailable) {
        this.scans = scans;
        this.scansUnavailable = scans == null
                ? blankToDefault(scansUnavailable, "the scan database could not be opened")
                : "";

        CveIndexManager manager = null;
        CveRepository index = null;
        String reason = "";
        try {
            manager = new CveIndexManager(CveIndexManager.defaultLocation());
            index = new CveRepository(manager);
        } catch (RepositoryException e) {
            // A missing index costs the vulnerability column, not the scanner.
            reason = blankToDefault(e.getMessage(), "the CVE index could not be opened");
        }
        this.indexManager = manager;
        this.cveIndex = index;
        this.indexUnavailable = reason;
    }

    private static String blankToDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    public ScanRepository scans() {
        return scans;
    }

    public boolean hasScans() {
        return scans != null;
    }

    public String scansUnavailable() {
        return scansUnavailable;
    }

    public CveRepository cveIndex() {
        return cveIndex;
    }

    public CveIndexManager indexManager() {
        return indexManager;
    }

    public String indexUnavailable() {
        return indexUnavailable;
    }

    public Preferences preferences() {
        return preferences;
    }

    public ExecutorService worker() {
        return worker;
    }

    /**
     * The pages that cannot be opened, and why.
     *
     * <p>Only the three pages that read stored scans. Network scan, Settings and
     * About need nothing, which is what guarantees {@link Navigation} always has
     * somewhere to start.
     */
    public Map<PageId, String> blockedPages() {
        Map<PageId, String> blocked = new EnumMap<>(PageId.class);
        if (!hasScans()) {
            blocked.put(PageId.DASHBOARD, scansUnavailable);
            blocked.put(PageId.HISTORY, scansUnavailable);
            blocked.put(PageId.VULNERABILITIES, scansUnavailable);
        }
        return blocked;
    }

    /** Called on the FX thread at shutdown. */
    public void shutdown() {
        worker.shutdownNow();
    }
}
