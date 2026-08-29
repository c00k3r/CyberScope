package com.cyberscope.ui;

import com.cyberscope.repository.CveFeedLoader;
import com.cyberscope.repository.CveIndexManager;
import javafx.application.Platform;
import javafx.concurrent.Task;

/**
 * Refreshes the CVE index on a background thread.
 *
 * <p>The refresh downloads about 100 MB and takes roughly fifty seconds. On the
 * FX thread that is a frozen window, a spinning cursor and, on some platforms,
 * an "application not responding" dialog -- so it runs here instead, and reports
 * progress through the {@link Task} properties the UI can bind to.
 *
 * <p>{@code updateMessage} and {@code updateProgress} are the only two methods on
 * {@code Task} that may be called from the background thread; they marshal to the
 * FX thread themselves. Anything else that touches a node has to go through
 * {@link Platform#runLater}. Getting that wrong produces a
 * {@code java.lang.IllegalStateException: Not on FX application thread}, and it
 * produces it intermittently, which is worse.
 *
 * <p>Cancellation is cooperative: {@code cancel(true)} interrupts the thread and
 * {@code CveFeedLoader} checks the interrupt flag between years and between
 * batches. The existing index is left untouched on cancellation, because the
 * loader builds into a staging file and swaps only on success.
 */
public final class CveIndexTask extends Task<CveFeedLoader.Result> {

    private final CveIndexManager manager;

    public CveIndexTask(CveIndexManager manager) {
        this.manager = manager;
    }

    @Override
    protected CveFeedLoader.Result call() throws Exception {
        updateMessage("Starting...");
        updateProgress(0, 1);
        return new CveFeedLoader(manager).refresh((stage, done, total) -> {
            updateMessage(stage);
            updateProgress(done, total);
        });
    }
}