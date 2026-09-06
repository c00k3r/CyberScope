package com.cyberscope.ui;

import com.cyberscope.App;
import com.cyberscope.repository.DatabaseManager;
import com.cyberscope.repository.RepositoryException;
import com.cyberscope.repository.ScanRepository;
import javafx.application.Application;
import javafx.geometry.Rectangle2D;
import javafx.scene.Scene;
import javafx.stage.Screen;
import javafx.stage.Stage;

/** JavaFX entry point. The command-line entry point remains {@link App}. */
public class CyberScopeApp extends Application {

    private AppShell shell;

    @Override
    public void start(Stage stage) {
        ScanRepository repository = null;
        String unavailable = "";

        // The database is a convenience, not a prerequisite. A read-only home
        // directory, a full disk, or a corrupt file must not stop someone running a
        // scan -- so the failure is carried into the UI as a message instead of
        // aborting startup. AppContext turns it into the set of pages that cannot
        // be opened, and the sidebar shows this sentence in their tooltips.
        try {
            repository = new ScanRepository(
                    new DatabaseManager(DatabaseManager.defaultLocation()));
        } catch (RepositoryException e) {
            unavailable = e.getMessage();
            System.err.println("[!] Scan history disabled: " + e.getMessage());
        }

        shell = new AppShell(new AppContext(repository, unavailable));

        // Visual bounds, not bounds: this already excludes the taskbar or dock,
        // so the status bar does not open underneath it.
        Rectangle2D screen = Screen.getPrimary().getVisualBounds();
        WindowGeometry.Placement where = WindowGeometry.fit(
                screen.getMinX(), screen.getMinY(), screen.getWidth(), screen.getHeight());

        stage.setTitle("CyberScope v" + App.VERSION + " - authorised targets only");
        stage.setScene(new Scene(shell.root(), where.width(), where.height()));
        stage.setMinWidth(where.minWidth());
        stage.setMinHeight(where.minHeight());
        stage.setX(where.x());
        stage.setY(where.y());

        // Printed, not logged, and kept permanently. "The window did not appear"
        // is unfalsifiable without it: a window placed off the edge of the screen
        // is indistinguishable from a window that was never created, and this is
        // the one line that tells the two apart from a terminal.
        System.out.println("[i] screen " + fmt(screen.getWidth()) + "x" + fmt(screen.getHeight())
                + " at (" + fmt(screen.getMinX()) + "," + fmt(screen.getMinY()) + ")"
                + "  ->  window " + fmt(where.width()) + "x" + fmt(where.height())
                + " at (" + fmt(where.x()) + "," + fmt(where.y()) + ")");

        stage.show();
    }

    private static String fmt(double value) {
        return String.valueOf(Math.round(value));
    }

    /** Runs on the FX thread at shutdown; releases the worker thread. */
    @Override
    public void stop() {
        if (shell != null) {
            shell.shutdown();
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}
