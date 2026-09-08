package com.cyberscope.ui;

import com.cyberscope.App;
import com.cyberscope.repository.DatabaseManager;
import com.cyberscope.repository.Preferences;
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
    private Preferences preferences;
    private Stage stage;

    /**
     * The last non-maximized bounds, tracked while the window is open.
     *
     * <p>Needed because {@code Stage} does not keep them. Once maximized,
     * {@code getWidth()} returns the screen width and the size the user actually
     * chose is gone -- so it is recorded on every move and resize <i>while the
     * window is in its normal state</i>, and that is what gets saved.
     */
    private double[] restored;

    @Override
    public void start(Stage stage) {
        this.stage = stage;
        this.preferences = new Preferences(Preferences.defaultLocation());

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
        WindowGeometry.Placement where = WindowGeometry.restore(
                preferences.window(),
                screen.getMinX(), screen.getMinY(), screen.getWidth(), screen.getHeight());

        stage.setTitle("CyberScope v" + App.VERSION + " - authorised targets only");
        Scene scene = new Scene(shell.root(), where.width(), where.height());
        Styles.apply(scene);          // reaches ComboBox pop-ups, which are their own Scene
        stage.setScene(scene);
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

        restored = new double[] {where.x(), where.y(), where.width(), where.height()};
        stage.xProperty().addListener((o, was, is) -> rememberIfNormal());
        stage.yProperty().addListener((o, was, is) -> rememberIfNormal());
        stage.widthProperty().addListener((o, was, is) -> rememberIfNormal());
        stage.heightProperty().addListener((o, was, is) -> rememberIfNormal());

        stage.show();

        // After show(), not before: setMaximized on an unshown stage is applied
        // by some window managers and ignored by others, and the ones that
        // ignore it leave the window at its normal size with the flag set.
        if (preferences.windowMaximized()) {
            stage.setMaximized(true);
        }

        // After show(), because the Scene assigns initial focus when it is
        // displayed and would otherwise overwrite this. The sidebar is the
        // BorderPane's left child, so without this the window opens with focus
        // on a nav row and typing a target does nothing.
        shell.focusContent();
    }

    private void rememberIfNormal() {
        if (stage != null && !stage.isMaximized() && !stage.isIconified()
                && Double.isFinite(stage.getWidth()) && stage.getWidth() >= 1) {
            restored = new double[] {
                    stage.getX(), stage.getY(), stage.getWidth(), stage.getHeight()};
        }
    }

    private static String fmt(double value) {
        return String.valueOf(Math.round(value));
    }

    /** Runs on the FX thread at shutdown; releases the worker thread. */
    @Override
    public void stop() {
        saveWindow();
        if (shell != null) {
            shell.shutdown();
        }
    }

    /**
     * Best effort, and it has to stay best effort.
     *
     * <p>This runs while the application is closing. A read-only home directory
     * or a full disk is exactly the condition {@code Preferences} exists to
     * tolerate, and an exception thrown here would surface as a stack trace on
     * a window the user has already dismissed -- reporting a failure they cannot
     * act on, about a convenience they did not ask for, at the one moment they
     * cannot do anything about it. It goes to stderr and nowhere else.
     */
    private void saveWindow() {
        if (preferences == null || stage == null || restored == null) {
            return;
        }
        try {
            preferences.setWindow(restored[0], restored[1], restored[2], restored[3],
                    stage.isMaximized());
        } catch (RepositoryException | RuntimeException e) {
            System.err.println("[!] Could not save window position: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}
