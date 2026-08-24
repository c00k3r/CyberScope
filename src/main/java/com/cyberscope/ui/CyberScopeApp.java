package com.cyberscope.ui;

import com.cyberscope.App;
import com.cyberscope.repository.DatabaseManager;
import com.cyberscope.repository.RepositoryException;
import com.cyberscope.repository.ScanRepository;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;

/** JavaFX entry point. The command-line entry point remains {@link App}. */
public class CyberScopeApp extends Application {

    private ScanView view;

    @Override
    public void start(Stage stage) {
        ScanRepository repository = null;
        String unavailable = "";

        // The database is a convenience, not a prerequisite. A read-only home
        // directory, a full disk, or a corrupt file must not stop someone running a
        // scan -- so the failure is carried into the UI as a message instead of
        // aborting startup.
        try {
            repository = new ScanRepository(
                    new DatabaseManager(DatabaseManager.defaultLocation()));
        } catch (RepositoryException e) {
            unavailable = e.getMessage();
            System.err.println("[!] Scan history disabled: " + e.getMessage());
        }

        view = new ScanView(repository, unavailable);
        stage.setTitle("CyberScope v" + App.VERSION + " - authorised targets only");
        stage.setScene(new Scene(view.root(), 1040, 560));
        stage.setMinWidth(820);
        stage.setMinHeight(420);
        stage.show();
    }

    /** Runs on the FX thread at shutdown; releases the scan executor. */
    @Override
    public void stop() {
        if (view != null) {
            view.shutdown();
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}