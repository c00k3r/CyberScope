package com.cyberscope.ui;

import com.cyberscope.App;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;

/** JavaFX entry point. The command-line entry point remains {@link App}. */
public class CyberScopeApp extends Application {

    private ScanView view;

    @Override
    public void start(Stage stage) {
        view = new ScanView();
        stage.setTitle("CyberScope v" + App.VERSION + " - authorised targets only");
        stage.setScene(new Scene(view.root(), 820, 500));
        stage.setMinWidth(680);
        stage.setMinHeight(380);
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
