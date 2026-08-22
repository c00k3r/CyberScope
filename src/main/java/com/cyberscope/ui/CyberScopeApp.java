package com.cyberscope.ui;

import com.cyberscope.App;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;

/**
 * JavaFX entry point. The command-line entry point remains {@link App}.
 *
 * <p>Deliberately thin: everything except lifecycle lives in {@link ScanView},
 * so the view can be built and inspected without launching an application.
 */
public class CyberScopeApp extends Application {

    @Override
    public void start(Stage stage) {
        ScanView view = new ScanView();
        stage.setTitle("CyberScope v" + App.VERSION + " - authorised targets only");
        stage.setScene(new Scene(view.root(), 780, 460));
        stage.setMinWidth(640);
        stage.setMinHeight(360);
        stage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
