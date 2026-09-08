package com.cyberscope.ui;

import com.cyberscope.App;
import com.cyberscope.model.NetworkPosture;
import com.cyberscope.model.NetworkReport;
import com.cyberscope.model.PostureAssessment;
import com.cyberscope.model.ReportProvenance;
import com.cyberscope.model.ScanReport;
import com.cyberscope.service.report.HtmlReportWriter;
import com.cyberscope.service.report.ProvenanceReader;
import com.cyberscope.service.report.ReportFile;
import com.cyberscope.service.scanner.ScanOutcome;
import javafx.scene.control.Alert;
import javafx.scene.control.TextArea;
import javafx.stage.FileChooser;
import javafx.stage.Window;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;

/**
 * Turns what is on screen into a file on disk.
 *
 * <h2>Where the work happens</h2>
 *
 * Rendering is pure string building and takes single-digit milliseconds even for
 * 200 findings, so it runs on the FX thread. The two things that are <i>not</i>
 * fast -- scoring the scans and reading index provenance -- have already been
 * done by the page asking for the export. Nothing here queries a database, which
 * is why there is no Task.
 *
 * <p>The exception is provenance, which is three small reads. Left on the FX
 * thread deliberately rather than made asynchronous: a file chooser is already
 * open and modal at that point, so there is no frame to drop.
 *
 * <h2>Writing to a file the user chose</h2>
 *
 * The chooser supplies the path, so the user has already consented to that
 * location and confirmed any overwrite. What the code must not do is build a
 * path itself from a target string, and that is exactly what
 * {@link ReportFile#nameFor} exists to prevent -- it is the <i>suggested</i>
 * name, sanitised, and the chooser is free to be overruled.
 */
final class ReportExporter {

    private final AppContext context;

    ReportExporter(AppContext context) {
        this.context = context;
    }

    /**
     * The window a modal chooser should belong to, found from any node in it.
     *
     * <p>Taken from the control that was clicked rather than from the page's
     * root, because the root is a blank final while the constructor is still
     * running and a lambda cannot capture it. Null before the scene exists,
     * which {@code FileChooser} accepts -- an unparented dialog is worse than no
     * dialog only if it never appears, and it does.
     */
    static Window windowOf(javafx.scene.Node node) {
        return node == null || node.getScene() == null ? null : node.getScene().getWindow();
    }

    /** Provenance for a report written right now. Never throws. */
    ReportProvenance provenance(Instant now) {
        return new ProvenanceReader(context.cveIndex()).read(now, App.VERSION);
    }

    /**
     * Exports one scan.
     *
     * @param assessment the posture already computed by the calling page -- not
     *                   recomputed here, so the file says exactly what the screen
     *                   said. A report that disagrees with the view it was
     *                   exported from is worse than no report.
     */
    void exportScan(Window owner, ScanOutcome outcome, long scanId,
                    PostureAssessment assessment) {
        Instant now = Instant.now();
        ZoneId zone = ZoneId.systemDefault();

        ScanReport report = new ScanReport(outcome.run().target().value(), scanId,
                outcome.run().startedAt(), outcome.run().scanType(),
                outcome.run().command(), assessment, outcome.hosts(), provenance(now));

        write(owner, ReportFile.nameFor(report.target(), now, zone),
                () -> HtmlReportWriter.render(report, now, zone));
    }

    /** Exports every target's latest scan as one document. */
    void exportNetwork(Window owner, NetworkPosture posture) {
        Instant now = Instant.now();
        ZoneId zone = ZoneId.systemDefault();
        NetworkReport report = new NetworkReport(posture, provenance(now), now);

        write(owner, ReportFile.networkName(now, zone),
                () -> HtmlReportWriter.renderNetwork(report, now, zone));
    }

    private void write(Window owner, String suggestedName,
                       java.util.function.Supplier<String> render) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Save report");
        chooser.setInitialFileName(suggestedName);
        chooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("HTML report", "*.html"));

        Path chosen = fileFrom(chooser.showSaveDialog(owner));
        if (chosen == null) {
            return;                       // cancelled: not an error, say nothing
        }
        try {
            // Explicit UTF-8. A service banner can contain any byte, the document
            // declares <meta charset="utf-8">, and writing it in the platform
            // default encoding would produce a file that contradicts its own
            // header on any machine that is not already UTF-8.
            Files.writeString(chosen, render.get(), StandardCharsets.UTF_8);
        } catch (IOException | RuntimeException e) {
            failed(chosen, e);
        }
    }

    private static Path fileFrom(java.io.File file) {
        return file == null ? null : file.toPath();
    }

    /**
     * A failed export is a dialog, unlike a failed scan save.
     *
     * <p>The difference is what the user was doing. A scan that could not be
     * saved happened in the background while they read results, so it goes in the
     * status line. An export is a deliberate act with a file chooser: they are
     * waiting for a file, and silence would leave them believing they had one.
     */
    private static void failed(Path path, Exception error) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Report not saved");
        alert.setHeaderText("Could not write " + path.getFileName());
        TextArea detail = new TextArea(error.getMessage() == null
                ? error.toString() : error.getMessage());
        detail.setEditable(false);
        detail.setWrapText(true);
        detail.setPrefRowCount(4);
        alert.getDialogPane().setContent(detail);
        alert.showAndWait();
    }
}
