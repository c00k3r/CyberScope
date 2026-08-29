package com.cyberscope.model;

import java.util.List;
import java.util.Optional;

/**
 * The verdict for one port: what we looked up, what came back, and how sure we are
 * that the question was even asked.
 *
 * <p>Deliberately impossible to read as a bare list of findings. Callers reach the
 * vulnerabilities through {@link #vulnerabilities()}, but the outcome sits beside
 * them in the same object, so rendering the list without rendering the outcome has
 * to be a decision rather than an oversight.
 *
 * @param outcome         which of the four situations applies
 * @param cpe             the CPE that was looked up, when there was one
 * @param vulnerabilities findings, already in {@link Vulnerability#REPORT_ORDER};
 *                        always empty unless the outcome is {@link MappingOutcome#MAPPED}
 * @param detail          one human-readable sentence explaining the outcome
 */
public record VulnAssessment(MappingOutcome outcome, Cpe cpe,
                             List<Vulnerability> vulnerabilities, String detail) {

    public VulnAssessment {
        if (outcome == null) {
            throw new IllegalArgumentException("outcome must not be null");
        }
        vulnerabilities = vulnerabilities == null ? List.of() : List.copyOf(vulnerabilities);
        detail = detail == null ? "" : detail;
        // A non-MAPPED outcome carrying findings would be a contradiction the rest
        // of the system has no way to render, so it is refused at construction.
        if (outcome != MappingOutcome.MAPPED && !vulnerabilities.isEmpty()) {
            throw new IllegalArgumentException(
                    "only a MAPPED assessment may carry vulnerabilities, got " + outcome);
        }
    }

    public static VulnAssessment mapped(Cpe cpe, List<Vulnerability> found) {
        return new VulnAssessment(MappingOutcome.MAPPED, cpe, found,
                found.isEmpty()
                        ? "No CVEs are filed against " + cpe.productKey()
                          + " " + cpe.version() + "."
                        : found.size() + " CVE(s) filed against "
                          + cpe.productKey() + " " + cpe.version() + ".");
    }

    public static VulnAssessment unresolved(Cpe cpe) {
        return new VulnAssessment(MappingOutcome.UNRESOLVED, cpe, List.of(),
                "The CVE index has nothing filed under " + cpe.productKey()
                + ". This is not a statement about the host -- the lookup failed,"
                + " so no question was answered.");
    }

    public static VulnAssessment notApplicable(String reason) {
        return new VulnAssessment(MappingOutcome.NOT_APPLICABLE, null, List.of(), reason);
    }

    public static VulnAssessment indexUnavailable(String reason) {
        return new VulnAssessment(MappingOutcome.INDEX_UNAVAILABLE, null, List.of(), reason);
    }

    public Optional<Cpe> lookedUp() {
        return Optional.ofNullable(cpe);
    }

    /**
     * True only when a lookup actually happened and returned nothing.
     *
     * <p>The single method every "this looks clean" message must go through. It
     * cannot be written accidentally, unlike {@code vulnerabilities().isEmpty()},
     * which is true for all four outcomes.
     */
    public boolean isConfirmedClean() {
        return outcome.isConclusive() && vulnerabilities.isEmpty();
    }

    /** The worst severity found, or {@link Severity#UNKNOWN} if there are none. */
    public Severity worstSeverity() {
        return vulnerabilities.stream()
                .map(Vulnerability::severity)
                .max((a, b) -> Integer.compare(a.rank(), b.rank()))
                .orElse(Severity.UNKNOWN);
    }

    /** Findings that rest on an unbounded "all versions" claim. */
    public long weaklyMatchedCount() {
        return vulnerabilities.stream().filter(Vulnerability::isWeaklyMatched).count();
    }
}