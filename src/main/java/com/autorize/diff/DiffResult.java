package com.autorize.diff;

import com.autorize.model.EnforcementStatus;

public class DiffResult {
    private final EnforcementStatus status;
    private final double similarityScore;
    private final String details;

    public DiffResult(EnforcementStatus status, double similarityScore, String details) {
        this.status = status;
        this.similarityScore = similarityScore;
        this.details = details;
    }

    public EnforcementStatus getStatus() { return status; }
    public double getSimilarityScore() { return similarityScore; }
    public String getDetails() { return details; }
}
