package com.autorize.model;

import java.awt.Color;

public enum EnforcementStatus {
    BYPASSED("Bypassed!", new Color(255, 153, 153), new Color(180, 0, 0)),
    ENFORCED("Enforced!", new Color(204, 255, 153), new Color(0, 140, 0)),
    AMBIGUOUS("Is enforced???", new Color(255, 204, 153), new Color(180, 90, 0)),
    DISABLED("Disabled", new Color(225, 225, 225), new Color(100, 100, 100)),
    ERROR("Error", new Color(255, 180, 180), new Color(150, 0, 0)),
    PENDING("Testing...", new Color(240, 240, 200), new Color(120, 120, 0));

    private final String displayName;
    private final Color backgroundColor;
    private final Color foregroundColor;

    EnforcementStatus(String displayName, Color backgroundColor, Color foregroundColor) {
        this.displayName = displayName;
        this.backgroundColor = backgroundColor;
        this.foregroundColor = foregroundColor;
    }

    public String getDisplayName() {
        return displayName;
    }

    public Color getBackgroundColor() {
        return backgroundColor;
    }

    public Color getForegroundColor() {
        return foregroundColor;
    }

    public static EnforcementStatus fromString(String text) {
        if (text == null) return DISABLED;
        for (EnforcementStatus status : EnforcementStatus.values()) {
            if (status.displayName.equalsIgnoreCase(text) || status.name().equalsIgnoreCase(text)) {
                return status;
            }
        }
        return AMBIGUOUS;
    }
}
