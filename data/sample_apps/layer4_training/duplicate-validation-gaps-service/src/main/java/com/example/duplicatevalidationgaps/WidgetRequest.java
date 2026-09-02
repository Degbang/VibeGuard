package com.example.duplicatevalidationgaps;

import jakarta.validation.constraints.NotBlank;

public class WidgetRequest {
    @NotBlank
    private String widgetId;

    public String getWidgetId() {
        return widgetId;
    }
}
