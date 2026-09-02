package com.example.duplicatevalidationgaps;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/widgets")
@RolesAllowed("user")
public class WidgetController {
    @PostMapping
    public String create(@RequestBody WidgetRequest request) {
        return request.getWidgetId();
    }

    @PutMapping
    public String update(@RequestBody WidgetRequest request) {
        return request.getWidgetId();
    }
}
