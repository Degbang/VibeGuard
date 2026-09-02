package com.example.unprotectedreports;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/reports")
public class ReportController {
    @GetMapping("/daily")
    public String daily() {
        return "daily-report";
    }
}
