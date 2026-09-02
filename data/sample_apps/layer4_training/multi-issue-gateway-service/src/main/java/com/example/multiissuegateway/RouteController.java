package com.example.multiissuegateway;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/routes")
public class RouteController {
    @GetMapping("/status")
    public String status() {
        return "route-ok";
    }
}
