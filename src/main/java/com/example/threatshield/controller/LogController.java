
package com.example.threatshield.controller;

import java.io.File;

import java.io.IOException;
import java.util.*;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

import com.example.threatshield.alert.Alert;
import com.example.threatshield.service.ThreatShieldService;

@CrossOrigin(origins = "*")
@RestController
public class LogController {

    private final ThreatShieldService s;

    // Restrict log files to this base directory
    private static final String ALLOWED_BASE_DIR = "E:\\test-logs";

    public LogController(ThreatShieldService s) {
        this.s = s;
    }

    private String validatePath(String path) throws IOException {
        File base = new File(ALLOWED_BASE_DIR).getCanonicalFile();
        File requested = new File(path).getCanonicalFile();
        if (!requested.getPath().startsWith(base.getPath() + File.separator)
                && !requested.equals(base)) {
            throw new SecurityException("Access denied: path outside allowed directory");
        }
        if (!requested.exists() || !requested.isFile()) {
            throw new IllegalArgumentException("File not found: " + path);
        }
        return requested.getPath();
    }

    @GetMapping("/analyze")
    public ResponseEntity<?> analyze(@RequestParam String path) {
        try {
            String safePath = validatePath(path);
            return ResponseEntity.ok(s.analyze(safePath));
        } catch (SecurityException e) {
            return ResponseEntity.status(403).body(Map.of("error", e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (IOException e) {
            return ResponseEntity.internalServerError().body(Map.of("error", "Failed to resolve path"));
        }
    }

    @GetMapping("/summary")
    public ResponseEntity<?> summary(@RequestParam String path) {
        try {
            String safePath = validatePath(path);
            List<Alert> alerts = s.analyze(safePath);
            Map<String, Object> data = new HashMap<>();
            data.put("totalAlerts", alerts.size());
            data.put("alerts", alerts);
            return ResponseEntity.ok(data);
        } catch (SecurityException e) {
            return ResponseEntity.status(403).body(Map.of("error", e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (IOException e) {
            return ResponseEntity.internalServerError().body(Map.of("error", "Failed to resolve path"));
        }
    }
}
