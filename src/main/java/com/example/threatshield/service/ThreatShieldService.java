package com.example.threatshield.service;

import java.util.List;

import org.springframework.stereotype.Service;

import com.example.threatshield.alert.Alert;
import com.example.threatshield.detector.DetectionEngine;
import com.example.threatshield.model.LogEvent;
import com.example.threatshield.parser.XmlLogParser;

@Service
public class ThreatShieldService {
    public List<Alert> analyze(String filePath) {
        List<LogEvent> events = XmlLogParser.parse(filePath);
        return DetectionEngine.runAll(events);
    }
}
