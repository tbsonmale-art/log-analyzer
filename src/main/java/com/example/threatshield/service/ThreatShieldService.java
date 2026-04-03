package com.example.threatshield.service;

import java.io.InputStream;
import java.util.List;
import org.springframework.stereotype.Service;
import com.example.threatshield.alert.Alert;
import com.example.threatshield.detector.DetectionEngine;
import com.example.threatshield.model.LogEvent;
import com.example.threatshield.parser.XmlLogParser;

@Service
public class ThreatShieldService {

    public List<Alert> analyze(InputStream inputStream) {
        List<LogEvent> events = XmlLogParser.parse(inputStream);
        return DetectionEngine.runAll(events);
    }
}