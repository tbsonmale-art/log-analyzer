package com.example.threatshield.detector;

import java.util.*;
import com.example.threatshield.alert.Alert;
import com.example.threatshield.model.LogEvent;

public class AccountCreationDetector {
    public static List<Alert> detect(List<LogEvent> events) {
        List<Alert> alerts = new ArrayList<>();
        for(LogEvent e: events){
            if(e.eventID==4720)
                alerts.add(new Alert("New user: "+e.username,"HIGH"));
        }
        return alerts;
    }
}
