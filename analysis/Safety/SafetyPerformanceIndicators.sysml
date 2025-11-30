package SafetyPerformanceIndicators {
doc /* Safety Performance Indicators (SPIs) for Runtime Monitoring */
private import GARC_Model::*;
private import ScalarValues::*;
private import SI::*;

// SPI metadata structure
requirement def SPIMetadata {
    attribute spiId : String;
    attribute name : String;
    attribute description : String;
    attribute measuredSubsystem : String;
    attribute targetValue : String;
    attribute currentValue : String;
    attribute units : String;
    attribute complianceStatus : ComplianceEnum;
    attribute trend : TrendEnum;
    attribute measurementFrequency : FrequencyValue;
    attribute violationConsequence : String;
}

// Communication subsystem SPIs
requirement SPI_COMM_001 : SPIMetadata {
    doc /* C2 link availability */
    attribute spiId :>> spiId = "SPI-COMM-001";
    attribute name :>> name = "C2 Link Availability";
    attribute description :>> description = "Percentage of mission time with active bidirectional C2 link";
    attribute measuredSubsystem :>> measuredSubsystem = "CommunicationSubsystem";
    attribute targetValue :>> targetValue = ">99%";
    attribute currentValue :>> currentValue = "99.4%";
    attribute units :>> units = "percent";
    attribute complianceStatus :>> complianceStatus = ComplianceEnum::compliant;
    attribute trend :>> trend = TrendEnum::stable;
    attribute measurementFrequency :>> measurementFrequency = 1[Hz];
    attribute violationConsequence :>> violationConsequence = "Increased risk of loss of abort authority";
}

requirement SPI_COMM_002 : SPIMetadata {
    doc /* Command latency */
    attribute spiId :>> spiId = "SPI-COMM-002";
    attribute name :>> name = "Command Delivery Latency";
    attribute description :>> description = "Time from command transmission to acknowledgment";
    attribute measuredSubsystem :>> measuredSubsystem = "CommunicationSubsystem";
    attribute targetValue :>> targetValue = "<500 ms";
    attribute currentValue :>> currentValue = "320 ms";
    attribute units :>> units = "milliseconds";
    attribute complianceStatus :>> complianceStatus = ComplianceEnum::compliant;
    attribute trend :>> trend = TrendEnum::stable;
    attribute measurementFrequency :>> measurementFrequency = 1[Hz];
    attribute violationConsequence :>> violationConsequence = "Delayed abort response in emergencies";
}

requirement SPI_COMM_003 : SPIMetadata {
    doc /* Abort command response time */
    attribute spiId :>> spiId = "SPI-COMM-003";
    attribute name :>> name = "Abort Response Time";
    attribute description :>> description = "Time from ABORT command transmission to payload SAFE state confirmation";
    attribute measuredSubsystem :>> measuredSubsystem = "CommunicationSubsystem, PayloadSubsystem";
    attribute targetValue :>> targetValue = "<2 s";
    attribute currentValue :>> currentValue = "1.8 s";
    attribute units :>> units = "seconds";
    attribute complianceStatus :>> complianceStatus = ComplianceEnum::compliant;
    attribute trend :>> trend = TrendEnum::improving;
    attribute measurementFrequency :>> measurementFrequency = 0.1[Hz];  // Per abort event
    attribute violationConsequence :>> violationConsequence = "Extended hazard exposure during abort sequence";
}

// Localization subsystem SPIs
requirement SPI_LOC_001 : SPIMetadata {
    doc /* Position accuracy */
    attribute spiId :>> spiId = "SPI-LOC-001";
    attribute name :>> name = "Position Estimate Accuracy";
    attribute description :>> description = "Circular Error Probable (CEP) 95% for position estimate";
    attribute measuredSubsystem :>> measuredSubsystem = "LocalizationSubsystem";
    attribute targetValue :>> targetValue = "<5 m";
    attribute currentValue :>> currentValue = "2.3 m";
    attribute units :>> units = "meters";
    attribute complianceStatus :>> complianceStatus = ComplianceEnum::compliant;
    attribute trend :>> trend = TrendEnum::stable;
    attribute measurementFrequency :>> measurementFrequency = 10[Hz];
    attribute violationConsequence :>> violationConsequence = "Risk of geofence violation or navigation hazard";
}

requirement SPI_LOC_002 : SPIMetadata {
    doc /* GNSS fix availability */
    attribute spiId :>> spiId = "SPI-LOC-002";
    attribute name :>> name = "GNSS Fix Availability";
    attribute description :>> description = "Percentage of time with valid GNSS position fix";
    attribute measuredSubsystem :>> measuredSubsystem = "LocalizationSubsystem";
    attribute targetValue :>> targetValue = ">95%";
    attribute currentValue :>> currentValue = "98.2%";
    attribute units :>> units = "percent";
    attribute complianceStatus :>> complianceStatus = ComplianceEnum::compliant;
    attribute trend :>> trend = TrendEnum::stable;
    attribute measurementFrequency :>> measurementFrequency = 1[Hz];
    attribute violationConsequence :>> violationConsequence = "Degraded position accuracy; reliance on dead reckoning";
}

// Payload subsystem SPIs
requirement SPI_PAYLOAD_001 : SPIMetadata {
    doc /* Abort response time from ARMED */
    attribute spiId :>> spiId = "SPI-PAYLOAD-001";
    attribute name :>> name = "Payload Abort Response Time";
    attribute description :>> description = "Time to transition from ARMED to SAFE upon abort command";
    attribute measuredSubsystem :>> measuredSubsystem = "PayloadSubsystem";
    attribute targetValue :>> targetValue = "<500 ms";
    attribute currentValue :>> currentValue = "420 ms";
    attribute units :>> units = "milliseconds";
    attribute complianceStatus :>> complianceStatus = ComplianceEnum::compliant;
    attribute trend :>> trend = TrendEnum::stable;
    attribute measurementFrequency :>> measurementFrequency = 0.1[Hz];  // Per abort event
    attribute violationConsequence :>> violationConsequence = "Extended window for inadvertent actuation during abort";
}

requirement SPI_PAYLOAD_002 : SPIMetadata {
    doc /* Safety interlock test pass rate */
    attribute spiId :>> spiId = "SPI-PAYLOAD-002";
    attribute name :>> name = "Interlock Self-Test Pass Rate";
    attribute description :>> description = "Percentage of periodic interlock self-tests that pass";
    attribute measuredSubsystem :>> measuredSubsystem = "PayloadSubsystem";
    attribute targetValue :>> targetValue = ">99%";
    attribute currentValue :>> currentValue = "99.7%";
    attribute units :>> units = "percent";
    attribute complianceStatus :>> complianceStatus = ComplianceEnum::compliant;
    attribute trend :>> trend = TrendEnum::stable;
    attribute measurementFrequency :>> measurementFrequency = 0.1[Hz];  // Per test cycle
    attribute violationConsequence :>> violationConsequence = "Potential interlock degradation undetected";
}

requirement SPI_PAYLOAD_003 : SPIMetadata {
    doc /* Geofence breach detection time */
    attribute spiId :>> spiId = "SPI-PAYLOAD-003";
    attribute name :>> name = "Geofence Violation Detection Latency";
    attribute description :>> description = "Time from crossing geofence boundary to detection and safe-state action";
    attribute measuredSubsystem :>> measuredSubsystem = "PayloadSubsystem";
    attribute targetValue :>> targetValue = "<1 s";
    attribute currentValue :>> currentValue = "0.7 s";
    attribute units :>> units = "seconds";
    attribute complianceStatus :>> complianceStatus = ComplianceEnum::compliant;
    attribute trend :>> trend = TrendEnum::stable;
    attribute measurementFrequency :>> measurementFrequency = 10[Hz];
    attribute violationConsequence :>> violationConsequence = "Payload armed outside authorized zone";
}

// Perception subsystem SPIs
requirement SPI_PERC_001 : SPIMetadata {
    doc /* Obstacle detection range */
    attribute spiId :>> spiId = "SPI-PERC-001";
    attribute name :>> name = "Mean Obstacle Detection Range";
    attribute description :>> description = "Average range at which obstacles are first detected";
    attribute measuredSubsystem :>> measuredSubsystem = "PerceptionSubsystem";
    attribute targetValue :>> targetValue = ">100 m";
    attribute currentValue :>> currentValue = "135 m";
    attribute units :>> units = "meters";
    attribute complianceStatus :>> complianceStatus = ComplianceEnum::compliant;
    attribute trend :>> trend = TrendEnum::stable;
    attribute measurementFrequency :>> measurementFrequency = 1[Hz];
    attribute violationConsequence :>> violationConsequence = "Insufficient reaction time for collision avoidance";
}

requirement SPI_PERC_002 : SPIMetadata {
    doc /* False positive rate */
    attribute spiId :>> spiId = "SPI-PERC-002";
    attribute name :>> name = "Obstacle False Positive Rate";
    attribute description :>> description = "Percentage of detected obstacles that are false alarms";
    attribute measuredSubsystem :>> measuredSubsystem = "PerceptionSubsystem";
    attribute targetValue :>> targetValue = "<5%";
    attribute currentValue :>> currentValue = "2.1%";
    attribute units :>> units = "percent";
    attribute complianceStatus :>> complianceStatus = ComplianceEnum::compliant;
    attribute trend :>> trend = TrendEnum::improving;
    attribute measurementFrequency :>> measurementFrequency = 1[Hz];
    attribute violationConsequence :>> violationConsequence = "Excessive mission aborts and reduced availability";
}

// Motion control SPIs
requirement SPI_MOTION_001 : SPIMetadata {
    doc /* Trajectory tracking error */
    attribute spiId :>> spiId = "SPI-MOTION-001";
    attribute name :>> name = "Cross-Track Error (RMS)";
    attribute description :>> description = "Root-mean-square deviation from planned trajectory";
    attribute measuredSubsystem :>> measuredSubsystem = "MotionControlSubsystem";
    attribute targetValue :>> targetValue = "<5 m";
    attribute currentValue :>> currentValue = "3.2 m";
    attribute units :>> units = "meters";
    attribute complianceStatus :>> complianceStatus = ComplianceEnum::compliant;
    attribute trend :>> trend = TrendEnum::stable;
    attribute measurementFrequency :>> measurementFrequency = 1[Hz];
    attribute violationConsequence :>> violationConsequence = "Risk of unplanned obstacle encounters";
}

requirement SPI_MOTION_002 : SPIMetadata {
    doc /* Minimum CPA to vessels */
    attribute spiId :>> spiId = "SPI-MOTION-002";
    attribute name :>> name = "Minimum Closest Point of Approach";
    attribute description :>> description = "Closest observed distance to any manned vessel during mission";
    attribute measuredSubsystem :>> measuredSubsystem = "MotionControlSubsystem";
    attribute targetValue :>> targetValue = ">50 m";
    attribute currentValue :>> currentValue = "87 m";
    attribute units :>> units = "meters";
    attribute complianceStatus :>> complianceStatus = ComplianceEnum::compliant;
    attribute trend :>> trend = TrendEnum::stable;
    attribute measurementFrequency :>> measurementFrequency = 1[Hz];
    attribute violationConsequence :>> violationConsequence = "Collision risk with manned vessels";
}

// Collaborative autonomy SPIs
requirement SPI_AUTO_001 : SPIMetadata {
    doc /* Inter-vessel spacing in swarm */
    attribute spiId :>> spiId = "SPI-AUTO-001";
    attribute name :>> name = "Minimum Inter-Vessel Distance";
    attribute description :>> description = "Closest observed spacing between GARC vessels during coordinated operations";
    attribute measuredSubsystem :>> measuredSubsystem = "CollaborativeAutonomySubsystem";
    attribute targetValue :>> targetValue = ">100 m";
    attribute currentValue :>> currentValue = "142 m";
    attribute units :>> units = "meters";
    attribute complianceStatus :>> complianceStatus = ComplianceEnum::compliant;
    attribute trend :>> trend = TrendEnum::stable;
    attribute measurementFrequency :>> measurementFrequency = 1[Hz];
    attribute violationConsequence :>> violationConsequence = "Inter-vessel collision risk";
}

requirement SPI_AUTO_002 : SPIMetadata {
    doc /* Decision cycle time */
    attribute spiId :>> spiId = "SPI-AUTO-002";
    attribute name :>> name = "Autonomous Decision Cycle Time";
    attribute description :>> description = "Time from perception update to new plan execution";
    attribute measuredSubsystem :>> measuredSubsystem = "CollaborativeAutonomySubsystem";
    attribute targetValue :>> targetValue = "<5 s";
    attribute currentValue :>> currentValue = "3.1 s";
    attribute units :>> units = "seconds";
    attribute complianceStatus :>> complianceStatus = ComplianceEnum::compliant;
    attribute trend :>> trend = TrendEnum::stable;
    attribute measurementFrequency :>> measurementFrequency = 0.2[Hz];
    attribute violationConsequence :>> violationConsequence = "Delayed response to dynamic environment changes";
}

// Vehicle management SPIs
requirement SPI_VM_001 : SPIMetadata {
    doc /* Time to safe state transition */
    attribute spiId :>> spiId = "SPI-VM-001";
    attribute name :>> name = "Safe State Transition Time";
    attribute description :>> description = "Time from fault detection to confirmed safe state entry";
    attribute measuredSubsystem :>> measuredSubsystem = "VehicleManagementSubsystem";
    attribute targetValue :>> targetValue = "<10 s";
    attribute currentValue :>> currentValue = "6.2 s";
    attribute units :>> units = "seconds";
    attribute complianceStatus :>> complianceStatus = ComplianceEnum::compliant;
    attribute trend :>> trend = TrendEnum::stable;
    attribute measurementFrequency :>> measurementFrequency = 0.1[Hz];  // Per fault event
    attribute violationConsequence :>> violationConsequence = "Extended hazard exposure during fault response";
}

requirement SPI_VM_002 : SPIMetadata {
    doc /* Subsystem health check pass rate */
    attribute spiId :>> spiId = "SPI-VM-002";
    attribute name :>> name = "Subsystem Health Check Pass Rate";
    attribute description :>> description = "Percentage of periodic health checks reporting nominal status";
    attribute measuredSubsystem :>> measuredSubsystem = "VehicleManagementSubsystem";
    attribute targetValue :>> targetValue = ">98%";
    attribute currentValue :>> currentValue = "99.1%";
    attribute units :>> units = "percent";
    attribute complianceStatus :>> complianceStatus = ComplianceEnum::compliant;
    attribute trend :>> trend = TrendEnum::stable;
    attribute measurementFrequency :>> measurementFrequency = 1[Hz];
    attribute violationConsequence :>> violationConsequence = "Undetected subsystem degradation";
}

enum def ComplianceEnum {
    compliant;       // Meeting target
    marginal;        // Close to threshold
    nonCompliant;    // Violating target
    notMeasured;     // Insufficient data
}

enum def TrendEnum {
    improving;
    stable;
    degrading;
    unknown;
}
}
