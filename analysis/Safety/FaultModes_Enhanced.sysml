package FaultModes {
    doc /* Enhanced fault modes with action mapping and propagation */
    private import GARC_Model::*;
    private import ScalarValues::*;
    private import Hazards::*;
    // ============================================================================
    // Enhanced Fault Mode Definition with Action Mapping
    // ============================================================================
    
    requirement def FaultMode {
        doc /* Fault mode definition with action dependency */
        attribute faultId : String;
        attribute component : String;
        attribute affectedAction : String;  // Links to action ID like "ACT-CMP-MOT-RUDDER-ACTUATION"
        attribute description : String;
        attribute failureRate : Real;  // failures per hour
        attribute detectionCoverage : Real;  // 0-1 probability
        attribute detectionTime : Real;  // seconds
        attribute mitigations : String;
        attribute causesHazards : Hazards::Hazard;
    }
    
    // ============================================================================
    // LOCALIZATION FAULTS
    // ============================================================================
    
    requirement FM_LOC_001 : FaultMode {
        doc /* GPS receiver hardware failure - no position fix available */
        attribute faultId :>> faultId = "FM-LOC-001";
        attribute component :>> component = "Localization";
        attribute affectedAction :>> affectedAction = "ACT-CMP-LOC-ESTIMATE-POSITION";
        attribute description :>> description = "GPS receiver fails to acquire or maintain satellite lock";
        attribute failureRate :>> failureRate = 1.0e-5;
        attribute detectionCoverage :>> detectionCoverage = 0.95;
        attribute detectionTime :>> detectionTime = 0.5;
        attribute mitigations :>> mitigations = "Multi-constellation GNSS, INS backup, integrity monitoring";
        attribute causesHazards :>> causesHazards ::> HAZ_LOC_001;
    }
    
    requirement FM_LOC_002 : FaultMode {
        doc /* IMU sensor drift accumulation */
        attribute faultId :>> faultId = "FM-LOC-002";
        attribute component :>> component = "Localization";
        attribute affectedAction :>> affectedAction = "ACT-CMP-LOC-SENSOR-FUSION";
        attribute description :>> description = "Inertial measurement unit accumulates drift beyond tolerance";
        attribute failureRate :>> failureRate = 5.0e-6;
        attribute detectionCoverage :>> detectionCoverage = 0.80;
        attribute detectionTime :>> detectionTime = 2.0;
        attribute mitigations :>> mitigations = "Periodic GNSS correction, zero-velocity updates";
        attribute causesHazards :>> causesHazards ::> HAZ_LOC_001;
    }
    
    requirement FM_LOC_003 : FaultMode {
        doc /* GPS spoofing attack succeeds */
        attribute faultId :>> faultId = "FM-LOC-003";
        attribute component :>> component = "Localization";
        attribute affectedAction :>> affectedAction = "ACT-CMP-LOC-SPOOF-DETECTION";
        attribute description :>> description = "Adversary successfully spoofs GNSS signals without detection";
        attribute failureRate :>> failureRate = 1.0e-7;
        attribute detectionCoverage :>> detectionCoverage = 0.99;
        attribute detectionTime :>> detectionTime = 0.1;
        attribute mitigations :>> mitigations = "Authentication, signal strength validation, dead reckoning comparison";
        attribute causesHazards :>> causesHazards ::> HAZ_LOC_002;
    }
    
    requirement FM_LOC_004 : FaultMode {
        doc /* Position estimate exceeds accuracy threshold */
        attribute faultId :>> faultId = "FM-LOC-004";
        attribute component :>> component = "Localization";
        attribute affectedAction :>> affectedAction = "ACT-CMP-LOC-SENSOR-FUSION";
        attribute description :>> description = "Fused position error grows beyond 5m safety envelope";
        attribute failureRate :>> failureRate = 2.0e-6;
        attribute detectionCoverage :>> detectionCoverage = 0.99;
        attribute detectionTime :>> detectionTime = 0.2;
        attribute mitigations :>> mitigations = "Error state monitoring, threshold alerts, navigation abort";
        attribute causesHazards :>> causesHazards ::> HAZ_LOC_001;
    }
    
    // ============================================================================
    // NAVIGATION FAULTS
    // ============================================================================
    
    requirement FM_NAV_001 : FaultMode {
        doc /* Trajectory planning algorithm produces unsafe path */
        attribute faultId :>> faultId = "FM-NAV-001";
        attribute component :>> component = "Navigation";
        attribute affectedAction :>> affectedAction = "ACT-CMP-NAV-PLAN-TRAJECTORY";
        attribute description :>> description = "Path planner computes trajectory that violates safety constraints";
        attribute failureRate :>> failureRate = 5.0e-7;
        attribute detectionCoverage :>> detectionCoverage = 0.90;
        attribute detectionTime :>> detectionTime = 0.5;
        attribute mitigations :>> mitigations = "Path validation, collision detection, constraint checking";
        attribute causesHazards :>> causesHazards ::> HAZ_AUTO_001;
    }
    
    requirement FM_NAV_002 : FaultMode {
        doc /* Geofence validation fails */
        attribute faultId :>> faultId = "FM-NAV-002";
        attribute component :>> component = "Navigation";
        attribute affectedAction :>> affectedAction = "ACT-CMP-NAV-GEOFENCE";
        attribute description :>> description = "Geofence boundary check fails to prevent breach";
        attribute failureRate :>> failureRate = 1.0e-6;
        attribute detectionCoverage :>> detectionCoverage = 0.95;
        attribute detectionTime :>> detectionTime = 0.1;
        attribute mitigations :>> mitigations = "Redundant geofence logic, position uncertainty margin, abort trigger";
        attribute causesHazards :>> causesHazards ::> HAZ_PAYLOAD_002;
    }
    
    // ============================================================================
    // MOTION CONTROL FAULTS
    // ============================================================================
    
    requirement FM_MOT_001 : FaultMode {
        doc /* Rudder servo fails to respond to commands */
        attribute faultId :>> faultId = "FM-MOT-001";
        attribute component :>> component = "Motion Control";
        attribute affectedAction :>> affectedAction = "ACT-CMP-MOT-RUDDER-ACTUATION";
        attribute description :>> description = "Rudder servo mechanism jams or loses electrical power";
        attribute failureRate :>> failureRate = 5.0e-6;
        attribute detectionCoverage :>> detectionCoverage = 0.98;
        attribute detectionTime :>> detectionTime = 0.2;
        attribute mitigations :>> mitigations = "Redundant servo, position feedback, emergency abort";
        attribute causesHazards :>> causesHazards ::> HAZ_001;
    }
    
    requirement FM_MOT_002 : FaultMode {
        doc /* Propulsion system produces insufficient thrust */
        attribute faultId :>> faultId = "FM-MOT-002";
        attribute component :>> component = "Motion Control";
        attribute affectedAction :>> affectedAction = "ACT-CMP-MOT-THRUST-CONTROL";
        attribute description :>> description = "Main propulsion motor fails or fuel/power depleted";
        attribute failureRate :>> failureRate = 3.0e-6;
        attribute detectionCoverage :>> detectionCoverage = 0.95;
        attribute detectionTime :>> detectionTime = 0.1;
        attribute mitigations :>> mitigations = "Power monitoring, thrust feedback, recovery procedure";
        attribute causesHazards :>> causesHazards ::> HAZ_001;
    }
    
    requirement FM_MOT_003 : FaultMode {
        doc /* Actuator control signal corruption */
        attribute faultId :>> faultId = "FM-MOT-003";
        attribute component :>> component = "Motion Control";
        attribute affectedAction :>> affectedAction = "ACT-CMP-MOT-RUDDER-ACTUATION";
        attribute description :>> description = "CAN bus or signal line noise corrupts actuator commands";
        attribute failureRate :>> failureRate = 2.0e-6;
        attribute detectionCoverage :>> detectionCoverage = 0.85;
        attribute detectionTime :>> detectionTime = 0.05;
        attribute mitigations :>> mitigations = "CRC checking, message validation, watchdog timer";
        attribute causesHazards :>> causesHazards ::> HAZ_001;
    }
    
    // ============================================================================
    // PERCEPTION FAULTS
    // ============================================================================
    
    requirement FM_PERC_001 : FaultMode {
        doc /* Obstacle detection algorithm misses object in path */
        attribute faultId :>> faultId = "FM-PERC-001";
        attribute component :>> component = "Perception";
        attribute affectedAction :>> affectedAction = "ACT-CMP-PERC-OBSTACLE-DETECTION";
        attribute description :>> description = "ML algorithm false negative - obstacle not detected";
        attribute failureRate :>> failureRate = 1.0e-5;
        attribute detectionCoverage :>> detectionCoverage = 0.70;
        attribute detectionTime :>> detectionTime = 0.1;
        attribute mitigations :>> mitigations = "Ensemble methods, thermal imaging backup, conservative assumptions";
        attribute causesHazards :>> causesHazards ::> HAZ_PERC_001;
    }
    
    requirement FM_PERC_002 : FaultMode {
        doc /* False positive obstacle detection */
        attribute faultId :>> faultId = "FM-PERC-002";
        attribute component :>> component = "Perception";
        attribute affectedAction :>> affectedAction = "ACT-CMP-PERC-OBJECT-CLASSIFICATION";
        attribute description :>> description = "Algorithm incorrectly classifies environmental artifact as obstacle";
        attribute failureRate :>> failureRate = 5.0e-6;
        attribute detectionCoverage :>> detectionCoverage = 0.75;
        attribute detectionTime :>> detectionTime = 0.2;
        attribute mitigations :>> mitigations = "Classification confidence thresholding, temporal filtering";
        attribute causesHazards :>> causesHazards ::> HAZ_PERC_002;
    }
    
    // ============================================================================
    // COMMUNICATION FAULTS
    // ============================================================================
    
    requirement FM_COMM_001 : FaultMode {
        doc /* C2 receiver complete loss of signal */
        attribute faultId :>> faultId = "FM-COMM-001";
        attribute component :>> component = "Communication";
        attribute affectedAction :>> affectedAction = "ACT-CMP-COMM-RECEIVE-COMMAND";
        attribute description :>> description = "Radio receiver hardware failure or antenna damage";
        attribute failureRate :>> failureRate = 2.0e-6;
        attribute detectionCoverage :>> detectionCoverage = 1.0;
        attribute detectionTime :>> detectionTime = 0.01;
        attribute mitigations :>> mitigations = "Dual receiver, diverse frequency bands, fallback autonomous mode";
        attribute causesHazards :>> causesHazards ::> HAZ_002;
    }
    
    requirement FM_COMM_002 : FaultMode {
        doc /* Spoofed command accepted by system */
        attribute faultId :>> faultId = "FM-COMM-002";
        attribute component :>> component = "Communication";
        attribute affectedAction :>> affectedAction = "ACT-CMP-COMM-COMMAND-VALIDATION";
        attribute description :>> description = "Adversary injects forged command that passes authentication";
        attribute failureRate :>> failureRate = 5.0e-8;
        attribute detectionCoverage :>> detectionCoverage = 0.99;
        attribute detectionTime :>> detectionTime = 0.05;
        attribute mitigations :>> mitigations = "Strong cryptography, challenge-response, command logging";
        attribute causesHazards :>> causesHazards ::> HAZ_COMM_002;
    }
    
    requirement FM_COMM_003 : FaultMode {
        doc /* Telemetry transmission failure */
        attribute faultId :>> faultId = "FM-COMM-003";
        attribute component :>> component = "Communication";
        attribute affectedAction :>> affectedAction = "ACT-CMP-COMM-TRANSMIT-TELEMETRY";
        attribute description :>> description = "Transmitter hardware failure or buffer overflow";
        attribute failureRate :>> failureRate = 1.0e-6;
        attribute detectionCoverage :>> detectionCoverage = 0.80;
        attribute detectionTime :>> detectionTime = 0.5;
        attribute mitigations :>> mitigations = "Status feedback, transmission queue monitoring";
        attribute causesHazards :>> causesHazards ::> HAZ_002;
    }
    
    // ============================================================================
    // PAYLOAD FAULTS
    // ============================================================================
    
    requirement FM_PAYLOAD_001 : FaultMode {
        doc /* Arming interlock validation fails */
        attribute faultId :>> faultId = "FM-PAYLOAD-001";
        attribute component :>> component = "Payload";
        attribute affectedAction :>> affectedAction = "ACT-CMP-PAYLOAD-INTERLOCK-CHECK";
        attribute description :>> description = "Safety interlocks bypass or software fault allows arming in unsafe state";
        attribute failureRate :>> failureRate = 1.0e-7;
        attribute detectionCoverage :>> detectionCoverage = 1.0;
        attribute detectionTime :>> detectionTime = 0.01;
        attribute mitigations :>> mitigations = "Hardware interlocks, watchdog, independent monitoring";
        attribute causesHazards :>> causesHazards ::> HAZ_PAYLOAD_001;
    }
    
    requirement FM_PAYLOAD_002 : FaultMode {
        doc /* Payload transitions to armed outside geofence */
        attribute faultId :>> faultId = "FM-PAYLOAD-002";
        attribute component :>> component = "Payload";
        attribute affectedAction :>> affectedAction = "ACT-CMP-PAYLOAD-ARMING";
        attribute description :>> description = "Arming check fails to verify vehicle is in authorized zone";
        attribute failureRate :>> failureRate = 5.0e-8;
        attribute detectionCoverage :>> detectionCoverage = 0.99;
        attribute detectionTime :>> detectionTime = 0.1;
        attribute mitigations :>> mitigations = "Position verification, geofence margin, redundant checks";
        attribute causesHazards :>> causesHazards ::> HAZ_PAYLOAD_002;
    }
    
    requirement FM_PAYLOAD_003 : FaultMode {
        doc /* Disarm command fails during armed state */
        attribute faultId :>> faultId = "FM-PAYLOAD-003";
        attribute component :>> component = "Payload";
        attribute affectedAction :>> affectedAction = "ACT-CMP-PAYLOAD-DISARMING";
        attribute description :>> description = "Cannot transition payload to safe state when commanded";
        attribute failureRate :>> failureRate = 1.0e-7;
        attribute detectionCoverage :>> detectionCoverage = 1.0;
        attribute detectionTime :>> detectionTime = 0.01;
        attribute mitigations :>> mitigations = "Hardware safe switch, force trigger, manual recovery";
        attribute causesHazards :>> causesHazards ::> HAZ_PAYLOAD_003;
    }
    
    requirement FM_PAYLOAD_004 : FaultMode {
        doc /* Payload actuates prematurely */
        attribute faultId :>> faultId = "FM-PAYLOAD-004";
        attribute component :>> component = "Payload";
        attribute affectedAction :>> affectedAction = "ACT-CMP-PAYLOAD-ACTUATION";
        attribute description :>> description = "Trigger logic fires before target conditions met";
        attribute failureRate :>> failureRate = 5.0e-8;
        attribute detectionCoverage :>> detectionCoverage = 0.95;
        attribute detectionTime :>> detectionTime = 0.01;
        attribute mitigations :>> mitigations = "Multi-condition validation, manual armed flag, timing verification";
        attribute causesHazards :>> causesHazards ::> HAZ_PAYLOAD_004;
    }
}
