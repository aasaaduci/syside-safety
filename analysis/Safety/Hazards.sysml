package Hazards {
    doc /* Hazard Definitions for GARC System */
    private import GARC_Model::*;
    private import ScalarValues::*;
    public import EnhancedHazards::*;
    
    private import SI::*;

    // Hazard metadata structure
    requirement def Hazard {
        attribute hazardId   : String;
        attribute title   : String;
        attribute description   : String;
        attribute severity   : SeverityEnum;
        attribute phase   : OperationalPhaseEnum;
        attribute effects   : String;
        attribute causes   : String;
    }
        // Supporting enumerations and types
    enum def SeverityEnum {
        catastrophic;  // Death, system loss, or severe environmental damage
        critical;      // Severe injury, major system damage
        marginal;      // Minor injury, minor system damage
        negligible;    // Less than minor injury or system damage
    }
    enum def OperationalPhaseEnum {
        allPhases;
        startup;
        navigation;
        autonomousOperations;
        collaborativeOperations;
        payloadOperations;
        recovery;
        shutdown;
    }
    // System-level hazards
    requirement HAZ_001 : Hazard {
        doc /* Loss of vessel control leading to collision or grounding */
        attribute hazardId :>> hazardId = "HAZ-001";
        attribute title :>> title = "Loss of Vessel Control";
        attribute description :>> description = "Platform loses ability to execute commanded trajectory, leading to collision or grounding";
        attribute severity :>> severity = SeverityEnum::catastrophic;
        attribute phase :>> phase = OperationalPhaseEnum::navigation;
        attribute effects :>> effects = "Collision with manned vessel, Infrastructure damage, Loss of vessel";
        attribute causes :>> causes = "Motion control failure, Actuator jam, Software crash, Power loss";
    }
    requirement HAZ_002 : Hazard {
        doc /* Loss of communication during mission-critical operations */
        attribute hazardId :>> hazardId = "HAZ-002";
        attribute title :>> title = "Loss of C2 Link During Critical Operations";
        attribute description :>> description = "Complete loss of command and control link when remote operators must intervene";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::allPhases;
        attribute effects :>> effects = "Loss of abort authority, Unable to terminate mission, Loss of situational awareness";
        attribute causes :>> causes = "Radio failure, Jamming, Beyond radio horizon, Antenna damage";
    }
    // Localization subsystem hazards
    requirement HAZ_LOC_001 : Hazard {
        doc /* Position error exceeds safety boundary */
        attribute hazardId :>> hazardId = "HAZ-LOC-001";
        attribute title :>> title = "Excessive Localization Error";
        attribute description :>> description = "Position estimate error exceeds allowable threshold for safe navigation";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::navigation;
        attribute effects :>> effects = "Geofence breach, Collision risk, Entry into restricted area";
        attribute causes :>> causes = "GPS spoofing, Satellite outage, IMU drift, Sensor fusion failure";
    }
    requirement HAZ_LOC_002 : Hazard {
        doc /* GPS spoofing attack successful */
        attribute hazardId :>> hazardId = "HAZ-LOC-002";
        attribute title :>> title = "Localization Spoof Attack";
        attribute description :>> description = "Adversary successfully spoofs GNSS signals, causing platform to report false position";
        attribute severity :>> severity = SeverityEnum::catastrophic;
        attribute phase :>> phase = OperationalPhaseEnum::allPhases;
        attribute effects :>> effects = "False position belief, Payload arming in wrong location, Loss of vessel control";
        attribute causes :>> causes = "GPS spoofing device, Inadequate spoof detection, Single source dependency";
    }
    // Communication subsystem hazards
    requirement HAZ_COMM_001 : Hazard {
        doc /* Loss of communication during payload arming sequence */
        attribute hazardId :>> hazardId = "HAZ-COMM-001";
        attribute title :>> title = "Communication Loss During Arming Operations";
        attribute description :>> description = "C2 link lost while payload is in ARMED or SAFE-TO-ARM state";
        attribute severity :>> severity = SeverityEnum::catastrophic;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Loss of remote abort, Unintended payload actuation, Loss of positive control";
        attribute causes :>> causes = "Radio TX failure, Jamming, Protocol timeout, Crypto failure";
    }
    requirement HAZ_COMM_002 : Hazard {
        doc /* Spoofed command accepted by system */
        attribute hazardId :>> hazardId = "HAZ-COMM-002";
        attribute title :>> title = "Spoofed Command Acceptance";
        attribute description :>> description = "Adversary successfully injects false command that passes authentication";
        attribute severity :>> severity = SeverityEnum::catastrophic;
        attribute phase :>> phase = OperationalPhaseEnum::allPhases;
        attribute effects :>> effects = "Unauthorized payload arming, Mission compromise, Loss of vehicle control";
        attribute causes :>> causes = "Weak authentication, Crypto key compromise, Replay attack, Protocol vulnerability";
    }
    requirement HAZ_COMM_003 : Hazard {
        doc /* Loss of abort command authority */
        attribute hazardId :>> hazardId = "HAZ-COMM-003";
        attribute title :>> title = "Loss of Abort Authority";
        attribute description :>> description = "Operator cannot successfully command abort when needed";
        attribute severity :>> severity = SeverityEnum::catastrophic;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Cannot stop armed platform, Uncontrolled payload";
        attribute causes :>> causes = "Communication failure, Command validation failure, Software fault";
    }
    // Payload subsystem hazards
    requirement HAZ_PAYLOAD_001 : Hazard {
        doc /* Inadvertent arming of explosive payload */
        attribute hazardId :>> hazardId = "HAZ-PAYLOAD-001";
        attribute title :>> title = "Inadvertent Payload Arming";
        attribute description :>> description = "Payload transitions to ARMED state without valid command sequence";
        attribute severity :>> severity = SeverityEnum::catastrophic;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Unintended arming, Premature actuation risk, Personnel hazard";
        attribute causes :>> causes = "Interlock bypass, Software fault, Hardware fault, Command corruption";
    }
    requirement HAZ_PAYLOAD_002 : Hazard {
        doc /* Arming outside designated geographic zone */
        attribute hazardId :>> hazardId = "HAZ-PAYLOAD-002";
        attribute title :>> title = "Geofence Violation During Arming";
        attribute description :>> description = "Payload arms when platform is outside authorized geographic zone";
        attribute severity :>> severity = SeverityEnum::catastrophic;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Arming in unsafe location, Violation of ROE, Collateral damage";
        attribute causes :>> causes = "Geofence validation failure, Position error, Software fault";
    }
    requirement HAZ_PAYLOAD_003 : Hazard {
        doc /* Loss of disarm capability */
        attribute hazardId :>> hazardId = "HAZ-PAYLOAD-003";
        attribute title :>> title = "Disarm Function Failure";
        attribute description :>> description = "System cannot transition from ARMED to SAFE state when commanded";
        attribute severity :>> severity = SeverityEnum::catastrophic;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Cannot safe payload, Extended hazard exposure, Loss of positive control";
        attribute causes :>> causes = "Actuator jam, Software hang, Power loss, Interlock fault";
    }
    requirement HAZ_PAYLOAD_004 : Hazard {
        doc /* Premature payload actuation */
        attribute hazardId :>> hazardId = "HAZ-PAYLOAD-004";
        attribute title :>> title = "Premature Payload Actuation";
        attribute description :>> description = "Payload actuates before target conditions are met";
        attribute severity :>> severity = SeverityEnum::catastrophic;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Wrong target engagement, Collateral damage, Mission failure";
        attribute causes :>> causes = "Trigger logic fault, Sensor false positive, Timing error";
    }
    // Perception subsystem hazards
    requirement HAZ_PERC_001 : Hazard {
        doc /* Failure to detect obstacle leading to collision */
        attribute hazardId :>> hazardId = "HAZ-PERC-001";
        attribute title :>> title = "Obstacle Detection Failure";
        attribute description :>> description = "Perception system fails to detect obstacle in collision path";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::navigation;
        attribute effects :>> effects = "Collision, Vessel damage, Personnel injury";
        attribute causes :>> causes = "Sensor blind spot, Sensor failure, Algorithm false negative, Environmental conditions";
    }
    requirement HAZ_PERC_002 : Hazard {
        doc /* False positive causing unnecessary abort */
        attribute hazardId :>> hazardId = "HAZ-PERC-002";
        attribute title :>> title = "Perception False Positive";
        attribute description :>> description = "Perception system incorrectly identifies obstacle, triggering unnecessary abort";
        attribute severity :>> severity = SeverityEnum::marginal;
        attribute phase :>> phase = OperationalPhaseEnum::navigation;
        attribute effects :>> effects = "Mission abort, Operational delay, Loss of availability";
        attribute causes :>> causes = "Sensor noise, Algorithm false positive, Environmental artifact";
    }
    // Collaborative Autonomy hazards
    requirement HAZ_AUTO_001 : Hazard {
        doc /* Autonomous decision leads to unsafe action */
        attribute hazardId :>> hazardId = "HAZ-AUTO-001";
        attribute title :>> title = "Unsafe Autonomous Decision";
        attribute description :>> description = "Autonomous planning or decision-making logic produces unsafe action";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::autonomousOperations;
        attribute effects :>> effects = "Unsafe trajectory, Collision risk, Geofence breach";
        attribute causes :>> causes = "Algorithm fault, Invalid assumptions, Incomplete world model";
    }
    requirement HAZ_AUTO_002 : Hazard {
        doc /* Swarm coordination failure in multi-vessel operations */
        attribute hazardId :>> hazardId = "HAZ-AUTO-002";
        attribute title :>> title = "Swarm Desynchronization";
        attribute description :>> description = "Multiple GARC vessels lose coordination, creating collision or separation risk";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::collaborativeOperations;
        attribute effects :>> effects = "Inter-vessel collision, Mission failure, Loss of coordination";
        attribute causes :>> causes = "Communication loss between vessels, Timing desync, Conflicting behaviors";
    }

}