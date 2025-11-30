package FunctionalFailures {
    doc /* Functional failures mapped to hazards for FHA */
    private import GARC_Model::*;
    private import SystemModes::*;
    private import SI::*;
    private import ScalarValues::*;
    // Functional failure mapping
    requirement def FunctionalFailure {
        attribute failureId : String;
        attribute system : String;
        attribute functionName : String;
        attribute failureMode : String;
        attribute failureDescription : String;
        attribute modePhase : String;
        attribute linkedHazardId : String;
    }

    // Motion Control Failures
    requirement FF_MOT_001 : FunctionalFailure {
        doc /* Rudder control loss */
        attribute failureId :>> failureId = "FF-MOT-001";
        attribute system :>> system = "Motion Control";
        attribute functionName :>> functionName = "Rudder Actuation";
        attribute failureMode :>> failureMode = "Loss of Rudder Control";
        attribute failureDescription :>> failureDescription = "Rudder servo fails to respond to control commands";
        attribute modePhase :>> modePhase = "Navigation";
        attribute linkedHazardId :>> linkedHazardId = "HAZ-001";
    }

    requirement FF_MOT_002 : FunctionalFailure {
        doc /* Propulsion failure */
        attribute failureId :>> failureId = "FF-MOT-002";
        attribute system :>> system = "Motion Control";
        attribute functionName :>> functionName = "Propulsion";
        attribute failureMode :>> failureMode = "Loss of Thrust";
        attribute failureDescription :>> failureDescription = "Main propulsion system fails to produce thrust";
        attribute modePhase :>> modePhase = "Navigation";
        attribute linkedHazardId :>> linkedHazardId = "HAZ-001";
    }

    // Communication Failures
    requirement FF_COMM_001 : FunctionalFailure {
        doc /* C2 receiver failure */
        attribute failureId :>> failureId = "FF-COMM-001";
        attribute system :>> system = "Communication";
        attribute functionName :>> functionName = "Command Reception";
        attribute failureMode :>> failureMode = "C2 Receiver Failure";
        attribute failureDescription :>> failureDescription = "Radio receiver loses signal or malfunctions";
        attribute modePhase :>> modePhase = "AllPhases";
        attribute linkedHazardId :>> linkedHazardId = "HAZ-002";
    }

    requirement FF_COMM_002 : FunctionalFailure {
        doc /* Data corruption */
        attribute failureId :>> failureId = "FF-COMM-002";
        attribute system :>> system = "Communication";
        attribute functionName :>> functionName = "Data Integrity";
        attribute failureMode :>> failureMode = "Undetected Data Error";
        attribute failureDescription :>> failureDescription = "Received data contains undetected errors";
        attribute modePhase :>> modePhase = "AllPhases";
        attribute linkedHazardId :>> linkedHazardId = "HAZ-002";
    }

    // Payload Failures
    requirement FF_PAYLOAD_001 : FunctionalFailure {
        doc /* Arming interlock failure */
        attribute failureId :>> failureId = "FF-PAYLOAD-001";
        attribute system :>> system = "Payload";
        attribute functionName :>> functionName = "Interlock Validation";
        attribute failureMode :>> failureMode = "Interlock Bypass";
        attribute failureDescription :>> failureDescription = "Safety interlocks fail to prevent arming in unsafe conditions";
        attribute modePhase :>> modePhase = "PayloadOperations";
        attribute linkedHazardId :>> linkedHazardId = "HAZ-PAYLOAD-001";
    }

    requirement FF_PAYLOAD_002 : FunctionalFailure {
        doc /* Disarm failure */
        attribute failureId :>> failureId = "FF-PAYLOAD-002";
        attribute system :>> system = "Payload";
        attribute functionName :>> functionName = "Disarm Function";
        attribute failureMode :>> failureMode = "Disarm Failure";
        attribute failureDescription :>> failureDescription = "Cannot transition from ARMED to SAFE state when commanded";
        attribute modePhase :>> modePhase = "PayloadOperations";
        attribute linkedHazardId :>> linkedHazardId = "HAZ-PAYLOAD-003";
    }

    // Localization Failures
    requirement FF_LOC_001 : FunctionalFailure {
        doc /* Position error exceeds threshold */
        attribute failureId :>> failureId = "FF-LOC-001";
        attribute system :>> system = "Localization";
        attribute functionName :>> functionName = "Position Estimation";
        attribute failureMode :>> failureMode = "Excessive Position Error";
        attribute failureDescription :>> failureDescription = "Position error exceeds 5m safety threshold";
        attribute modePhase :>> modePhase = "Navigation";
        attribute linkedHazardId :>> linkedHazardId = "HAZ-LOC-001";
    }

    requirement FF_LOC_002 : FunctionalFailure {
        doc /* GNSS spoofing success */
        attribute failureId :>> failureId = "FF-LOC-002";
        attribute system :>> system = "Localization";
        attribute functionName :>> functionName = "GNSS Spoofing Detection";
        attribute failureMode :>> failureMode = "Spoofing Detection Failure";
        attribute failureDescription :>> failureDescription = "Adversary successfully spoofs GNSS signals undetected";
        attribute modePhase :>> modePhase = "Navigation";
        attribute linkedHazardId :>> linkedHazardId = "HAZ-LOC-002";
    }

    // Perception Failures
    requirement FF_PERC_001 : FunctionalFailure {
        doc /* Obstacle detection failure */
        attribute failureId :>> failureId = "FF-PERC-001";
        attribute system :>> system = "Perception";
        attribute functionName :>> functionName = "Obstacle Detection";
        attribute failureMode :>> failureMode = "Detection Failure";
        attribute failureDescription :>> failureDescription = "Algorithm fails to detect obstacle in collision path";
        attribute modePhase :>> modePhase = "Navigation";
        attribute linkedHazardId :>> linkedHazardId = "HAZ-PERC-001";
    }
}
