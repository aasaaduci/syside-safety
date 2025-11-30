package SafetyRequirements {
    doc /* Safety Requirements for GARC System */
    private import GARC_Model::*;
    private import Hazards::*;
    private import SafetyGoals::*;
    private import ScalarValues::*;
    private import SI::*;

    // Requirement metadata structure
    requirement def SafetyRequirementMetadata {
        attribute reqId : String;
        attribute text : String;
        attribute rationale : String;
        attribute verificationMethod : VerificationMethodEnum;
        attribute satisfiesGoals : SystemSafetyGoal;
        attribute mitigatesHazards : Hazard[*];
    }

    // Communication subsystem safety requirements
    requirement SR_COMM_001 : SafetyRequirementMetadata {
        doc /* Abort capability maintenance */
        attribute reqId :>> reqId = "SR-COMM_001";
        attribute text :>> text = "The communication subsystem shall provide dual-redundant abort command paths to the payload controller.";
        attribute rationale :>> rationale = "Ensures abort authority is maintained even with partial communication failure.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::test;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_001;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_COMM_001;
    }

    requirement SR_COMM_002 : SafetyRequirementMetadata {
        doc /* Communication loss detection */
        attribute reqId :>> reqId = "SR-COMM_002";
        attribute text :>> text = "The communication subsystem shall detect loss of C2 link within 500 ms.";
        attribute rationale :>> rationale = "Rapid detection of communication loss enables timely fail-safe transition.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::test;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_001;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_COMM_001;
    }

    requirement SR_COMM_003 : SafetyRequirementMetadata {
        doc /* Command authentication */
        attribute reqId :>> reqId = "SR-COMM_003";
        attribute text :>> text = "All safety-critical commands (ARM, DISARM, ABORT, MISSION) shall be cryptographically authenticated and validated prior to execution.";
        attribute rationale :>> rationale = "Prevents acceptance of spoofed or replayed commands that could result in unsafe actions.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::test;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_004;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_COMM_002;
    }

    // Localization subsystem safety requirements
    requirement SR_LOC_001 : SafetyRequirementMetadata {
        doc /* Position accuracy bounds */
        attribute reqId :>> reqId = "SR-LOC_001";
        attribute text :>> text = "The localization subsystem shall maintain position accuracy within 5 m CEP95 during navigation.";
        attribute rationale :>> rationale = "Position accuracy is critical for geofencing and collision avoidance.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::test;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_003;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_LOC_001;
    }

    requirement SR_LOC_002 : SafetyRequirementMetadata {
        doc /* GPS spoofing detection */
        attribute reqId :>> reqId = "SR-LOC_002";
        attribute text :>> text = "The localization subsystem shall employ multi-source cross-validation to detect GNSS spoofing.";
        attribute rationale :>> rationale = "GPS spoofing poses existential threat to the platform; it must be detected quickly.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::analysis_;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_003;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_LOC_002;
    }

    requirement SR_LOC_003 : SafetyRequirementMetadata {
        doc /* Localization health monitoring */
        attribute reqId :>> reqId = "SR-LOC_003";
        attribute text :>> text = "The localization subsystem shall continuously monitor fix quality (DOP, satellite count, fault status) and declare DEGRADED when thresholds are exceeded.";
        attribute rationale :>> rationale = "Proactive detection of localization degradation enables preventive safety actions.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::test;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_003;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_LOC_001;
    }

    // Payload subsystem safety requirements
    requirement SR_PAYLOAD_001 : SafetyRequirementMetadata {
        doc /* Dual independent interlocks */
        attribute reqId :>> reqId = "SR-PAYLOAD_001";
        attribute text :>> text = "The payload subsystem shall implement two independent safety interlocks preventing unintended arming.";
        attribute rationale :>> rationale = "Dual interlocks eliminate single-point failure paths to inadvertent arming.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::test;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_002;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_PAYLOAD_001;
    }

    requirement SR_PAYLOAD_002 : SafetyRequirementMetadata {
        doc /* Geofence enforcement */
        attribute reqId :>> reqId = "SR-PAYLOAD_002";
        attribute text :>> text = "The payload subsystem shall verify platform position is within the authorized geofence before allowing SAFE-TO-ARM or ARMED states.";
        attribute rationale :>> rationale = "Prevents arming outside designated areas, enforcing ROE and reducing collateral risk.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::test;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_005;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_PAYLOAD_002;
    }

    requirement SR_PAYLOAD_003 : SafetyRequirementMetadata {
        doc /* Abort response time */
        attribute reqId :>> reqId = "SR-PAYLOAD_003";
        attribute text :>> text = "The payload subsystem shall transition from ARMED to SAFE state within 5 s of an abort command or watchdog timeout.";
        attribute rationale :>> rationale = "Rapid abort response minimizes exposure window during emergencies.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::test;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_001;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_COMM_003;
    }

    requirement SR_PAYLOAD_004 : SafetyRequirementMetadata {
        doc /* Separation distance enforcement */
        attribute reqId :>> reqId = "SR-PAYLOAD_004";
        attribute text :>> text = "The payload subsystem shall enforce minimum safe separation distance from protected zones prior to arming.";
        attribute rationale :>> rationale = "Ensures adequate buffer to reduce collateral damage risk.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::test;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_005;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_PAYLOAD_002;
    }

    requirement SR_PAYLOAD_005 : SafetyRequirementMetadata {
        doc /* Command sequence validation */
        attribute reqId :>> reqId = "SR-PAYLOAD_005";
        attribute text :>> text = "The payload subsystem shall enforce a strict authenticated command sequence (AUTHORIZE -> ARM -> ACTUATE).";
        attribute rationale :>> rationale = "Multi-step authenticated sequence prevents inadvertent or unauthorized arming.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::test;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_002;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_PAYLOAD_001;
    }

    requirement SR_PAYLOAD_006 : SafetyRequirementMetadata {
        doc /* Automatic reversion to SAFE */
        attribute reqId :>> reqId = "SR-PAYLOAD_006";
        attribute text :>> text = "The payload subsystem shall automatically revert to SAFE upon comm loss, geofence violation, interlock fault, or watchdog timeout.";
        attribute rationale :>> rationale = "Fail-safe design ensures the system defaults to SAFE rather than remaining armed during faults.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::test;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_001;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_COMM_001;
    }

    requirement SR_PAYLOAD_007 : SafetyRequirementMetadata {
        doc /* No single-point failure to ARM */
        attribute reqId :>> reqId = "SR-PAYLOAD_007";
        attribute text :>> text = "No single hardware or software fault shall result in transition to ARMED state.";
        attribute rationale :>> rationale = "Ensures robust defense-in-depth against inadvertent arming.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::analysis_;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_002;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_PAYLOAD_001;
    }

    // Perception subsystem safety requirements
    requirement SR_PERC_001 : SafetyRequirementMetadata {
        doc /* Obstacle detection performance */
        attribute reqId :>> reqId = "SR-PERC_001";
        attribute text :>> text = "The perception subsystem shall detect obstacles with cross-section greater than 1 m^2 at ranges beyond 100 m with a false negative rate below 5%.";
        attribute rationale :>> rationale = "Adequate detection range and reliability are required for collision avoidance.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::test;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_006;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_PERC_001;
    }

    requirement SR_PERC_002 : SafetyRequirementMetadata {
        doc /* Sensor degradation detection */
        attribute reqId :>> reqId = "SR-PERC_002";
        attribute text :>> text = "The perception subsystem shall detect sensor degradation or failure within 5 s and flag degraded mode.";
        attribute rationale :>> rationale = "Rapid detection of perception degradation enables timely speed reduction or abort.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::test;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_006;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_PERC_001;
    }

    // Motion control safety requirements
    requirement SR_MOTION_001 : SafetyRequirementMetadata {
        doc /* Collision avoidance maneuver */
        attribute reqId :>> reqId = "SR-MOTION_001";
        attribute text :>> text = "The motion control subsystem shall execute collision avoidance maneuvers to maintain COLREGS-compliant separation.";
        attribute rationale :>> rationale = "Compliance with maritime rules and safe distance maintenance prevents collisions.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::test;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_006;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_001;
    }

    requirement SR_MOTION_002 : SafetyRequirementMetadata {
        doc /* Actuator fault detection */
        attribute reqId :>> reqId = "SR-MOTION_002";
        attribute text :>> text = "The motion control subsystem shall detect actuator faults (rudder jam or thrust loss) within 1 s.";
        attribute rationale :>> rationale = "Rapid fault detection enables safe degradation before loss of control.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::test;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_007;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_001;
    }

    // Vehicle management safety requirements
    requirement SR_VM_001 : SafetyRequirementMetadata {
        doc /* Health monitoring and safe state transition */
        attribute reqId :>> reqId = "SR-VM_001";
        attribute text :>> text = "The vehicle management subsystem shall continuously monitor all safety-critical subsystems and command safe state within 10 s of a critical fault.";
        attribute rationale :>> rationale = "Centralized health monitoring ensures coordinated safe state transitions.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::test;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_007;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_001;
    }

    requirement SR_VM_002 : SafetyRequirementMetadata {
        doc /* Safe state definition and behavior */
        attribute reqId :>> reqId = "SR-VM_002";
        attribute text :>> text = "Safe state shall be defined as: (1) Payload SAFE, (2) Loiter or station-keep at current position, and (3) Broadcast distress status to operators.";
        attribute rationale :>> rationale = "Well-defined safe state ensures predictable and protective behavior under faults.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::demonstration;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_007;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_001;
    }

    // Collaborative autonomy safety requirements
    requirement SR_CA_001 : SafetyRequirementMetadata {
        doc /* Swarm deconfliction */
        attribute reqId :>> reqId = "SR-CA_001";
        attribute text :>> text = "The collaborative autonomy subsystem shall maintain minimum inter-vessel separation of 100 m during swarm operations.";
        attribute rationale :>> rationale = "Prevents inter-vessel collisions during swarm operations.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::test;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_008;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_AUTO_002;
    }

    requirement SR_CA_002 : SafetyRequirementMetadata {
        doc /* Autonomous decision verification */
        attribute reqId :>> reqId = "SR-CA_002";
        attribute text :>> text = "All autonomous mission decisions shall be verified against safety constraints; unsafe plans shall be rejected.";
        attribute rationale :>> rationale = "Ensures autonomous decisions do not violate safety boundaries.";
        attribute verificationMethod :>> verificationMethod = VerificationMethodEnum::test;
        attribute satisfiesGoals :>> satisfiesGoals ::> SG_006;
        attribute mitigatesHazards :>> mitigatesHazards ::> HAZ_AUTO_001;
    }

    enum def VerificationMethodEnum {
        test;          // Physical or simulation testing
        analysis_;      // Mathematical or statistical analysis
        inspection;    // Visual inspection or code review
        demonstration; // Operational demonstration
    }

    attribute def GoalReferenceArray {
        attribute goalIds : String[1..*];
    }
}
