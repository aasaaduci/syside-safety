package SafetyGoals {
doc /* Safety Goals for GARC System */
private import GARC_Model::*;
private import Hazards::*;
private import SafetyRequirements::*;
private import ScalarValues::String;


// Safety goal structure
requirement def SystemSafetyGoal {
    attribute goalId : String;
    attribute statement : String;
    attribute rationale : String;
    attribute asil : ASILEnum;
    attribute mitigatesHazards : Hazard;
    attribute allocatedRequirements : RequirementReferenceArray;
}

requirement SG_001 : SystemSafetyGoal {
    doc /* Maintain abort capability at all times */
    attribute goalId :>> goalId = "SG-001";
    attribute statement :>> statement = "The system shall maintain the ability to abort mission and transition to a safe state at all times.";
    attribute rationale :>> rationale = "Loss of abort authority during armed operations creates catastrophic risk.";
    attribute asil :>> asil = ASILEnum::ASIL_D;
    //attribute mitigatesHazards :>> mitigatesHazards = ["HAZ-COMM-001", "HAZ-COMM-003", "HAZ-PAYLOAD-003"];
    //attribute allocatedRequirements :>> allocatedRequirements = ["SR-COMM-001", "SR-PAYLOAD-003", "SR-PAYLOAD-006"];
}

requirement SG_002 : SystemSafetyGoal {
    doc /* Prevent unintended payload actuation */
    attribute goalId :>> goalId = "SG-002";
    attribute statement :>> statement = "The system shall prevent payload arming or actuation except when explicitly authorized under controlled conditions.";
    attribute rationale :>> rationale = "Unintended arming or actuation poses catastrophic risk; multiple barriers are required.";
    attribute asil :>> asil = ASILEnum::ASIL_D;
    //attribute mitigatesHazards :>> mitigatesHazards = ["HAZ-PAYLOAD-001", "HAZ-PAYLOAD-004"];
    //attribute allocatedRequirements :>> allocatedRequirements = ["SR-PAYLOAD-001", "SR-PAYLOAD-005", "SR-PAYLOAD-007"];
}

requirement SG_003 : SystemSafetyGoal {
    doc /* Maintain accurate position awareness */
    attribute goalId :>> goalId = "SG-003";
    attribute statement :>> statement = "The system shall maintain position estimation accuracy within defined safety bounds.";
    attribute rationale :>> rationale = "Position errors can lead to geofence violations, collisions, and wrong-location arming.";
    attribute asil :>> asil = ASILEnum::ASIL_C;
    //attribute mitigatesHazards :>> mitigatesHazards = ["HAZ-LOC-001", "HAZ-LOC-002", "HAZ-PAYLOAD-002"];
    //attribute allocatedRequirements :>> allocatedRequirements = ["SR-LOC-001", "SR-LOC-002", "SR-LOC-003"];
}

requirement SG_004 : SystemSafetyGoal {
    doc /* Secure command authentication */
    attribute goalId :>> goalId = "SG-004";
    attribute statement :>> statement = "The system shall authenticate all mission-critical commands using strong cryptography.";
    attribute rationale :>> rationale = "Acceptance of spoofed commands could lead to unauthorized arming or unsafe behaviors.";
    attribute asil :>> asil = ASILEnum::ASIL_D;
    //attribute mitigatesHazards :>> mitigatesHazards = ["HAZ-COMM-002"];
    //attribute allocatedRequirements :>> allocatedRequirements = ["SR-COMM-003", "SR-PAYLOAD-005"];
}

requirement SG_005 : SystemSafetyGoal {
    doc /* Enforce geographic constraints */
    attribute goalId :>> goalId = "SG-005";
    attribute statement :>> statement = "The system shall enforce geographic boundaries and prevent payload arming outside authorized zones.";
    attribute rationale :>> rationale = "Arming outside authorized zones violates ROE and creates collateral damage risk.";
    attribute asil :>> asil = ASILEnum::ASIL_D;
    //attribute mitigatesHazards :>> mitigatesHazards = ["HAZ-PAYLOAD-002"];
    //attribute allocatedRequirements :>> allocatedRequirements = ["SR-PAYLOAD-002", "SR-PAYLOAD-004"];
}

requirement SG_006 : SystemSafetyGoal {
    doc /* Collision avoidance */
    attribute goalId :>> goalId = "SG-006";
    attribute statement :>> statement = "The system shall detect obstacles and execute collision avoidance maneuvers.";
    attribute rationale :>> rationale = "Collisions with manned vessels or infrastructure pose catastrophic consequences.";
    attribute asil :>> asil = ASILEnum::ASIL_C;
    //attribute mitigatesHazards :>> mitigatesHazards = ["HAZ-001", "HAZ-PERC-001"];
    //attribute allocatedRequirements :>> allocatedRequirements = ["SR-PERC-001", "SR-MOTION-001"];
}

requirement SG_007 : SystemSafetyGoal {
    doc /* Fail-safe behavior */
    attribute goalId :>> goalId = "SG-007";
    attribute statement :>> statement = "The system shall transition to a predefined safe state upon detection of critical faults.";
    attribute rationale :>> rationale = "Graceful degradation to safe state prevents escalation of faults into hazards.";
    attribute asil :>> asil = ASILEnum::ASIL_C;
    //attribute mitigatesHazards :>> mitigatesHazards = ["HAZ-001", "HAZ-PAYLOAD-001", "HAZ-PAYLOAD-003"];
    //attribute allocatedRequirements :>> allocatedRequirements = ["SR-VM-001", "SR-VM-002", "SR-PAYLOAD-006"];
}

requirement SG_008 : SystemSafetyGoal {
    doc /* Swarm coordination safety */
    attribute goalId :>> goalId = "SG-008";
    attribute statement :>> statement = "The system shall maintain safe coordination with other GARC vessels during collaborative operations.";
    attribute rationale :>> rationale = "Loss of swarm coordination can lead to vessel collisions and mission failure.";
    attribute asil :>> asil = ASILEnum::ASIL_B;
    //attribute mitigatesHazards :>> mitigatesHazards = ["HAZ-AUTO-002"];
    //attribute allocatedRequirements :>> allocatedRequirements = ["SR-CA-001", "SR-CA-002"];
}

enum def ASILEnum {
    ASIL_A;  // Lowest automotive safety integrity level
    ASIL_B;
    ASIL_C;
    ASIL_D;  // Highest automotive safety integrity level
}

attribute def HazardReferenceArray {
    attribute hazardIds : String[1..*];
}

attribute def RequirementReferenceArray {
    attribute requirementIds : String[1..*];
}
}
