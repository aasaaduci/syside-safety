package FaultPropagation {
doc /* Fault Propagation Paths and Analysis */

private import GARC_Model::*;
private import FaultModes::*;
private import ScalarValues::*;
private import SI::*;
private import ScalarValues::*;
private import SI::*;
// Fault propagation path structure
attribute def FaultPropagationPath {
    attribute pathId : String;
    attribute sourceFault : String;  // Fault mode ID
    attribute sourceComponent : String;
    attribute destinationComponent : String;
    attribute propagationMechanism : PropagationMechanismEnum;
    attribute propagationTime : TimeValue;
    attribute canBeBlocked : Boolean;
    attribute blockingMechanism : String;
}

// Communication to Payload propagation
attribute FP_COMM_TO_PAYLOAD : FaultPropagationPath {
    doc /* Comm fault propagates to payload preventing abort */
    attribute pathId :>> pathId = "FP-001";
    attribute sourceFault :>> sourceFault = "FM-COMM-001";  // Loss of C2 link
    attribute sourceComponent :>> sourceComponent = "CommunicationSubsystem";
    attribute destinationComponent :>> destinationComponent = "PayloadSubsystem";
    attribute propagationTime :>> propagationTime = 0.5[s];
    attribute canBeBlocked :>> canBeBlocked = true;
    attribute blockingMechanism :>> blockingMechanism = "Automatic reversion to SAFE state on comm loss detection";
}

// Localization to Motion Control propagation
attribute FP_LOCALIZATION_TO_MOTION : FaultPropagationPath {
    doc /* Localization error propagates to motion control causing unsafe navigation */
    attribute pathId :>> pathId = "FP-002";
    attribute sourceFault :>> sourceFault = "FM-LOC-002";  // Degraded accuracy
    attribute sourceComponent :>> sourceComponent = "LocalizationSubsystem";
    attribute destinationComponent :>> destinationComponent = "MotionControlSubsystem";
    attribute propagationTime :>> propagationTime = 0.1[s];
    attribute canBeBlocked :>> canBeBlocked = true;
    attribute blockingMechanism :>> blockingMechanism = "Position accuracy monitoring with DEGRADED state declaration";
}

// Perception to Autonomy propagation
attribute FP_PERCEPTION_TO_AUTONOMY : FaultPropagationPath {
    doc /* Perception false negative propagates to autonomy causing unsafe decisions */
    attribute pathId :>> pathId = "FP-003";
    attribute sourceFault :>> sourceFault = "FM-PERC-002";  // False negative
    attribute sourceComponent :>> sourceComponent = "PerceptionSubsystem";
    attribute destinationComponent :>> destinationComponent = "CollaborativeAutonomySubsystem";
    attribute propagationTime :>> propagationTime = 0.2[s];
    attribute canBeBlocked :>> canBeBlocked = true;
    attribute blockingMechanism :>> blockingMechanism = "Conservative path planning with safety margins";
}

// Localization to Payload propagation
attribute FP_LOCALIZATION_TO_PAYLOAD : FaultPropagationPath {
    doc /* GPS spoof propagates to payload causing wrong-location arming */
    attribute pathId :>> pathId = "FP-004";
    attribute sourceFault :>> sourceFault = "FM-LOC-003";  // GPS spoofing
    attribute sourceComponent :>> sourceComponent = "LocalizationSubsystem";
    attribute destinationComponent :>> destinationComponent = "PayloadSubsystem";
    attribute propagationMechanism :>> propagationMechanism = PropagationMechanismEnum::dataFlow;
    attribute canBeBlocked :>> canBeBlocked = true;
    attribute blockingMechanism :>> blockingMechanism = "Multi-source position cross-validation before arming";
}

// Communication TX to RX propagation (within subsystem)
attribute FP_TX_TO_PROTOCOL : FaultPropagationPath {
    doc /* TX failure propagates to protocol stack */
    attribute pathId :>> pathId = "FP-005";
    attribute sourceFault :>> sourceFault = "FM-COMM-002";  // TX failure
    attribute sourceComponent :>> sourceComponent = "RadioHandler";
    attribute destinationComponent :>> destinationComponent = "ProtocolStack";
    attribute propagationMechanism :>> propagationMechanism = PropagationMechanismEnum::controlFlow;
    attribute propagationTime :>> propagationTime = 1[s];
    attribute canBeBlocked :>> canBeBlocked = true;
    attribute blockingMechanism :>> blockingMechanism = "Redundant TX channel switching";
}

// Payload interlock to controller propagation
attribute FP_INTERLOCK_TO_CONTROLLER : FaultPropagationPath {
    doc /* Interlock bypass propagates to controller enabling inadvertent arming */
    attribute pathId :>> pathId = "FP-006";
    attribute sourceFault :>> sourceFault = "FM-PAYLOAD-003";  // Interlock bypass
    attribute sourceComponent :>> sourceComponent = "SafetyInterlockLogic";
    attribute destinationComponent :>> destinationComponent = "PayloadController";
    attribute propagationMechanism :>> propagationMechanism = PropagationMechanismEnum::controlFlow;
    attribute propagationTime :>> propagationTime = .100[s];
    attribute canBeBlocked :>> canBeBlocked = true;
    attribute blockingMechanism :>> blockingMechanism = "Dual redundant interlocks with independent failure modes";
}

// Motion actuator to vehicle management propagation
attribute FP_ACTUATOR_TO_VM : FaultPropagationPath {
    doc /* Actuator fault propagates to vehicle management triggering safe mode */
    attribute pathId :>> pathId = "FP-007";
    attribute sourceFault :>> sourceFault = "FM-MOTION-001";  // Rudder jam
    attribute sourceComponent :>> sourceComponent = "ActuatorDriver";
    attribute destinationComponent :>> destinationComponent = "VehicleManagementSubsystem";
    attribute propagationMechanism :>> propagationMechanism = PropagationMechanismEnum::statusSignal;
    attribute canBeBlocked :>> canBeBlocked = false;
    attribute blockingMechanism :>> blockingMechanism = "N/A - Intended propagation for fault response";
}

// Swarm comm to coordination propagation
attribute FP_SWARM_COMM_TO_COORD : FaultPropagationPath {
    doc /* Loss of inter-vessel comm propagates to swarm logic causing desync */
    attribute pathId :>> pathId = "FP-008";
    attribute sourceFault :>> sourceFault = "FM-AUTO-002";  // Swarm comm loss
    attribute sourceComponent :>> sourceComponent = "DataFusion";
    attribute destinationComponent :>> destinationComponent = "SwarmLogic";
    attribute propagationMechanism :>> propagationMechanism = PropagationMechanismEnum::dataFlow;
    attribute propagationTime :>> propagationTime = 1[s];
    attribute canBeBlocked :>> canBeBlocked = true;
    attribute blockingMechanism :>> blockingMechanism = "Fall back to independent operations with increased separation";
}

// Perception degradation to motion control
attribute FP_PERC_DEGRADE_TO_MOTION : FaultPropagationPath {
    doc /* Environmental sensor degradation propagates to motion requiring speed reduction */
    attribute pathId :>> pathId = "FP-009";
    attribute sourceFault :>> sourceFault = "FM-PERC-003";  // Environmental degradation
    attribute sourceComponent :>> sourceComponent = "PerceptionSubsystem";
    attribute destinationComponent :>> destinationComponent = "MotionControlSubsystem";
    attribute propagationMechanism :>> propagationMechanism = PropagationMechanismEnum::statusSignal;
    attribute propagationTime :>> propagationTime = 5[s];
    attribute canBeBlocked :>> canBeBlocked = true;
    attribute blockingMechanism :>> blockingMechanism = "Adaptive speed reduction based on sensor confidence";
}

// Watchdog to payload propagation
attribute FP_WATCHDOG_TO_PAYLOAD : FaultPropagationPath {
    doc /* Watchdog timeout propagates to payload forcing SAFE state */
    attribute pathId :>> pathId = "FP-010";
    attribute sourceFault :>> sourceFault = "FM-PAYLOAD-005";  // Watchdog failure
    attribute sourceComponent :>> sourceComponent = "HardwareWatchdog";
    attribute destinationComponent :>> destinationComponent = "PayloadController";
    attribute propagationMechanism :>> propagationMechanism = PropagationMechanismEnum::hardwareSignal;
    attribute propagationTime :>> propagationTime = 10[s];
    attribute canBeBlocked :>> canBeBlocked = false;
    attribute blockingMechanism :>> blockingMechanism = "N/A - Intended safety action";
}

enum def PropagationMechanismEnum {
    dataFlow;        // Fault propagates through data dependencies
    controlFlow;     // Fault propagates through control logic
    statusSignal;    // Fault propagates through status/health reporting
    hardwareSignal;  // Fault propagates through electrical/mechanical path
    timing;          // Fault propagates through timing dependencies
}
}
