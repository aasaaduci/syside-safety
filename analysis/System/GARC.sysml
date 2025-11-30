package GARC_Model {
doc /*
* Global Autonomous Reconnaissance Craft (GARC)
* Complete SysML v2 Model with Integrated Safety Analysis
* Supports: FTA, FHA, SHA, SSHA, FMEA, FMECA, FMEDA, STPA, BowTie, SPI
*/


private import ScalarValues::*;
private import Quantities::*;
private import ISQ::*;
private import SI::*;
private import MeasurementReferences::*;
// Import safety analysis packages
private import Hazards::*;
private import SafetyGoals::*;
private import SafetyRequirements::*;
private import SafetyPerformanceIndicators::*;
private import FaultModel::*;
private import SystemRequirements::*;

part def GARC_Segment {
    doc /*
     * Top-level autonomous surface vessel system
     * Operational Design Domain: Littoral waters, remote operations
     * Mission Profile: ISR, autonomous teaming, optional payload delivery
     */
    // System-level attributes
    attribute vesselLength : LengthValue = 4.9[m];
    attribute autonomyLevel : String = "SAE Level 4";
    attribute missionDuration : TimeValue = 24[h];
    // Subsystem composition
    part localization : Localization::LocalizationSubsystem[1];
    part communication : Communication::CommunicationSubsystem[1];
    part collaborativeAutonomy : CollaborativeAutonomy::CollaborativeAutonomySubsystem[1];
    part payload : Payload::PayloadSubsystem[0..1];
    part perception : Perception::PerceptionSubsystem[1];
    part vehicleManagement : VehicleManagement::VehicleManagementSubsystem[1];
    part motionControl : MotionControl::MotionControlSubsystem[1];
    // Power and physical infrastructure
    part powerSystem : PowerSubsystem[1];
    part hull : HullStructure[1];
    // System-level ports for external interfaces


    port c2Interface : C2Interface;
    port sensorDataOut : SensorDataInterface;
    port actuationIn : ActuationInterface;
    // System-level requirements allocation
    ref requirement REQ_SYS_001;
    ref requirement REQ_SYS_002;
    // System-level safety goals
    ref safetyGoal1 :>> SafetyGoals::SG_001;
    ref safetyGoal2 :>> SafetyGoals::SG_002;
    ref safetyGoal3 :>> SafetyGoals::SG_003;
    // System-level hazards
    ref hazard1 :>> Hazards::HAZ_001;
    ref hazard2 :>> Hazards::HAZ_002;
    // Connections between subsystems
    connect localization.positionOut to motionControl.positionIn;
    connect localization.positionOut to collaborativeAutonomy.ownPositionIn;
    connect perception.obstacleDataOut to motionControl.obstacleDataIn;
    connect perception.obstacleDataOut to collaborativeAutonomy.environmentDataIn;
    connect communication.c2DataOut to collaborativeAutonomy.c2CommandsIn;
    connect collaborativeAutonomy.MissionCommandPort to motionControl.missionCommandIn;
    // Fault propagation paths
    ref faultPropagation1 :>> FaultPropagation::FP_COMM_TO_PAYLOAD;
    ref faultPropagation2 :>> FaultPropagation::FP_LOCALIZATION_TO_MOTION;
    ref faultPropagation3 :>> FaultPropagation::FP_PERCEPTION_TO_AUTONOMY;
}
// Supporting infrastructure definitions
part def PowerSubsystem {
    attribute voltage : ElectricPotentialValue = 28[V];
    attribute capacity : EnergyValue = 5[kW*h];


    port powerOut : ElectricalPowerPort;
}
part def HullStructure {
    attribute material : String = "Composite";
    attribute displacementMass : MassValue = 400[kg];
}
// Interface definitions
port def C2Interface {
    doc /* Command and Control bidirectional interface */
    out commandData : C2CommandMessage;
    in telemetryData : TelemetryMessage;
    in statusData : StatusMessage;
}
port def SensorDataInterface {
    out cameraData : ImageData;
    out lidarData : PointCloudData;
    out radarData : RadarTrackData;
}
port def ActuationInterface {
    in thrustCommand : ThrustCommand;
    in rudderCommand : RudderCommand;
}
port def ElectricalPowerPort {
    out voltage : ElectricPotentialValue;
    out current : ElectricCurrentValue;
}

// Basic message and command definitions
attribute def C2CommandMessage {
    attribute command : String;
    attribute payload : String;
    attribute timestamp : TimeUnit;
}

attribute def TelemetryMessage {
    attribute status : String;
    attribute detail : String;
    attribute timestamp : TimeUnit;
}

attribute def StatusMessage {
    attribute component : String;
    attribute currentState : String;
    attribute faultCode : Integer;
}

attribute def ImageData {
    attribute format : String;
    attribute bytes : String;
}

attribute def PointCloudData {
    attribute points : String;
}

attribute def RadarTrackData {
    attribute tracks : String;
}

attribute def ThrustCommand {
    attribute thrust : Real;
}

attribute def RudderCommand {
    attribute angle : AngularMeasureValue;
}
}
