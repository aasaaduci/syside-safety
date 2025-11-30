package Payload {
    doc /* Payload Subsystem - Explosive Payload Control */
    private import ScalarValues::*;
    private import SI::*;
    private import Quantities::*;
    private import MeasurementReferences::*;
    private import GARC_Model::*;
    private import Localization::*;
    private import PayloadSoftware::*;
    private import Hazards::*;
    private import SafetyGoals::*;
    private import SafetyRequirements::*;
    private import SafetyPerformanceIndicators::*;
    private import FaultModes::*;



    part def PayloadSubsystem {
        doc /*
        * Safety-critical explosive payload control system
        * Geographic arming zone enforcement
        * Multiple independent safety interlocks
        * Fail-safe design with automatic reversion to SAFE state
        */
        // Attributes
        attribute safetyIntegrityLevel : String = "SIL 3";
        attribute armingMode : ArmingStateEnum = ArmingStateEnum::safe;
        attribute geofenceEnabled : Boolean = true;
        attribute watchdogTimeout : TimeValue = 5[s];

        // Hardware components
        part safetyInterlock : RedundantSafetyInterlock[2];  // Dual redundant
        part actuator : PayloadActuator[1];
        part stateMonitor : IndependentStateMonitor[1];
        part watchdog : HardwareWatchdog[1];

        // Software components
        part payloadController : PayloadController[1];
        part safetyLogic : SafetyLogic[2];  // Dual redundant
        part armAuthorizer : ArmingAuthorizer[1];
        part interlockValidator : InterlockValidator[1];
        part actuationDriver : ActuationDriver[1];
        part geofenceValidator : GeofenceValidator[1];
        part geofenceLoader : GeofenceLoader[1];
        part roeLoader : ROELoader[1];
        part actuationEnabler : ActuationEnabler[1];
        part targetDetector : TargetDetector[1];
        part targetValidator : TargetValidator[1];
        part actuationVerifier : ActuationVerifier[1];
        part temperatureMonitor : TemperatureMonitor[1];
        part payloadLogger : PayloadLogger[1];

        // Ports
        port commandIn : PayloadCommandPort;
        port statusOut : PayloadStatusPort;
        port safetySignalIn : SafetySignalPort;
        port actuationOut : ActuationPort;

        // Internal connections
        connect commandIn to armAuthorizer.ddsPort.sub;
        connect armAuthorizer.ddsPort to payloadController.ddsPort;
        connect payloadController.ddsPort to safetyLogic.ddsPort;
        connect safetyLogic.ddsPort to safetyInterlock.enableIn;
        connect safetyInterlock.interlockOut to actuator.enableIn;
        connect stateMonitor.monitorOut to statusOut;
        connect watchdog.timeoutSignal to safetyLogic.ddsPort;
        connect safetyLogic.ddsPort to payloadController.ddsPort;
        connect geofenceValidator.ddsPort to interlockValidator.ddsPort;
        connect geofenceLoader.ddsPort to geofenceValidator.ddsPort;
        connect roeLoader.ddsPort to targetValidator.ddsPort;
        connect actuationEnabler.ddsPort to actuationDriver.ddsPort;
        connect targetDetector.ddsPort to targetValidator.ddsPort;
        connect targetValidator.ddsPort to actuationDriver.ddsPort;
        connect actuationDriver.ddsPort to actuationVerifier.ddsPort;
        connect temperatureMonitor.ddsPort to interlockValidator.ddsPort;
        connect payloadController.ddsPort to payloadLogger.ddsPort;


        // Safety requirements
        satisfy requirement SR_PAYLOAD_001;  // Dual independent interlocks
        satisfy requirement SR_PAYLOAD_002;  // Geofence enforcement
        satisfy requirement SR_PAYLOAD_003;  // Abort within 5s
        satisfy requirement SR_PAYLOAD_004;  // Separation distance enforcement
        satisfy requirement SR_PAYLOAD_005;  // Command authentication
        satisfy requirement SR_PAYLOAD_006;  // Automatic reversion to SAFE
        satisfy requirement SR_PAYLOAD_007;  // No single point failures
        // Fault modes
        ref faultMode1 :>> FaultModes::FM_PAYLOAD_001;  // Unintended arming
        ref faultMode2 :>> FaultModes::FM_PAYLOAD_002;  // No disarm response
        ref faultMode3 :>> FaultModes::FM_PAYLOAD_003;  // Interlock bypass
        ref faultMode4 :>> FaultModes::FM_PAYLOAD_004;  // Geofence violation
        // Hazard exposure
        ref hazard1 :>> Hazards::HAZ_PAYLOAD_001;  // Inadvertent arming
        ref hazard2 :>> Hazards::HAZ_PAYLOAD_002;  // Arming outside designated zone
        ref hazard3 :>> Hazards::HAZ_PAYLOAD_003;  // Loss of disarm capability
        ref hazard4 :>> Hazards::HAZ_PAYLOAD_004;  // Premature actuation
        ref hazard5 :>> Hazards::HAZ_PAYLOAD_005;
        ref hazard6 :>> Hazards::HAZ_PAYLOAD_006;
        ref hazard7 :>> Hazards::HAZ_PAYLOAD_007;
        ref hazard8 :>> Hazards::HAZ_TARGET_001;
        ref hazard9 :>> Hazards::HAZ_ROE_001;
        ref hazard10 :>> Hazards::HAZ_GEO_001;

        // Safety goals contribution
        ref safetyGoal1 :>> SafetyGoals::SG_001;  // Maintain abort capability
        ref safetyGoal2 :>> SafetyGoals::SG_002;  // Prevent unintended actuation
        ref safetyGoal3 :>> SafetyGoals::SG_005;  // Enforce geographic constraints
        
        // Safety Performance Indicators
        ref spi1 :>> SafetyPerformanceIndicators::SPI_PAYLOAD_001;  // Abort response time
        ref spi2 :>> SafetyPerformanceIndicators::SPI_PAYLOAD_002;  // Interlock test pass rate
        ref spi3 :>> SafetyPerformanceIndicators::SPI_PAYLOAD_003;  // Geofence breach detection
    }


    // Hardware component definitions
    part def RedundantSafetyInterlock {
        attribute channel : Integer;
        attribute diagnosticCoverage : Real = 0.99;
        port enableIn : BooleanSignalPort;
        port interlockOut : BooleanSignalPort;
        port diagnosticOut : DiagnosticPort;
    }
    part def PayloadActuator {
        attribute actuationType : String = "Electromechanical";
        attribute failSafeMode : String = "De-energize to SAFE";
        port enableIn : BooleanSignalPort;
        port actuationOut : ActuationSignalPort;
    }
    part def IndependentStateMonitor {
        attribute monitoringRate : FrequencyValue = 10[Hz];
        port stateIn : StatePort;
        port monitorOut : MonitorPort;
    }
    part def HardwareWatchdog {
        attribute timeout : TimeValue = 5[s];
        port kickIn : WatchdogKickPort;
        port timeoutSignal : BooleanSignalPort;
    }
    // Port definitions
    port def PayloadCommandPort {
        in authorize : AuthorizeCommand;
        in armingZone : GeographicZone;
        in arm : ArmCommand;
        in disarm : DisarmCommand;
        in abort : AbortCommand;
    }
    port def PayloadStatusPort {


        out currentState : ArmingStateEnum;
        out interlockStatus : InterlockStatusArray;
        out geofenceStatus : GeofenceStatusEnum;
        out lastCommand : CommandMessage;
        out faultStatus : PayloadFaultStatusEnum;
    }
    port def SafetySignalPort {
        in commLinkStatus : Boolean;
        in separationStatus : Boolean;
        in emergencyStop : Boolean;
    }
    port def ActuationPort {
        out actuate : Boolean;
    }
    port def BooleanSignalPort {
        inout signal : Boolean;
    }
    port def DiagnosticPort {
        out selfTestResult : Boolean;
        out faultCode : Integer;
    }
    port def ActuationSignalPort {
        out signal : Boolean;
    }
    port def StatePort {
        in state : ArmingStateEnum;
    }
    port def MonitorPort {
        out stateValid : Boolean;
        out mismatchDetected : Boolean;
    }


    port def WatchdogKickPort {
        in kick : Boolean;
    }
    // Command definitions
    attribute def AuthorizeCommand {
        attribute authToken : String;
        attribute timestamp : TimeUnit;
    }
    attribute def GeographicZone {
        attribute vertices : PositionArray;
        attribute minAltitude : LengthValue;
        attribute maxAltitude : LengthValue;
    }
    attribute def ArmCommand {
        attribute authToken : String;
        attribute timestamp : TimeUnit;
    }
    attribute def DisarmCommand {
        attribute timestamp : TimeUnit;
    }
    attribute def AbortCommand {
        attribute priority : Integer;
        attribute timestamp : TimeUnit;
    }
    attribute def PositionArray {
        attribute positions : PositionData[1..*];
    }
    // State and status definitions
    enum def ArmingStateEnum {
        safe;
        safeToArm;
        armed;
        faulted;
        aborted;


    }

    item def CommandMessage;

    attribute def InterlockStatusArray {
        attribute interlock1 : Boolean;
        attribute interlock2 : Boolean;
    }
    enum def GeofenceStatusEnum {
        insideZone;
        outsideZone;
        zoneNotSet;
        validationError;
    }
    enum def PayloadFaultStatusEnum {
        nominal;
        interlockFault;
        geofenceFault;
        commFault;
        watchdogFault;
        stateMonitorFault;
    }
}
