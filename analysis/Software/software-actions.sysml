package SoftwareActions {
    doc /* Top-level Software Actions Package */
    private import PayloadActions::*;
    private import LocalizationActions::*;
    private import NavigationActions::*;
    private import MotionControlActions::*;
    private import PerceptionActions::*;
    private import CommunicationActions::*;

    action def Software_Actions {
        action payloadSubsystem : Payload_Action;
        action localizationSubsystem : Localization_Action;
        action navigationSubsystem : Navigation_Action;
        action motionControlSubsystem : MotionControl_Action;
        action perceptionSubsystem : Perception_Action;
        action communicationSubsystem : Communication_Action;
    }
}

package ActionDefinitions {
    doc /* Common Action Definitions */
    private import ScalarValues::*;

    action def Function {
        exhibit state errorState;
    }

    state def errorState {
        state Operational;
        state ErroneousWrong;
        state ErroneousLost;
        state Late;
        state Early;
        state Inadvertent;
    }
}

package PayloadActions {
    doc /* Actions for Payload Subsystem */
    private import ScalarValues::*;
    private import Payload::*;

    action def Payload_Action {
        action validate : ValidateInterlocks;
        action authorize : AuthorizeArming;
        action arm : ArmPayload;
        action disarm : DisarmPayload;
        action execute : ExecuteActuation;
        action monitor : MonitorState;

        // Payload arming message flow
        flow from validate.interlockStatus to authorize.interlockStatus;
        flow from authorize.armAuthorized to arm.armAuthorized;
        flow from arm.armedStatus to execute.armedStatus;
        flow from arm.armedStatus to monitor.currentState;
        flow from execute.actuationFeedback to monitor.hardwareStatus;
    }

    action def ValidateInterlocks {
        doc /* Validate all safety interlocks before arming */
        in position;
        in geofenceStatus;
        in commLinkStatus;
        in separationStatus;
        in systemHealth;
        out interlockStatus;

        
    }

    action def AuthorizeArming {
        doc /* Check authorization and validate geofence */
        in armCommand;
        in interlockStatus;
        in position;
        in geofenceBoundary;
        out armAuthorized;
    }

    action def ArmPayload {
        doc /* Transition payload to ARMED state */
        in armAuthorized;
        in geofenceStatus;
        out armedStatus;
        out armPayload;

        ref LOF = Hazards::HAZ_PAYLOAD_003;  // Failure to arm
        ref IF = Hazards::HAZ_PAYLOAD_001;  // Inadvertent arming
        ref INCF = Hazards::HAZ_PAYLOAD_002;  // Arming outside designated zone
        ref EF = Hazards::HAZ_PAYLOAD_004;  // Premature actuation
        ref LF = Hazards::HAZ_PAYLOAD_003;  // Loss of disarm capability

    }

    action def DisarmPayload {
        doc /* Safely transition to SAFE state */
        in disarmCommand;
        in abortSignal;
        out safeStatus;
        out disarmPayload;
    }

    action def ExecuteActuation {
        doc /* Execute payload actuation */
        in actuationCommand;
        in actuationTrigger;
        in enableSignal;
        in armedStatus;
        out actuationFeedback;
        out actuationStatus;
    }

    action def MonitorState {
        doc /* Monitor payload state and health */
        in currentState;
        in hardwareStatus;
        out stateValid;
        out mismatchDetected;
    }
}

package LocalizationActions {
    doc /* Actions for Localization Subsystem */
    private import ScalarValues::*;
    private import Localization::*;

    action def Localization_Action {
        action gnssRecovery : ProcessGNSS;
        action insIntegration : ProcessINS;
        action sensorFusion : FusePositionData;
        action healthMonitoring : MonitorHealth;
        action spoofDetection : DetectSpoofing;

        // Localization sensor fusion flow
        flow from gnssRecovery.gpsPosition to sensorFusion.gpsPosition;
        flow from gnssRecovery.gpsQuality to healthMonitoring.gpsQuality;
        flow from insIntegration.insEstimate to sensorFusion.insEstimate;
        flow from sensorFusion.fusedPosition to healthMonitoring.fusedPosition;
        flow from sensorFusion.positionAccuracy to healthMonitoring.positionAccuracy;
        flow from gnssRecovery.gpsPosition to spoofDetection.gpsSignalStrength;
    }

    action def ProcessGNSS {
        doc /* Process raw GNSS signals */
        in gpsRawData;
        in constellationData;
        out gpsPosition;
        out gpsQuality;
    }

    action def ProcessINS {
        doc /* Process inertial measurement data */
        in imuData;
        in compassHeading;
        out insEstimate;
        out insDrift;
    }

    action def FusePositionData {
        doc /* Multi-sensor fusion for robust position */
        in gpsPosition;
        in gpsBackupPosition;
        in altitudeEstimate;
        in headingEstimate;
        in insEstimate;
        in priorPosition;
        out fusedPosition;
        out positionAccuracy;
    }

    action def MonitorHealth {
        doc /* Monitor localization system health */
        in gpsQuality;
        in fusedPosition;
        in positionAccuracy;
        in gpsQualityBackup;
        out healthStatus;
        out fixQuality;
    }

    action def DetectSpoofing {
        doc /* Detect and mitigate GNSS spoofing */
        in gpsSignalStrength;
        in gpsSignalBackup;
        in signalAuthenticCode;
        out spoofingDetected;
        out spoofMitigation;
    }
}

package NavigationActions {
    doc /* Actions for Navigation Subsystem */
    private import ScalarValues::*;
    private import Payload::*;

    action def Navigation_Action {
        action planTrajectory : PlanPath;
        action validateWaypoint : ValidateWaypoint;
        action enforceGeofence : EnforceGeofence;
        action avoidObstacles : AvoidObstacles;

        // Navigation planning flow
        flow from validateWaypoint.waypointValid to planTrajectory.targetWaypoint;
        flow from planTrajectory.desiredHeading to avoidObstacles.currentTrajectory;
        flow from avoidObstacles.avoidanceTrajectory to enforceGeofence.position;
    }

    action def PlanPath {
        doc /* Plan safe trajectory to waypoint */
        in currentPosition;
        in targetWaypoint;
        in obstacles;
        out desiredHeading;
        out desiredSpeed;
    }

    action def ValidateWaypoint {
        doc /* Validate waypoint safety constraints */
        in targetWaypoint;
        in systemCapabilities;
        out waypointValid;
    }

    action def EnforceGeofence {
        doc /* Enforce geographic boundaries */
        in position;
        in geofenceBoundary;
        in armingZone;
        out geofenceStatus;
        out boundaryViolation;
    }

    action def AvoidObstacles {
        doc /* Modify trajectory for obstacle avoidance */
        in detectedObstacles;
        in currentTrajectory;
        out avoidanceTrajectory;
    }
}

package MotionControlActions {
    doc /* Actions for Motion Control Subsystem */
    private import ScalarValues::*;
    private import MotionControl::*;

    action def MotionControl_Action {
        action rudderControl : CommandRudder;
        action thrustControl : CommandThrust;
        action speedRegulation : RegulateSpeed;
        action courseControl : HoldCourse;

        // Motion control feedback loops
        flow from speedRegulation.speedCommand to thrustControl.speedCommand;
        flow from courseControl.headingCommand to rudderControl.headingCommand;
        flow from rudderControl.rudderAngle to courseControl.rudderFeedback;
        flow from thrustControl.thrustLevel to speedRegulation.thrustFeedback;
    }

    action def CommandRudder {
        doc /* Command rudder servo actuation */
        in headingCommand;
        in currentHeading;
        in feedback;
        out rudderAngle;
    }

    action def CommandThrust {
        doc /* Command propulsion thrust */
        in speedCommand;
        in currentSpeed;
        in powerAvailable;
        out thrustLevel;
    }

    action def RegulateSpeed {
        doc /* Maintain desired speed setpoint */
        in speedSetpoint;
        in currentSpeed;
        in thrustFeedback;
        out speedCommand;
    }

    action def HoldCourse {
        doc /* Maintain desired heading */
        in headingSetpoint;
        in currentHeading;
        in rudderFeedback;
        out headingCommand;
    }
}

package PerceptionActions {
    doc /* Actions for Perception Subsystem */
    private import ScalarValues::*;
    private import Perception::*;

    action def Perception_Action {
        action detectObjects : DetectObstacles;
        action classifyObjects : ClassifyObjects;
        action trackObjects : TrackTargets;
        action assessThreat : AssessThreat;

        // Perception processing pipeline
        flow from detectObjects.detectedObjects to classifyObjects.detectedObjects;
        flow from classifyObjects.classifiedObjects to trackObjects.classifiedObjects;
        flow from trackObjects.objectTracks to assessThreat.objectTracks;
    }

    action def DetectObstacles {
        doc /* Detect obstacles from sensor data */
        in sensorData;
        in lidarData;
        in cameraData;
        out detectedObjects;
    }

    action def ClassifyObjects {
        doc /* Classify detected objects */
        in detectedObjects;
        in objectDatabase;
        out classifiedObjects;
    }

    action def TrackTargets {
        doc /* Track moving objects over time */
        in classifiedObjects;
        in priorTracks;
        out objectTracks;
    }

    action def AssessThreat {
        doc /* Assess collision threat from tracked objects */
        in objectTracks;
        in currentTrajectory;
        out threatLevel;
    }
}

package CommunicationActions {
    doc /* Actions for Communication Subsystem */
    private import ScalarValues::*;
    private import Communication::*;

    action def Communication_Action {
        action receiveSignal : ReceiveRFSignal;
        action decodeMessage : DecodeMessage;
        action validateCommand : AuthenticateCommand;
        action encodeResponse : EncodeResponse;
        action transmitData : TransmitRFSignal;
        action monitorLink : MonitorLinkQuality;

        // C2 command reception and validation flow
        flow from receiveSignal.rawData to decodeMessage.rawData;
        flow from decodeMessage.decodedMessage to validateCommand.decodedMessage;
        flow from validateCommand.validatedCommand to encodeResponse.responseData;
        flow from encodeResponse.encodedMessage to transmitData.encodedMessage;
        flow from receiveSignal.rawData to monitorLink.rfSignal;
    }

    action def ReceiveRFSignal {
        doc /* Receive and demodulate RF signals */
        in rfSignal;
        in frequencyTuning;
        out rawData;
    }

    action def DecodeMessage {
        doc /* Decode received message frames */
        in rawData;
        in frameFormat;
        out decodedMessage;
    }

    action def AuthenticateCommand {
        doc /* Authenticate and validate received commands */
        in decodedMessage;
        in encryptionKey;
        in commandWhitelist;
        out validatedCommand;
        out authenticationStatus;
    }

    action def EncodeResponse {
        doc /* Encode response message for transmission */
        in responseData;
        in encryptionKey;
        out encodedMessage;
        out encodedBackup;
    }

    action def TransmitRFSignal {
        doc /* Modulate and transmit RF signals */
        in encodedMessage;
        in frequencyTuning;
        out rfSignal;
    }

    action def MonitorLinkQuality {
        doc /* Monitor communication link health */
        in rfSignal;
        in receivedFrames;
        out linkQuality;
        out errorRate;
        out signalStrength;
    }
}
