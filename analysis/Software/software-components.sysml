package PayloadSoftware {
    doc /* Software components supporting Payload subsystem */
    private import ScalarValues::*;
    private import SI::*;
    private import Payload::*;
    private import PayloadActions::*;
    public import EnhancedPayloadSoftware::*;

    part def InterlockValidator {
        doc /* Validates all safety interlocks before arming */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action validate : PayloadActions::ValidateInterlocks;
        }
        bind ddsPort.sub = run.validate.position;
        bind ddsPort.sub = run.validate.commLinkStatus;
        bind ddsPort.sub = run.validate.separationStatus;
        bind ddsPort.pub = run.validate.interlockStatus;
    }

    part def ArmingAuthorizer {
        doc /* Checks authorization and geofence constraints */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action authorize : PayloadActions::AuthorizeArming;
        }
        bind ddsPort.sub = run.authorize.armCommand;
        bind ddsPort.sub = run.authorize.interlockStatus;
        bind ddsPort.sub = run.authorize.position;
        bind ddsPort.sub = run.authorize.geofenceBoundary;
        bind ddsPort.pub = run.authorize.armAuthorized;
    }

    part def PayloadController {
        doc /* Main payload state machine controller */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action arm : PayloadActions::ArmPayload;
        }
        bind ddsPort.sub = run.arm.armAuthorized;
        bind ddsPort.sub = run.arm.geofenceStatus;
        bind ddsPort.pub = run.arm.armedStatus;
    }

    part def SafetyLogic {
        doc /* Dual-channel independent safety interlock logic */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action disarm : PayloadActions::DisarmPayload;
        }
        bind ddsPort.sub = run.disarm.disarmCommand;
        bind ddsPort.sub = run.disarm.abortSignal;
        bind ddsPort.pub = run.disarm.safeStatus;
    }

    part def ActuationDriver {
        doc /* Payload actuation driver with feedback */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action execute : PayloadActions::ExecuteActuation;
        }
        bind ddsPort.sub = run.execute.actuationCommand;
        bind ddsPort.sub = run.execute.armedStatus;
        bind ddsPort.pub = run.execute.actuationFeedback;
    }

    part def StateMonitor {
        doc /* Independent state monitoring for verification */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action monitor : PayloadActions::MonitorState;
        }
        bind ddsPort.sub = run.monitor.currentState;
        bind ddsPort.sub = run.monitor.hardwareStatus;
        bind ddsPort.pub = run.monitor.mismatchDetected;
        bind ddsPort.pub = run.monitor.stateValid;
    }
}

package LocalizationSoftware {
    doc /* Software components supporting Localization subsystem */
    private import ScalarValues::*;
    private import SI::*;
    private import Localization::*;
    private import LocalizationActions::*;
    public import EnhancedLocalizationSoftware::*;

    part def GNSSProcessor {
        doc /* Processes raw GNSS signals and computes position */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action process : LocalizationActions::ProcessGNSS;
        }
        bind ddsPort.sub = run.process.gpsRawData;
        bind ddsPort.pub = run.process.gpsPosition;
    }

    part def INSProcessor {
        doc /* Processes IMU and compass data for orientation */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action process : LocalizationActions::ProcessINS;
        }
        bind ddsPort.sub = run.process.imuData;
        bind ddsPort.pub = run.process.insEstimate;
    }

    part def SensorFusionEngine {
        doc /* Multi-sensor fusion for robust position estimate */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action fuse : LocalizationActions::FusePositionData;
        }
        bind ddsPort.sub = run.fuse.gpsPosition;
        bind ddsPort.pub = run.fuse.fusedPosition;
    }

    part def HealthMonitor {
        doc /* Monitors localization system health */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action monitor : LocalizationActions::MonitorHealth;
        }
        bind ddsPort.sub = run.monitor.gpsQuality;
        bind ddsPort.pub = run.monitor.healthStatus;
    }

    part def SpoofingDetector {
        doc /* Detects and mitigates GNSS spoofing attacks */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action detect : LocalizationActions::DetectSpoofing;
        }
        bind ddsPort.sub = run.detect.gpsSignalStrength;
        bind ddsPort.pub = run.detect.spoofingDetected;
    }
}

package NavigationSoftware {
    doc /* Software components supporting Navigation subsystem */
    private import ScalarValues::*;
    private import SI::*;
    private import Payload::*;
    private import NavigationActions::*;

    part def PathPlanner {
        doc /* Computes safe collision-free trajectory */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action plan : NavigationActions::PlanPath;
        }
        bind ddsPort.sub = run.plan.currentPosition;
        bind ddsPort.sub = run.plan.targetWaypoint;
        bind ddsPort.sub = run.plan.obstacles;
        bind ddsPort.pub = run.plan.desiredHeading;
        bind ddsPort.pub = run.plan.desiredSpeed;
    }

    part def WaypointValidator {
        doc /* Validates waypoint safety constraints */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action validate : NavigationActions::ValidateWaypoint;
        }
        bind ddsPort.sub = run.validate.targetWaypoint;
        bind ddsPort.sub = run.validate.systemCapabilities;
        bind ddsPort.pub = run.validate.waypointValid;
    }

    part def GeofenceEnforcer {
        doc /* Enforces geographic boundaries and arming zones */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action enforce : NavigationActions::EnforceGeofence;
        }
        bind ddsPort.sub = run.enforce.position;
        bind ddsPort.sub = run.enforce.geofenceBoundary;
        bind ddsPort.sub = run.enforce.armingZone;
        bind ddsPort.pub = run.enforce.boundaryViolation;
        bind ddsPort.pub = run.enforce.geofenceStatus;
    }

    part def ObstacleAvoidance {
        doc /* Modifies trajectory for obstacle avoidance */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action avoid : NavigationActions::AvoidObstacles;
        }
        bind ddsPort.sub = run.avoid.detectedObstacles;
        bind ddsPort.sub = run.avoid.currentTrajectory;
        bind ddsPort.pub = run.avoid.avoidanceTrajectory;
    }
}

package MotionControlSoftware {
    doc /* Software components supporting Motion Control subsystem */
    private import ScalarValues::*;
    private import SI::*;
    private import MotionControl::*;
    private import MotionControlActions::*;

    part def RudderController {
        doc /* Steering servo control with feedback loop */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action rudder : MotionControlActions::CommandRudder;
        }
        bind ddsPort.sub = run.rudder.headingCommand;
        bind ddsPort.sub = run.rudder.currentHeading;
        bind ddsPort.sub = run.rudder.feedback;
        bind ddsPort.pub = run.rudder.rudderAngle;
    }

    part def ThrustController {
        doc /* Propulsion thrust control with power management */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action thrust : MotionControlActions::CommandThrust;
        }
        bind ddsPort.sub = run.thrust.speedCommand;
        bind ddsPort.sub = run.thrust.currentSpeed;
        bind ddsPort.sub = run.thrust.powerAvailable;
        bind ddsPort.pub = run.thrust.thrustLevel;
    }

    part def SpeedRegulator {
        doc /* Speed setpoint regulation */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action regulate : MotionControlActions::RegulateSpeed;
        }
        bind ddsPort.sub = run.regulate.speedSetpoint;
        bind ddsPort.sub = run.regulate.currentSpeed;
        bind ddsPort.sub = run.regulate.thrustFeedback;
        bind ddsPort.pub = run.regulate.speedCommand;
    }

    part def CourseController {
        doc /* Heading setpoint maintenance */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action course : MotionControlActions::HoldCourse;
        }
        bind ddsPort.sub = run.course.headingSetpoint;
        bind ddsPort.sub = run.course.currentHeading;
        bind ddsPort.sub = run.course.rudderFeedback;
        bind ddsPort.pub = run.course.headingCommand;
    }
}

package PerceptionSoftware {
    doc /* Software components supporting Perception subsystem */
    private import ScalarValues::*;
    private import SI::*;
    private import Perception::*;
    private import PerceptionActions::*;

    part def ObjectDetector {
        doc /* Detects obstacles from sensor data using ML */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action detect : PerceptionActions::DetectObstacles;
        }
        bind ddsPort.sub = run.detect.sensorData;
        bind ddsPort.sub = run.detect.lidarData;
        bind ddsPort.sub = run.detect.cameraData;
        bind ddsPort.pub = run.detect.detectedObjects;
    }

    part def ObjectClassifier {
        doc /* Classifies detected objects into categories */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action classify : PerceptionActions::ClassifyObjects;
        }
        bind ddsPort.sub = run.classify.detectedObjects;
        bind ddsPort.sub = run.classify.objectDatabase;
        bind ddsPort.pub = run.classify.classifiedObjects;
    }

    part def ObjectTracker {
        doc /* Tracks moving objects across frames */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action track : PerceptionActions::TrackTargets;
        }
        bind ddsPort.sub = run.track.classifiedObjects;
        bind ddsPort.sub = run.track.priorTracks;
        bind ddsPort.pub = run.track.objectTracks;
    }

    part def ThreatAssessor {
        doc /* Assesses collision threat from tracked objects */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action assess : PerceptionActions::AssessThreat;
        }
        bind ddsPort.sub = run.assess.objectTracks;
        bind ddsPort.sub = run.assess.currentTrajectory;
        bind ddsPort.pub = run.assess.threatLevel;
    }
}

package CommunicationSoftware {
    doc /* Software components supporting Communication subsystem */
    private import ScalarValues::*;
    private import SI::*;
    private import Communication::*;
    private import CommunicationActions::*;
    public import EnhancedCommunicationSoftware::*;

    part def RadioHandler {
        doc /* Handles radio I/O including TX/RX data paths */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action handleRadio : CommunicationActions::ReceiveRFSignal;
        }
        bind ddsPort.sub = run.handleRadio.rfSignal;
        bind ddsPort.sub = run.handleRadio.frequencyTuning;
        bind ddsPort.pub = run.handleRadio.rawData;
    }

    part def ProtocolStack {
        doc /* Encodes and decodes communication frames */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action stackProtocol : CommunicationActions::DecodeMessage;
        }
        bind ddsPort.sub = run.stackProtocol.rawData;
        bind ddsPort.sub = run.stackProtocol.frameFormat;
        bind ddsPort.pub = run.stackProtocol.decodedMessage;
    }

    part def CommandValidator {
        doc /* Authenticates and validates received commands */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action validate : CommunicationActions::AuthenticateCommand;
        }
        bind ddsPort.sub = run.validate.decodedMessage;
        bind ddsPort.sub = run.validate.encryptionKey;
        bind ddsPort.sub = run.validate.commandWhitelist;
        bind ddsPort.pub = run.validate.validatedCommand;
        bind ddsPort.pub = run.validate.authenticationStatus;
    }

    part def ResponseEncoder {
        doc /* Encodes response messages for transmission */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action encode : CommunicationActions::EncodeResponse;
        }
        bind ddsPort.sub = run.encode.responseData;
        bind ddsPort.sub = run.encode.encryptionKey;
        bind ddsPort.pub = run.encode.encodedMessage;
    }

    part def TransmitterDriver {
        doc /* Modulates and transmits RF signals */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action transmit : CommunicationActions::TransmitRFSignal;
        }
        bind ddsPort.sub = run.transmit.encodedMessage;
        bind ddsPort.sub = run.transmit.frequencyTuning;
        bind ddsPort.pub = run.transmit.rfSignal;
    }

    part def ChannelMonitor {
        doc /* Monitors link quality and RF environment */
        port ddsPort {
            in sub;
            out pub;
        }
        action run {
            perform action monitorChannel : CommunicationActions::MonitorLinkQuality;
        }
        bind ddsPort.sub = run.monitorChannel.rfSignal;
        bind ddsPort.sub = run.monitorChannel.receivedFrames;
        bind ddsPort.pub = run.monitorChannel.linkQuality;
        bind ddsPort.pub = run.monitorChannel.errorRate;
        bind ddsPort.pub = run.monitorChannel.signalStrength;
    }
}
