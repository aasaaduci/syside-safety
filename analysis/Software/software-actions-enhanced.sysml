package EnhancedLocalizationActions {
    doc /* Enhanced Localization with multiple sensor fusion */
    private import ScalarValues::*;
    private import LocalizationActions::*;
    private import EnhancedHazards::*;
    private import Hazards::*;
    
    action def Localization_Action {
        action gnssRecovery : ProcessGNSS;
        action gnssBackup : ProcessGNSSBackup;  // NEW
        action insIntegration : ProcessINS;
        action barometerAlt : ProcessBarometer;  // NEW
        action magneticHeading : ProcessMagnetometer;  // NEW
        action sensorFusion : FusePositionData;
        action healthMonitoring : MonitorHealth;
        action spoofDetection : DetectSpoofing;
        action positionValidation : ValidatePositionQuality;  // NEW
        action driftCompensation : CompensateDrift;  // NEW
        
        // Primary GNSS path
        flow from gnssRecovery.gpsPosition to sensorFusion.gpsPosition;
        flow from gnssRecovery.gpsQuality to healthMonitoring.gpsQuality;
        
        // Backup GNSS path (redundancy)
        flow from gnssBackup.gpsPositionBackup to sensorFusion.gpsBackupPosition;
        flow from gnssBackup.gpsQualityBackup to healthMonitoring.gpsQualityBackup;
        
        // Inertial path
        flow from insIntegration.insEstimate to sensorFusion.insEstimate;
        flow from insIntegration.insDrift to driftCompensation.measuredDrift;
        
        // Barometric altitude
        flow from barometerAlt.altitude to sensorFusion.altitudeEstimate;
        
        // Magnetic heading
        flow from magneticHeading.heading to sensorFusion.headingEstimate;
        
        // Sensor fusion outputs
        flow from sensorFusion.fusedPosition to healthMonitoring.fusedPosition;
        flow from sensorFusion.fusedPosition to positionValidation.position;
        flow from sensorFusion.positionAccuracy to healthMonitoring.positionAccuracy;
        
        // Spoofing detection
        flow from gnssRecovery.gpsPosition to spoofDetection.gpsSignalStrength;
        flow from gnssBackup.gpsPositionBackup to spoofDetection.gpsSignalBackup;
        
        // Drift compensation feedback
        flow from driftCompensation.correctedEstimate to sensorFusion.insEstimate;
    }
    
    action def ProcessGNSSBackup {
        doc /* Backup GNSS receiver for redundancy */
        in gpsRawDataBackup;
        in constellationDataBackup;
        out gpsPositionBackup;
        out gpsQualityBackup;
        
        ref LOF = HAZ_LOC_003;  // Both GNSS failed
        ref INCF = HAZ_LOC_002;  // GPS spoofing on backup
    }
    
    action def ProcessBarometer {
        doc /* Barometric altitude for vertical position */
        in pressureData;
        in temperatureCompensation;
        out altitude;
        out altitudeQuality;
        
        ref LOF = HAZ_LOC_004;  // Altitude sensor failure
        ref INCF = HAZ_LOC_001;  // Wrong altitude reading
    }
    
    action def ProcessMagnetometer {
        doc /* Magnetic compass heading */
        in magneticField;
        in declination;
        out heading;
        out headingQuality;
        
        ref LOF = HAZ_LOC_005;  // Compass failure
        ref INCF = HAZ_001;  // Wrong heading causes collision
    }
    
    action def ValidatePositionQuality {
        doc /* Validate position solution quality */
        in position;
        in gpsQuality;
        in fusionCovariance;
        out positionValid;
        out qualityMetric;
        
        ref IF = HAZ_PAYLOAD_002;  // False good position allows arming
        ref LOF = HAZ_LOC_001;  // No quality check
    }
    
    action def CompensateDrift {
        doc /* Compensate INS drift using GNSS */
        in measuredDrift;
        in gpsReference;
        out correctedEstimate;
        out driftRate;
        
        ref INCF = HAZ_LOC_001;  // Wrong drift compensation
        ref LOF = HAZ_LOC_003;  // No drift compensation
    }
}


package EnhancedCommunicationActions {
    doc /* Enhanced Communication with redundancy and encryption */
    private import ScalarValues::*;
    private import CommunicationActions::*;
    private import EnhancedHazards::*;
    private import Hazards::*;
    
    action def Communication_Action {
        action receiveSignal : ReceiveRFSignal;
        action receiveBackup : ReceiveBackupLink;  // NEW
        action selectSource : SelectCommandSource;  // NEW
        action decodeMessage : DecodeMessage;
        action validateCommand : AuthenticateCommand;
        action validateSyntax : ValidateCommandSyntax;  // NEW
        action dispatchCommand : DispatchCommand;  // NEW
        action encryptTelemetry : EncryptTelemetry;  // NEW
        action encodeResponse : EncodeResponse;
        action transmitData : TransmitRFSignal;
        action transmitBackup : TransmitBackupLink;  // NEW
        action monitorLink : MonitorLinkQuality;
        action detectJamming : DetectJamming;  // NEW
        action logCommunication : LogCommEvents;  // NEW
        
        // Primary command reception
        flow from receiveSignal.rawData to selectSource.primaryCommand;
        flow from receiveBackup.backupData to selectSource.backupCommand;
        flow from selectSource.selectedCommand to decodeMessage.rawData;
        flow from decodeMessage.decodedMessage to validateCommand.decodedMessage;
        flow from validateCommand.validatedCommand to validateSyntax.command;
        flow from validateSyntax.validCommand to dispatchCommand.command;
        
        // Telemetry transmission
        flow from encryptTelemetry.encryptedData to encodeResponse.responseData;
        flow from encodeResponse.encodedMessage to transmitData.encodedMessage;
        flow from encodeResponse.encodedBackup to transmitBackup.backupMessage;
        
        // Link monitoring
        flow from receiveSignal.rawData to monitorLink.rfSignal;
        flow from monitorLink.linkQuality to selectSource.linkHealth;
        flow from receiveSignal.rawData to detectJamming.signalAnalysis;
        
        // Logging
        flow from validateCommand.validatedCommand to logCommunication.commandReceived;
        flow from transmitData.rfSignal to logCommunication.telemetrySent;
    }
    
    action def ReceiveBackupLink {
        doc /* Backup communication channel (satellite) */
        in satelliteSignal;
        in linkConfig;
        out backupData;
        out backupQuality;
        
        ref LOF = HAZ_COMM_001;  // Total C2 loss
        ref INCF = HAZ_COMM_002;  // Backup also spoofed
    }
    
    action def SelectCommandSource {
        doc /* Select between primary and backup command sources */
        in primaryCommand;
        in backupCommand;
        in linkHealth;
        out selectedCommand;
        out sourceUsed;
        
        ref IF = HAZ_COMM_002;  // Wrong source selected
        ref INCF = HAZ_COMM_004;  // Source switching glitch
        ref LOF = HAZ_COMM_001;  // Both sources failed
    }
    
    action def ValidateCommandSyntax {
        doc /* Validate command syntax and parameters */
        in command;
        in commandSchema;
        out validCommand;
        out syntaxError;
        
        ref IF = HAZ_COMM_004;  // Invalid command accepted
        ref INCF = HAZ_PAYLOAD_005;  // Corrupted payload command
        ref LOF = HAZ_COMM_003;  // Abort command rejected
    }
    
    action def DispatchCommand {
        doc /* Route command to appropriate subsystem */
        in command;
        in commandType;
        out payloadCommand;
        out navigationCommand;
        out abortCommand;
        out configCommand;
        
        ref IF = HAZ_PAYLOAD_001;  // Wrong command routed to payload
        ref INCF = HAZ_COMM_004;  // Command corruption during dispatch
        ref LOF = HAZ_COMM_003;  // Abort not dispatched
    }
    
    action def EncryptTelemetry {
        doc /* Encrypt telemetry before transmission */
        in rawTelemetry;
        in encryptionKey;
        out encryptedData;
        out encryptionStatus;
        
        ref INCF = HAZ_SEC_002;  // Weak encryption
        ref LOF = HAZ_DATA_002;  // No encryption
        ref IF = HAZ_SEC_001;  // Key compromise
    }
    
    action def TransmitBackupLink {
        doc /* Backup telemetry transmission via satellite */
        in backupMessage;
        in satelliteConfig;
        out satelliteSignal;
        out transmitStatus;
        
        ref LOF = HAZ_COMM_001;  // Backup link failed
        ref INCF = HAZ_DATA_002;  // Corrupted backup telemetry
    }
    
    action def DetectJamming {
        doc /* Detect RF jamming attacks */
        in signalAnalysis;
        in noiseBaseline;
        out jammingDetected;
        out jammingType;
        
        ref LOF = HAZ_COMM_001;  // Jamming not detected
        ref IF = HAZ_COMM_004;  // False jamming alert
    }
    
    action def LogCommEvents {
        doc /* Log all communication events for audit */
        in commandReceived;
        in telemetrySent;
        out commLog;
        out auditTrail;
        
        ref LOF = HAZ_DATA_001;  // Audit trail lost
        ref INCF = HAZ_DATA_002;  // Corrupted log
    }
}



package EnhancedPayloadActions {
    doc /* Enhanced Payload with geofencing and ROE validation */
    private import ScalarValues::*;
    private import PayloadActions::*;
    private import EnhancedHazards::*;
    private import Hazards::*;

    action def Payload_Action {
        action validate : ValidateInterlocks;
        action validateGeofence : ValidateGeofence;  // NEW
        action loadGeofence : LoadGeofenceDefinition;  // NEW
        action authorize : AuthorizeArming;
        action loadROE : LoadROE;  // NEW
        action arm : ArmPayload;
        action enableActuation : EnableActuation;  // NEW
        action disarm : DisarmPayload;
        action execute : ExecuteActuation;
        action detectTarget : DetectTarget;  // NEW
        action validateTarget : ValidateTarget;  // NEW
        action monitor : MonitorState;
        action verifyActuation : VerifyActuationResult;  // NEW
        action monitorTemperature : MonitorPayloadTemperature;  // NEW
        action logEvents : LogPayloadEvents;  // NEW
        
        // Interlock validation flow
        flow from validate.interlockStatus to authorize.interlockStatus;
        flow from validateGeofence.geofenceStatus to validate.geofenceStatus;
        flow from loadGeofence.geofenceBoundary to validateGeofence.geofenceBoundary;
        
        // Arming sequence
        flow from authorize.armAuthorized to arm.armAuthorized;
        flow from arm.armedStatus to enableActuation.payloadState;
        flow from arm.armedStatus to monitor.currentState;
        
        // Target engagement
        flow from detectTarget.targetConfirmed to validateTarget.detectedTarget;
        flow from loadROE.rulesOfEngagement to validateTarget.rulesOfEngagement;
        flow from validateTarget.validTarget to execute.actuationTrigger;
        flow from enableActuation.actuationEnabled to execute.enableSignal;
        
        // Monitoring and verification
        flow from execute.actuationFeedback to monitor.hardwareStatus;
        flow from execute.actuationStatus to verifyActuation.actuationStatus;
        flow from monitorTemperature.temperatureAlert to validate.systemHealth;
        
        // Logging
        flow from arm.armedStatus to logEvents.armingEvents;
        flow from execute.actuationStatus to logEvents.actuationEvents;
    }
    
    action def ValidateGeofence {
        doc /* Verify position within authorized geographic zone */
        in currentPosition;
        in geofenceBoundary;
        out geofenceStatus;
        out boundaryDistance;
        
        ref IF = HAZ_PAYLOAD_002;  // False inside geofence
        ref LOF = HAZ_PAYLOAD_007;  // No geofence check
        ref INCF = HAZ_GEO_001;  // Wrong geofence boundary
    }
    
    action def LoadGeofenceDefinition {
        doc /* Load geofence definition from secure storage */
        in missionPlan;
        in securityToken;
        out geofenceBoundary;
        out loadStatus;
        
        ref INCF = HAZ_GEO_001;  // Corrupted geofence data
        ref IF = HAZ_CONFIG_001;  // Unauthorized geofence change
        ref LOF = HAZ_PAYLOAD_007;  // Geofence not loaded
    }
    
    action def LoadROE {
        doc /* Load rules of engagement from mission plan */
        in missionPlan;
        in securityToken;
        out rulesOfEngagement;
        out roeLoadStatus;
        
        ref INCF = HAZ_ROE_001;  // Corrupted ROE
        ref IF = HAZ_CONFIG_001;  // Unauthorized ROE change
        ref LOF = HAZ_LEGAL_001;  // No ROE loaded
    }
    
    action def EnableActuation {
        doc /* Enable actuation logic after arming */
        in payloadState;
        in interlockRecheck;
        out actuationEnabled;
        out enableStatus;
        
        ref IF = HAZ_PAYLOAD_001;  // Enabled when not armed
        ref INCF = HAZ_PAYLOAD_012;  // Partial enable
        ref LOF = HAZ_PAYLOAD_013;  // Cannot enable
    }
    
    action def DetectTarget {
        doc /* Detect and classify payload target */
        in imageData;
        in radarData;
        in lidarData;
        out targetConfirmed;
        out targetClassification;
        
        ref IF = HAZ_PAYLOAD_004;  // False target detection
        ref INCF = HAZ_PERC_003;  // Target misclassification
        ref LOF = HAZ_TARGET_001;  // Target not detected
    }
    
    action def ValidateTarget {
        doc /* Validate target against rules of engagement */
        in detectedTarget;
        in rulesOfEngagement;
        in targetClassification;
        out validTarget;
        out roeCompliance;
        
        ref IF = HAZ_TARGET_001;  // Invalid target approved
        ref INCF = HAZ_ROE_001;  // ROE violation
        ref LOF = HAZ_LEGAL_001;  // No ROE validation
    }
    
    action def VerifyActuationResult {
        doc /* Verify actuation executed correctly */
        in actuationStatus;
        in hardwareFeedback;
        out actuationVerified;
        out verificationStatus;
        
        ref IF = HAZ_PAYLOAD_013;  // False successful actuation
        ref INCF = HAZ_PAYLOAD_014;  // Incomplete actuation
        ref LOF = HAZ_PAYLOAD_015;  // No verification
    }
    
    action def MonitorPayloadTemperature {
        doc /* Monitor payload temperature for safety */
        in temperatureSensor;
        in temperatureThreshold;
        out temperatureAlert;
        out thermalStatus;
        
        ref INCF = HAZ_PAYLOAD_015;  // Overheat condition
        ref LOF = HAZ_FIRE_001;  // No temperature monitoring
        ref IF = HAZ_ELEC_001;  // False overheat alarm
    }
    
    action def LogPayloadEvents {
        doc /* Log all payload-related events */
        in armingEvents;
        in actuationEvents;
        in targetEvents;
        out payloadLog;
        out auditTrail;
        
        ref LOF = HAZ_DATA_001;  // Loss of payload evidence
        ref INCF = HAZ_LEGAL_002;  // Corrupted legal documentation
    }
}