package Communication {
    doc /* Communication Subsystem - C2 Link and Data Exchange */
    private import ScalarValues::*;
    private import SI::*;
    private import Quantities::*;
    private import MeasurementReferences::*;
    private import GARC_Model::*;
    private import CommunicationSoftware::*;

    private import Hazards::*;
    private import SafetyGoals::*;
    private import SafetyRequirements::*;
    private import SafetyPerformanceIndicators::*;
    private import FaultModes::*;

    part def CommunicationSubsystem {
        doc /*
        * Secure bidirectional C2 link
        * Mission-critical for remote operations and payload control
        * Cryptographically authenticated command channel
        */
        // Attributes
        attribute frequency : FrequencyValue = 2400000[Hz];
        attribute range : LengthValue = 50[km];
        attribute dataRate : Real = 10; //[Mbit/s];
        attribute latency : TimeValue = 0.100[s];
        attribute linkAvailability : Real = 0.99;  // 99% uptime
        attribute encryptionStandard : String = "AES-256";

        // Hardware components
        part radio : SoftwareDefinedRadio[2];  // Redundant
        part antenna : OmniAntenna[2];
        part cryptoModule : HardwareCryptoModule[1];
        part satelliteModem : SatelliteModem[1];
        part backupAntenna : SatelliteAntenna[1];

        // Software components
        part radioHandler : RadioHandler[2];
        part protocolStack : ProtocolStack[1];
        part cryptoSoftware : CommandValidator[1];
        part responseEncoder : ResponseEncoder[1];
        part transmitterDriver : TransmitterDriver[1];
        part channelMonitor : ChannelMonitor[1];
        part backupLinkHandler : BackupLinkHandler[1];
        part commandSourceSelector : CommandSourceSelector[1];
        part syntaxValidator : SyntaxValidator[1];
        part commandDispatcher : CommandDispatcher[1];
        part telemetryEncryptor : TelemetryEncryptor[1];
        part backupTransmitter : BackupTransmitter[1];
        part jammingDetector : JammingDetector[1];
        part communicationLogger : CommunicationLogger[1];


        // Ports
        port c2DataOut : C2DataPort;
        port telemetryIn : TelemetryPort;
        port rfOut : RFPort;
        port healthStatusOut : CommHealthPort;

        // Internal connections
        connect radio.dataOut to radioHandler.ddsPort.sub;
        connect radioHandler.ddsPort to protocolStack.ddsPort;
        connect protocolStack.ddsPort to cryptoSoftware.ddsPort;
        connect cryptoSoftware.ddsPort to c2DataOut;
        connect channelMonitor.ddsPort to healthStatusOut;
        connect satelliteModem.dataOut to backupLinkHandler.ddsPort.sub;
        connect radioHandler.ddsPort to commandSourceSelector.ddsPort;
        connect backupLinkHandler.ddsPort to commandSourceSelector.ddsPort;
        connect commandSourceSelector.ddsPort to syntaxValidator.ddsPort;
        connect syntaxValidator.ddsPort to commandDispatcher.ddsPort;
        connect telemetryEncryptor.ddsPort to responseEncoder.ddsPort;
        connect responseEncoder.ddsPort to backupTransmitter.ddsPort;
        connect radioHandler.ddsPort to jammingDetector.ddsPort;
        connect cryptoSoftware.ddsPort to communicationLogger.ddsPort;

        perform action communicationAction : CommunicationActions::Communication_Action;

        // Safety requirements
        satisfy requirement SR_COMM_001;  // Maintain abort capability
        satisfy requirement SR_COMM_002;  // Detect comm loss
        satisfy requirement SR_COMM_003;  // Command authentication

        // Fault modes
        ref faultMode1 :>> FaultModes::FM_COMM_001;  // Loss of C2 link
        ref faultMode2 :>> FaultModes::FM_COMM_002;  // TX failure
        ref faultMode3 :>> FaultModes::FM_COMM_003;  // RX failure

        // Hazard exposure
        ref hazard1 :>> Hazards::HAZ_COMM_001;  // Loss of comm during arming
        ref hazard2 :>> Hazards::HAZ_COMM_002;  // Spoofed command accepted
        ref hazard3 :>> Hazards::HAZ_COMM_003;  // Loss of abort authority
        ref hazard4 :>> Hazards::HAZ_COMM_004;
        ref hazard5 :>> Hazards::HAZ_SEC_001;
        ref hazard6 :>> Hazards::HAZ_SEC_002;
        ref hazard7 :>> Hazards::HAZ_DATA_001;
        ref hazard8 :>> Hazards::HAZ_DATA_002;

        // Safety goals contribution
        ref safetyGoal1 :>> SafetyGoals::SG_001;  // Maintain abort capability
        ref safetyGoal2 :>> SafetyGoals::SG_004;  // Secure command authentication
        // Safety Performance Indicators

        ref spi1 :>> SafetyPerformanceIndicators::SPI_COMM_001;  // Link availability
        ref spi2 :>> SafetyPerformanceIndicators::SPI_COMM_002;  // Command latency
        ref spi3 :>> SafetyPerformanceIndicators::SPI_COMM_003;  // Abort response time
    }


    part def SatelliteModem {
    attribute frequency : FrequencyValue = 1600000000[Hz];
    attribute dataRate : Real = 1; // Mbps
    port dataOut : DigitalDataPort;
    }

    part def SatelliteAntenna {
        attribute gain : Real = 12[dB];
        attribute beamwidth : AngularMeasureValue = 30[degree];
    }



    part def SoftwareDefinedRadio {
        attribute txPower : PowerValue = 10[W];
        attribute sensitivity : PowerValue = -110[dB];
        port dataOut : DigitalDataPort;
        port rfIn : RFPort;
    }
    part def OmniAntenna {
        attribute gain : Real = 3[dB];
        attribute vswr : Real = 1.5;
    }
    part def HardwareCryptoModule {
        attribute algorithm : String = "AES-256-GCM";
        attribute keyLength : Integer = 256;
    }
    // Port definitions
    port def C2DataPort {
        out commands : CommandMessage;
        out missionData : MissionDataMessage;
    }
    port def TelemetryPort {
        in systemStatus : StatusMessage;
        in sensorData : SensorMessage;
    }
    port def RFPort {
        inout signal : RFSignal;
    }


    port def CommHealthPort {
        out linkQuality : Real;
        out signalStrength : PowerValue;
        out faultStatus : CommFaultStatusEnum;
    }
    port def DigitalDataPort {
        out data : BitStream;
    }
    // Message definitions
    attribute def CommandMessage {
        attribute messageId : Integer;
        attribute timestamp : TimeUnit;
        attribute commandType : CommandTypeEnum;
        attribute payload : String;
        attribute signature : String;
    }
    attribute def MissionDataMessage {
        attribute waypointList : WaypointArray;
        attribute missionProfile : String;
    }
    attribute def StatusMessage {
        attribute systemHealth : String;
        attribute subsystemStatus : StatusArray;
    }
    attribute def SensorMessage {
        attribute sensorType : String;
        attribute data : String;
    }
    attribute def RFSignal {
        attribute frequency : FrequencyValue;
        attribute power : PowerValue;
        attribute modulation : String;


    }
    attribute def BitStream {
        attribute bits : String;
        attribute bitrate : Real;
    }
    attribute def WaypointArray {
        attribute waypoints : String[1..*];
    }
    attribute def StatusArray {
        attribute subsystems : String[1..*];
    }
    enum def CommandTypeEnum {
        abort;
        arm;
        disarm;
        waypoint;
        missionUpdate;
        healthCheck;
    }
    enum def CommFaultStatusEnum {
        nominal;
        degradedLink;
        jammingDetected;
        linkLost;
        authFailure;
    }
}

// package CommunicationActions {
//     doc /* Actions for Communication Subsystem */
//     private import ScalarValues::*;
//     private import Communication::*;

//     action def Communication_Action {
//         action dataEncoding : EncodeData;
//         action monitorChannel : MonitorChannel;
//         action linkQualityAssessment : AssessLinkQuality;
//         action radioHandler : HandleRadio;
//         action protocolStack : StackProtocol;

//     }

//     action def HandleRadio {
//         // Attributes
//         in rfSignal;
//         out rawData;       // Internal logic would go here
//     }

//     action def StackProtocol {
//         // Attributes
//         in rawData;
//         out decryptedData;       // Internal logic would go here
//     }

//     action def EncodeData {
//         // Attributes
//         in rawData;
//         out encodedData;       // Internal logic would go here
//     }

//     action def MonitorChannel {
//         // Attributes
//         in dataChannel;
//         out channelQuality;  // Internal logic would go here
//     }

//     action def AssessLinkQuality {
//         // Attributes
//         in rfSignal;
//         out linkQuality;  // Internal logic would go here
//     }

//     action def ValidateCommand {
//         // Attributes
//         in decodedMessage;
//         out validatedCommand;  // Internal logic would go here
//     }
// }