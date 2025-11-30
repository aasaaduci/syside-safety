// package FaultModes {
// doc /* Fault Mode Definitions and Propagation */
// private import GARC_Model::*;
// private import Hazards::*;
// private import SafetyGoals::*;
// private import ScalarValues::*;
// private import SI::*;
// private import ScalarValues::*;
// private import SI::*;

// // Fault mode metadata structure
// attribute def FaultModeMetadata {
//     attribute faultId : String;
//     attribute component : String;
//     attribute description : String;
//     attribute failureRate : Real;  // Failures per hour
//     attribute detectionCoverage : Real;  // 0.0 to 1.0
//     attribute detectionTime : TimeValue;
//     //attribute propagatesTo : Component[*];
//     attribute causesHazards : Hazard;
//     attribute mitigations : String;
// }

// // Communication subsystem fault modes
// requirement FM_COMM_001 : FaultModeMetadata {
//     doc /* Complete loss of C2 link */
//     attribute faultId :>> faultId = "FM_COMM_001";
//     attribute component :>> component = "CommunicationSubsystem";
//     attribute description :>> description = "Complete loss of bidirectional C2 communication link";
//     attribute failureRate :>> failureRate = 0.00001;  // Per hour
//     attribute detectionCoverage :>> detectionCoverage = 0.99;
//     attribute detectionTime :>> detectionTime = 0.500[s];
//     //attribute propagatesTo :>> propagatesTo ::> CollaborativeAutonomy, "Payload;
//     attribute causesHazards :>> causesHazards ::> HAZ_COMM_001;
//     attribute mitigations :>> mitigations = "Redundant radio channels safe state transition abort autonomy";
// }

// requirement FM_COMM_002 : FaultModeMetadata {
//     doc /* Radio transmitter failure */
//     attribute faultId :>> faultId = "FM_COMM_002";
//     attribute component :>> component = "RadioHandler";
//     attribute description :>> description = "Radio cannot transmit data packets (TX failure)";
//     attribute failureRate :>> failureRate = 5.06;
//     attribute detectionCoverage :>> detectionCoverage = 0.95;
//     attribute detectionTime :>> detectionTime = 1[s];
//     //attribute propagatesTo :>> propagatesTo = Communication::ProtocolStack;
//     attribute causesHazards :>> causesHazards ::> HAZ_COMM_001;
//     attribute mitigations :>> mitigations = "Redundant TX path timeout detection to backup radio";
// }

// requirement FM_COMM_003 : FaultModeMetadata {
//     doc /* Radio receiver failure */
//     attribute faultId :>> faultId = "FM_COMM_003";
//     attribute component :>> component = "RadioHandler";
//     attribute description :>> description = "Radio cannot receive data packets (RX failure)";
//     attribute failureRate :>> failureRate = 5.06;
//     attribute detectionCoverage :>> detectionCoverage = 0.95;
//     attribute detectionTime :>> detectionTime = 2[s];
//     //attribute propagatesTo :>> propagatesTo = Communication::ProtocolStack;
//     attribute causesHazards :>> causesHazards ::> HAZ_COMM_001;
//     attribute mitigations :>> mitigations = "Redundant RX path monitoring to backup radio";
// }

// requirement FM_COMM_004 : FaultModeMetadata {
//     doc /* Data corruption in transmission */
//     attribute faultId :>> faultId = "FM_COMM_004";
//     attribute component :>> component = "ProtocolStack";
//     attribute description :>> description = "Transmitted or received data contains undetected errors";
//     attribute failureRate :>> failureRate = 1.07;
//     attribute detectionCoverage :>> detectionCoverage = 0.9999;  // CRC_32 detection
//     attribute detectionTime :>> detectionTime = 0.100[s];
//     //attribute propagatesTo :>> propagatesTo = Payload;
//     attribute causesHazards :>> causesHazards ::> HAZ_COMM_002;
//     attribute mitigations :>> mitigations = "CRC_32 checksums sequence numbers authentication";
// }

// requirement FM_COMM_005 : FaultModeMetadata {
//     doc /* RF jamming detected */
//     attribute faultId :>> faultId = "FM_COMM_005";
//     attribute component :>> component = "ChannelMonitor";
//     attribute description :>> description = "Adversary jamming signal detected on C2 frequency";
//     attribute failureRate :>> failureRate = 1.04;  // Threat_dependent
//     attribute detectionCoverage :>> detectionCoverage = 0.90;
//     attribute detectionTime :>> detectionTime = 0.500[s];
//     //attribute propagatesTo :>> propagatesTo = VehicleManagement;
//     attribute causesHazards :>> causesHazards ::> HAZ_COMM_001;
//     attribute mitigations :>> mitigations = "Frequency hopping spectrum state transition";
// }

// requirement FM_COMM_006 : FaultModeMetadata {
//     doc /* Authentication failure */
//     attribute faultId :>> faultId = "FM_COMM_006";
//     attribute component :>> component = "CryptoModule";
//     attribute description :>> description = "Received command fails cryptographic authentication";
//     attribute failureRate :>> failureRate = 1.06;  // Excludes deliberate attacks
//     attribute detectionCoverage :>> detectionCoverage = 1.0;
//     attribute detectionTime :>> detectionTime = 0.050[s];
//     //attribute propagatesTo :>> propagatesTo = Payload;
//     attribute causesHazards :>> causesHazards ::> HAZ_COMM_002;
//     attribute mitigations :>> mitigations = "Strong crypto (AES_256) validation replay protection";
// }

// // Localization subsystem fault modes
// requirement FM_LOC_001 : FaultModeMetadata {
//     doc /* Loss of GNSS fix */
//     attribute faultId :>> faultId = "FM_LOC_001";
//     attribute component :>> component = "GNSSReceiver";
//     attribute description :>> description = "Insufficient satellites for position fix";
//     attribute failureRate :>> failureRate = 1.04;
//     attribute detectionCoverage :>> detectionCoverage = 1.0;
//     attribute detectionTime :>> detectionTime = 0.500[s];
//     //attribute propagatesTo :>> propagatesTo = SensorFusionEngine;
//     attribute causesHazards :>> causesHazards ::> HAZ_LOC_001;
//     attribute mitigations :>> mitigations = "INS backup reckoning speed payload operations";
// }

// requirement FM_LOC_002 : FaultModeMetadata {
//     doc /* Degraded position accuracy */
//     attribute faultId :>> faultId = "FM_LOC_002";
//     attribute component :>> component = "SensorFusionEngine";
//     attribute description :>> description = "Position error exceeds 5 m threshold";
//     attribute failureRate :>> failureRate = 5.05;
//     attribute detectionCoverage :>> detectionCoverage = 0.98;
//     attribute detectionTime :>> detectionTime = 1[s];
//     //attribute propagatesTo :>> propagatesTo = MotionControl;
//     attribute causesHazards :>> causesHazards ::> HAZ_LOC_001;
//     attribute mitigations :>> mitigations = "Accuracy monitoring DEGRADED state speed to INS_only navigation";
// }

// requirement FM_LOC_003 : FaultModeMetadata {
//     doc /* GPS spoofing attack */
//     attribute faultId :>> faultId = "FM_LOC_003";
//     attribute component :>> component = "GNSSReceiver";
//     attribute description :>> description = "Adversary successfully injects false GNSS signals";
//     attribute failureRate :>> failureRate = 1.06;  // Threat_dependent
//     attribute detectionCoverage :>> detectionCoverage = 0.95;
//     attribute detectionTime :>> detectionTime = 2[s];
//     //attribute propagatesTo :>> propagatesTo = SensorFusionEngine;
//     attribute causesHazards :>> causesHazards ::> HAZ_LOC_002;
//     attribute mitigations :>> mitigations = "Multi_source cross_validation consistency check detection algorithms";
// }

// requirement FM_LOC_004 : FaultModeMetadata {
//     doc /* IMU drift accumulation */
//     attribute faultId :>> faultId = "FM_LOC_004";
//     attribute component :>> component = "INSProcessor";
//     attribute description :>> description = "Inertial measurement drift exceeds acceptable bounds";
//     attribute failureRate :>> failureRate = 1.05;
//     attribute detectionCoverage :>> detectionCoverage = 0.99;
//     attribute detectionTime :>> detectionTime = 5[s];
//     //attribute propagatesTo :>> propagatesTo = SensorFusionEngine;
//     attribute causesHazards :>> causesHazards ::> HAZ_LOC_001;
//     attribute mitigations :>> mitigations = "Regular GNSS updates updates monitoring";
// }

// // Payload subsystem fault modes
// requirement FM_PAYLOAD_001 : FaultModeMetadata {
//     doc /* Unintended arming transition */
//     attribute faultId :>> faultId = "FM_PAYLOAD_001";
//     attribute component :>> component = "PayloadController";
//     attribute description :>> description = "Payload transitions to ARMED without valid command sequence";
//     attribute failureRate :>> failureRate = 1.07;
//     attribute detectionCoverage :>> detectionCoverage = 0.99;
//     attribute detectionTime :>> detectionTime = 0.100[s];
//     //attribute propagatesTo :>> propagatesTo = VehicleManagement;
//     attribute causesHazards :>> causesHazards ::> HAZ_PAYLOAD_001;
//     attribute mitigations :>> mitigations = "Dual independent interlocks sequence validation monitoring";
// }

// requirement FM_PAYLOAD_002 : FaultModeMetadata {
//     doc /* Disarm command not executed */
//     attribute faultId :>> faultId = "FM_PAYLOAD_002";
//     attribute component :>> component = "PayloadController";
//     attribute description :>> description = "System cannot transition from ARMED to SAFE when commanded";
//     attribute failureRate :>> failureRate = 1.06;
//     attribute detectionCoverage :>> detectionCoverage = 0.99;
//     attribute detectionTime :>> detectionTime = 0.500[s];
//     //attribute propagatesTo :>> propagatesTo = VehicleManagement;
//     attribute causesHazards :>> causesHazards ::> HAZ_PAYLOAD_003;
//     attribute mitigations :>> mitigations = "Dual disarm paths watchdog reset cycle fallback";
// }

// requirement FM_PAYLOAD_003 : FaultModeMetadata {
//     doc /* Safety interlock bypass */
//     attribute faultId :>> faultId = "FM_PAYLOAD_003";
//     attribute component :>> component = "SafetyInterlockLogic";
//     attribute description :>> description = "One or more safety interlocks incorrectly report satisfied conditions";
//     attribute failureRate :>> failureRate = 1.07;
//     attribute detectionCoverage :>> detectionCoverage = 0.99;
//     attribute detectionTime :>> detectionTime = 0.100[s];
//     //attribute propagatesTo :>> propagatesTo = PayloadController;
//     attribute causesHazards :>> causesHazards ::> HAZ_PAYLOAD_001;
//     attribute mitigations :>> mitigations = "Dual redundant interlocks verification diagnostics";
// }

// requirement FM_PAYLOAD_004 : FaultModeMetadata {
//     doc /* Geofence validation failure */
//     attribute faultId :>> faultId = "FM_PAYLOAD_004";
//     attribute component :>> component = "GeofenceValidator";
//     attribute description :>> description = "Geofence check incorrectly reports position inside authorized zone";
//     attribute failureRate :>> failureRate = 1.07;
//     attribute detectionCoverage :>> detectionCoverage = 0.99;
//     attribute detectionTime :>> detectionTime = 0.100[s];
//     //attribute propagatesTo :>> propagatesTo = PayloadController;
//     attribute causesHazards :>> causesHazards ::> HAZ_PAYLOAD_002;
//     attribute mitigations :>> mitigations = "Independent position source boundary margin geofence validation";
// }

// requirement FM_PAYLOAD_005 : FaultModeMetadata {
//     doc /* Watchdog timer failure */
//     attribute faultId :>> faultId = "FM_PAYLOAD_005";
//     attribute component :>> component = "HardwareWatchdog";
//     attribute description :>> description = "Watchdog fails to detect software hang or timeout";
//     attribute failureRate :>> failureRate = 1.06;
//     attribute detectionCoverage :>> detectionCoverage = 0.95;
//     attribute detectionTime :>> detectionTime = 10[s];
//     //attribute propagatesTo :>> propagatesTo = PayloadController;
//     attribute causesHazards :>> causesHazards ::> HAZ_PAYLOAD_003;
//     attribute mitigations :>> mitigations = "Independent watchdog circuit self_test reset path";
// }

// requirement FM_PAYLOAD_006 : FaultModeMetadata {
//     doc /* State monitor mismatch */
//     attribute faultId :>> faultId = "FM_PAYLOAD_006";
//     attribute component :>> component = "IndependentStateMonitor";
//     attribute description :>> description = "Independent monitor detects mismatch between commanded and observed payload state";
//     attribute failureRate :>> failureRate = 1.06;
//     attribute detectionCoverage :>> detectionCoverage = 0.99;
//     attribute detectionTime :>> detectionTime = 0.200[s];
//     //attribute propagatesTo :>> propagatesTo = VehicleManagement;
//     attribute causesHazards :>> causesHazards ::> HAZ_PAYLOAD_001;
//     attribute mitigations :>> mitigations = "Emergency shutdown reconciliation state transition";
// }

// // Perception subsystem fault modes
// requirement FM_PERC_001 : FaultModeMetadata {
//     doc /* Camera sensor failure */
//     attribute faultId :>> faultId = "FM_PERC_001";
//     attribute component :>> component = "CameraDriver";
//     attribute description :>> description = "Camera produces no output or corrupted images";
//     attribute failureRate :>> failureRate = 1.05;
//     attribute detectionCoverage :>> detectionCoverage = 0.95;
//     attribute detectionTime :>> detectionTime = 1[s];
//     //attribute propagatesTo :>> propagatesTo = CVAlgorithm;
//     attribute causesHazards :>> causesHazards ::> HAZ_PERC_001;
//     attribute mitigations :>> mitigations = "Redundant cameras/Radar backup speed monitoring";
// }

// requirement FM_PERC_002 : FaultModeMetadata {
//     doc /* Object detection false negative */
//     attribute faultId :>> faultId = "FM_PERC_002";
//     attribute component :>> component = "CVAlgorithm";
//     attribute description :>> description = "Algorithm fails to detect obstacle in collision path";
//     attribute failureRate :>> failureRate = 1.06;  // Per object encounter
//     attribute detectionCoverage :>> detectionCoverage = 0.90;
//     attribute detectionTime :>> detectionTime = 5[s];
//     //attribute propagatesTo :>> propagatesTo = MotionControl;
//     attribute causesHazards :>> causesHazards ::> HAZ_PERC_001;
//     attribute mitigations :>> mitigations = "Multi_sensor fusion path planning limits under uncertainty";
// }

// requirement FM_PERC_003 : FaultModeMetadata {
//     doc /* Sensor environmental degradation */
//     attribute faultId :>> faultId = "FM_PERC_003";
//     attribute component :>> component = "PerceptionSubsystem";
//     attribute description :>> description = "Rain, fog, or sea spray degrades sensor performance below safety thresholds";
//     attribute failureRate :>> failureRate = 1.03;  // Weather_dependent
//     attribute detectionCoverage :>> detectionCoverage = 0.85;
//     attribute detectionTime :>> detectionTime = 10[s];
//     //attribute propagatesTo :>> propagatesTo = MotionControl;
//     attribute causesHazards :>> causesHazards ::> HAZ_PERC_001;
//     attribute mitigations :>> mitigations = "Weather monitoring speed reduction abort under severe degradation";
// }

// // Motion control fault modes
// requirement FM_MOTION_001 : FaultModeMetadata {
//     doc /* Rudder actuator jam */
//     attribute faultId :>> faultId = "FM_MOTION_001";
//     attribute component :>> component = "ActuatorDriver";
//     attribute description :>> description = "Rudder stuck at fixed angle, cannot execute commanded turn";
//     attribute failureRate :>> failureRate = 1.05;
//     attribute detectionCoverage :>> detectionCoverage = 0.99;
//     attribute detectionTime :>> detectionTime = 0.500[s];
//     //attribute propagatesTo :>> propagatesTo = VehicleManagement;
//     attribute causesHazards :>> causesHazards ::> HAZ_001;
//     attribute mitigations :>> mitigations = "Actuator redundancy vectoring backup stop procedures";
// }

// requirement FM_MOTION_002 : FaultModeMetadata {
//     doc /* Thrust loss */
//     attribute faultId :>> faultId = "FM_MOTION_002";
//     attribute component :>> component = "ActuatorDriver";
//     attribute description :>> description = "Propulsion system fails, no thrust available";
//     attribute failureRate :>> failureRate = 1.05;
//     attribute detectionCoverage :>> detectionCoverage = 1.0;
//     attribute detectionTime :>> detectionTime = 1[s];
//     //attribute propagatesTo :>> propagatesTo = VehicleManagement;
//     attribute causesHazards :>> causesHazards ::> HAZ_001;
//     attribute mitigations :>> mitigations = "Redundant propulsion mode signal";
// }

// // Collaborative autonomy fault modes
// requirement FM_AUTO_001 : FaultModeMetadata {
//     doc /* Unsafe trajectory plan */
//     attribute faultId :>> faultId = "FM_AUTO_001";
//     attribute component :>> component = "SwarmLogic";
//     attribute description :>> description = "Autonomous planner generates trajectory violating safety constraints";
//     attribute failureRate :>> failureRate = 1.06;
//     attribute detectionCoverage :>> detectionCoverage = 0.95;
//     attribute detectionTime :>> detectionTime = 0.500[s];
//     //attribute propagatesTo :>> propagatesTo = MotionControl;
//     attribute causesHazards :>> causesHazards ::> HAZ_AUTO_001;
//     attribute mitigations :>> mitigations = "Safety constraint verification validation oversight";
// }

// requirement FM_AUTO_002 : FaultModeMetadata {
//     doc /* Swarm communication loss */
//     attribute faultId :>> faultId = "FM_AUTO_002";
//     attribute component :>> component = "DataFusion";
//     attribute description :>> description = "Loss of inter_vessel communication in swarm operations";
//     attribute failureRate :>> failureRate = 1.04;
//     attribute detectionCoverage :>> detectionCoverage = 0.99;
//     attribute detectionTime :>> detectionTime = 1[s];
//     //attribute propagatesTo :>> propagatesTo = SwarmLogic;
//     attribute causesHazards :>> causesHazards ::> HAZ_AUTO_002;
//     attribute mitigations :>> mitigations = "Deconfliction maneuvers back to independent ops separation distances";
// }

// // Supporting types
// attribute def ComponentReferenceArray {
//     attribute components : String[0..*];
// }

// attribute def MitigationArray {
//     attribute mitigations : String[1..*];
// }
// }
