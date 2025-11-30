package Localization {
doc /* Localization Subsystem - Position and Orientation Estimation */
private import ScalarValues::*;
private import SI::*;
private import Quantities::*;
private import MeasurementReferences::*;
private import GARC_Model::*;
private import LocalizationSoftware::*;
private import Hazards::*;
private import SafetyGoals::*;
private import SafetyRequirements::*;
private import SafetyPerformanceIndicators::*;
private import FaultModes::*;
part def LocalizationSubsystem {
    doc /*
     * Provides position, velocity, and orientation estimates
     * Sensor fusion: GNSS, INS, compass, DVL
     * Safety-critical function for navigation and geofencing
     */
    // Attributes
    attribute positionAccuracy : LengthValue = 2[m];  // CEP 95%
    attribute updateRate : FrequencyValue = 10[Hz];
    attribute integrityLevel : String = "SIL 2";

    // Hardware components
    part gnssReceiver : GNSSReceiver[2];  // Redundant
    part imu : IMU[2];  // Redundant
    part compass : MagneticCompass[1];
    part dvl : DopplerVelocityLog[1];
    part gnssReceiverBackup : GNSSReceiver[1];
    part barometer : Barometer[1];
    part magnetometer : Magnetometer[1];

    // Software components
    part gnssSoftware : GNSSProcessor[2];
    part insProcessor : INSProcessor[1];
    part fusionEngine : SensorFusionEngine[1];
    part healthMonitor : HealthMonitor[1];
    part spoofingDetector : SpoofingDetector[1];
    part gnssBackupProcessor : GNSSBackupProcessor[1];
    part barometerProcessor : BarometerProcessor[1];
    part magnetometerProcessor : MagnetometerProcessor[1];
    part positionQualityValidator : PositionQualityValidator[1];
    part driftCompensator : DriftCompensator[1];
    
    // Ports
    port positionOut : PositionPort;
    port velocityOut : VelocityPort;
    port orientationOut : OrientationPort;
    port healthStatusOut : HealthStatusPort;

    // Internal connections
    connect gnssReceiver.dataOut to gnssSoftware.ddsPort.sub;
    connect gnssSoftware.ddsPort to fusionEngine.ddsPort;
    connect imu.dataOut to insProcessor.ddsPort.sub;
    connect insProcessor.ddsPort to fusionEngine.ddsPort;
    connect fusionEngine.ddsPort to positionOut;
    connect fusionEngine.ddsPort to velocityOut;
    connect fusionEngine.ddsPort to orientationOut;
    connect healthMonitor.ddsPort to healthStatusOut;
    connect gnssReceiverBackup.dataOut to gnssBackupProcessor.ddsPort.sub;
    connect gnssBackupProcessor.ddsPort to fusionEngine.ddsPort;
    connect barometer.dataOut to barometerProcessor.ddsPort.sub;
    connect barometerProcessor.ddsPort to fusionEngine.ddsPort;
    connect magnetometer.dataOut to magnetometerProcessor.ddsPort.sub;
    connect magnetometerProcessor.ddsPort to fusionEngine.ddsPort;
    connect fusionEngine.ddsPort to positionQualityValidator.ddsPort;
    connect insProcessor.ddsPort to driftCompensator.ddsPort;
    connect driftCompensator.ddsPort to fusionEngine.ddsPort;


    // Safety requirements
    satisfy requirement SR_LOC_001;
    satisfy requirement SR_LOC_002;
    satisfy requirement SR_LOC_003;
    // Fault modes
    ref faultMode1 :>> FaultModes::FM_LOC_001;  // Loss of GNSS fix
    ref faultMode2 :>> FaultModes::FM_LOC_002;  // Degraded accuracy
    ref faultMode3 :>> FaultModes::FM_LOC_003;  // GPS spoofing
    ref faultMode4 :>> FaultModes::FM_LOC_004;  // IMU drift
    // Hazard exposure
    ref hazard1 :>> Hazards::HAZ_LOC_001;  // Position error exceeds safety boundary
    ref hazard2 :>> Hazards::HAZ_LOC_002;  // Localization spoof attack
    ref hazard3 :>> Hazards::HAZ_LOC_003;
    ref hazard4 :>> Hazards::HAZ_LOC_004;
    ref hazard5 :>> Hazards::HAZ_LOC_005;


    // Safety goals contribution
    ref safetyGoal :>> SafetyGoals::SG_003;  // Maintain accurate position awareness
    // Safety Performance Indicators
    ref spi1 :>> SafetyPerformanceIndicators::SPI_LOC_001;  // Position accuracy metric
    ref spi2 :>> SafetyPerformanceIndicators::SPI_LOC_002;  // Fix availability
}


// Hardware component definitions
part def GNSSReceiver {
    attribute constellation : String;  // GPS, GLONASS, Galileo
    attribute channels : Integer = 72;
    port dataOut : GNSSDataPort;
}
part def IMU {
    attribute gyroRange : AngularVelocityValue = 500[degree/s];
    attribute accelRange : AccelerationValue = 16[m/s^2];
    attribute updateRate : FrequencyValue = 100[Hz];
    port dataOut : IMUDataPort;
}
part def MagneticCompass {
    attribute accuracy : AngularMeasureValue = 2[degree];
    port headingOut : HeadingPort;
}
part def DopplerVelocityLog {
    attribute maxDepth : LengthValue = 200[m];
    attribute accuracy : SpeedValue = 0.1[m/s];
    port velocityOut : DVLVelocityPort;
}
// Port definitions
port def PositionPort {
    out latitude : AngularMeasureValue;
    out longitude : AngularMeasureValue;
    out altitude : LengthValue;
    out timestamp : TimeUnit;
}
port def VelocityPort {
    out vNorth : SpeedValue;
    out vEast : SpeedValue;
    out vDown : SpeedValue;
}

part def Barometer {
    attribute range : PressureValue = 1100[Pa];
    attribute accuracy : PressureValue = 0.5[Pa];
    port dataOut : BarometerDataPort;
}

part def Magnetometer {
    attribute range : MagneticFluxValue = 8[Wb];
    attribute accuracy : MagneticFluxValue = 0.01[Wb];
    port dataOut : MagnetometerDataPort;
}

// New port definitions
port def BarometerDataPort {
    out pressure : PressureValue;
    out temperature : TemperatureValue;
}

port def MagnetometerDataPort {
    out fieldX : MagneticFluxValue;
    out fieldY : MagneticFluxValue;
    out fieldZ : MagneticFluxValue;
}


port def OrientationPort {
    out roll : AngularMeasureValue;
    out pitch : AngularMeasureValue;
    out yaw : AngularMeasureValue;
}
port def HealthStatusPort {
    out fixQuality : Integer;
    out satelliteCount : Integer;
    out hdop : Real;
    out faultStatus : FaultStatusEnum;
}
port def GNSSDataPort {
    out position : PositionData;
    out velocity : VelocityData;
    out timestamp : TimeUnit;
}
port def IMUDataPort {
    out gyro : AngularVelocityVector;
    out accel : AccelerationVector;
    out timestamp : TimeUnit;
}
port def HeadingPort {
    out heading : AngularMeasureValue;
}
port def DVLVelocityPort {
    out velocity : VelocityVector;
    out bottomLock : Boolean;
}
// Data type definitions
attribute def PositionData {
    attribute lat : AngularMeasureValue;


    attribute lon : AngularMeasureValue;
    attribute alt : LengthValue;
}
attribute def VelocityData {
    attribute vn : SpeedValue;
    attribute ve : SpeedValue;
    attribute vd : SpeedValue;
}
attribute def AngularVelocityVector {
    attribute wx : AngularVelocityValue;
    attribute wy : AngularVelocityValue;
    attribute wz : AngularVelocityValue;
}
attribute def AccelerationVector {
    attribute ax : AccelerationValue;
    attribute ay : AccelerationValue;
    attribute az : AccelerationValue;
}
attribute def VelocityVector {
    attribute vx : SpeedValue;
    attribute vy : SpeedValue;
    attribute vz : SpeedValue;
}
enum def FaultStatusEnum {
    nominal;
    degraded;
    failed;
}
}
