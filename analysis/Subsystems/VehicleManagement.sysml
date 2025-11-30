package VehicleManagement {
doc /* Vehicle management subsystem for health monitoring and safe-state control */
private import ScalarValues::*;
private import GARC_Model::*;

part def VehicleManagementSubsystem {
    doc /* Monitors subsystem health and coordinates safe state transitions */
    out healthStatusOut : StatusMessage;
}
}
