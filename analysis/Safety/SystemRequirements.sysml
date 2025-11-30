package SystemRequirements {
doc /* System-level requirements for GARC */
private import ScalarValues::*;
private import SI::*;

requirement def REQ_SYS_001 {
    doc /* Maintain remote abort capability */
    attribute reqId : String = "REQ-SYS-001";
    attribute text : String = "The system shall maintain a remote abort capability at all times during operations.";
}

requirement def REQ_SYS_002 {
    doc /* Safe state definition */
    attribute reqId : String = "REQ-SYS-002";
    attribute text : String = "The system shall transition to a defined safe state upon critical fault detection.";
}
}
