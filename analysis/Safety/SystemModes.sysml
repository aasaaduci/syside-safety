package SystemModes {
    doc /* System operational modes for FHA */
    private import GARC_Model::*;
    private import SI::*;
    private import ScalarValues::*;

    // System mode metadata structure
    requirement def SystemMode {
        attribute modeId : String;
        attribute modeName : String;
        attribute description : String;
        attribute entryConditions : String;
        attribute exitConditions : String;
    }

    // Define operational modes
    requirement MODE_001 : SystemMode {
        doc /* Startup and initialization mode */
        attribute modeId :>> modeId = "MODE-001";
        attribute modeName :>> modeName = "Startup & Initialization";
        attribute description :>> description = "System boots, performs self-tests, initializes sensors";
        attribute entryConditions :>> entryConditions = "Power applied, startup command";
        attribute exitConditions :>> exitConditions = "All systems initialized, ready for nominal operation";
    }

    requirement MODE_002 : SystemMode {
        doc /* Navigation and transit mode */
        attribute modeId :>> modeId = "MODE-002";
        attribute modeName :>> modeName = "Navigation & Transit";
        attribute description :>> description = "Vehicle navigates to target waypoint without payload arming";
        attribute entryConditions :>> entryConditions = "Initialization complete, navigation enabled";
        attribute exitConditions :>> exitConditions = "Reached target area or abort commanded";
    }

    requirement MODE_003 : SystemMode {
        doc /* Payload preparation and arming mode */
        attribute modeId :>> modeId = "MODE-003";
        attribute modeName :>> modeName = "Payload Operations";
        attribute description :>> description = "Payload system armed and ready for actuation";
        attribute entryConditions :>> entryConditions = "Correct position, operator authorization";
        attribute exitConditions :>> exitConditions = "Payload actuated or disarmed, exit operation";
    }

    requirement MODE_004 : SystemMode {
        doc /* Autonomous swarm coordination mode */
        attribute modeId :>> modeId = "MODE-004";
        attribute modeName :>> modeName = "Collaborative Operations";
        attribute description :>> description = "Multiple GARC vessels coordinate in swarm formation";
        attribute entryConditions :>> entryConditions = "Multiple vehicles initialized, swarm enabled";
        attribute exitConditions :>> exitConditions = "Mission complete, return to individual navigation";
    }

    requirement MODE_005 : SystemMode {
        doc /* Recovery and return mode */
        attribute modeId :>> modeId = "MODE-005";
        attribute modeName :>> modeName = "Recovery & Return";
        attribute description :>> description = "Vehicle returns to base/recovery point";
        attribute entryConditions :>> entryConditions = "Mission complete or abort commanded";
        attribute exitConditions :>> exitConditions = "At recovery point, safe to recover";
    }
}
