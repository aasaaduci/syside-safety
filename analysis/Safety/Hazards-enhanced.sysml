package EnhancedHazards {
    doc /* Enhanced hazard catalog with detailed conditions */
    private import Hazards::*;
    // NEW LOCALIZATION HAZARDS
    requirement HAZ_LOC_003 : Hazard {
        doc /* Complete localization failure - no backup */
        attribute hazardId :>> hazardId = "HAZ-LOC-003";
        attribute title :>> title = "Total Localization Failure";
        attribute description :>> description = "All position data sources (GNSS, INS, backup) fail simultaneously";
        attribute severity :>> severity = SeverityEnum::catastrophic;
        attribute phase :>> phase = OperationalPhaseEnum::allPhases;
        attribute effects :>> effects = "No position knowledge, Cannot navigate safely, Mission abort required";
        attribute causes :>> causes = "Multiple sensor failure, Common cause event, Power loss, EMI";
    }
    
    requirement HAZ_LOC_004 : Hazard {
        doc /* Altitude sensor failure */
        attribute hazardId :>> hazardId = "HAZ-LOC-004";
        attribute title :>> title = "Barometric Altitude Sensor Failure";
        attribute description :>> description = "Barometric altimeter provides incorrect or no altitude data";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::navigation;
        attribute effects :>> effects = "Wrong vertical position, Collision with underwater obstacles";
        attribute causes :>> causes = "Sensor malfunction, Calibration error, Environmental conditions";
    }
    
    requirement HAZ_LOC_005 : Hazard {
        doc /* Heading error >10 degrees */
        attribute hazardId :>> hazardId = "HAZ-LOC-005";
        attribute title :>> title = "Excessive Heading Error";
        attribute description :>> description = "Magnetic compass or heading estimate error exceeds 10 degrees";
        attribute severity :>> severity = SeverityEnum::catastrophic;
        attribute phase :>> phase = OperationalPhaseEnum::allPhases;
        attribute effects :>> effects = "Wrong orientation causes collision, Wrong target direction";
        attribute causes :>> causes = "Magnetic interference, Compass failure, Calibration error";
    }
    
    // NEW COMMUNICATION HAZARDS (HAZ_COMM_001 through HAZ_COMM_003 already exist)
    requirement HAZ_COMM_004 : Hazard {
        doc /* Command corruption during transmission */
        attribute hazardId :>> hazardId = "HAZ-COMM-004";
        attribute title :>> title = "Command Message Corruption";
        attribute description :>> description = "Command message corrupted during transmission or processing";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::allPhases;
        attribute effects :>> effects = "Command parameters corrupted, Unintended system behavior";
        attribute causes :>> causes = "Bit errors, Protocol fault, Buffer overflow, Decoding error";
    }
    
    // NEW PAYLOAD HAZARDS
    requirement HAZ_PAYLOAD_005 : Hazard {
        doc /* Invalid arming parameter accepted */
        attribute hazardId :>> hazardId = "HAZ-PAYLOAD-005";
        attribute title :>> title = "Invalid Arming Parameter";
        attribute description :>> description = "Payload arming command contains invalid or out-of-range parameters that are accepted";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Arming with incorrect configuration, Unpredictable payload behavior";
        attribute causes :>> causes = "Command validation failure, Parameter range check bypass, Software fault";
    }
    
    requirement HAZ_PAYLOAD_006 : Hazard {
        doc /* Interlock or authorization bypass */
        attribute hazardId :>> hazardId = "HAZ-PAYLOAD-006";
        attribute title :>> title = "Safety Interlock Bypass";
        attribute description :>> description = "Critical safety interlocks or authorization checks are circumvented";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Safety checks circumvented, Unauthorized arming possible";
        attribute causes :>> causes = "Software exploit, Hardware fault, Authorization logic error";
    }
    
    requirement HAZ_PAYLOAD_007 : Hazard {
        doc /* No geofence validation performed */
        attribute hazardId :>> hazardId = "HAZ-PAYLOAD-007";
        attribute title :>> title = "Missing Geofence Validation";
        attribute description :>> description = "Payload arming sequence completes without performing geographic boundary validation";
        attribute severity :>> severity = SeverityEnum::catastrophic;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Arming without geographic boundary check, ROE violation risk";
        attribute causes :>> causes = "Geofence validation bypass, Software fault, Configuration error";
    }
    
    requirement HAZ_PAYLOAD_008 : Hazard {
        doc /* Authorization timeout during arming */
        attribute hazardId :>> hazardId = "HAZ-PAYLOAD-008";
        attribute title :>> title = "Arming Authorization Timeout";
        attribute description :>> description = "Operator authorization times out during payload arming sequence";
        attribute severity :>> severity = SeverityEnum::marginal;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Arming sequence interrupted, Mission delay";
        attribute causes :>> causes = "Operator delay, Communication latency, Protocol timeout";
    }
    
    requirement HAZ_PAYLOAD_009 : Hazard {
        doc /* Partial arming state inconsistency */
        attribute hazardId :>> hazardId = "HAZ-PAYLOAD-009";
        attribute title :>> title = "Partial Arming State";
        attribute description :>> description = "Payload enters undefined intermediate state between SAFE and ARMED";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Payload in undefined intermediate state, Unpredictable behavior";
        attribute causes :>> causes = "State machine fault, Interrupted transition, Power glitch, Software race condition";
    }
    
    requirement HAZ_PAYLOAD_010 : Hazard {
        doc /* Disarm attempted during actuation */
        attribute hazardId :>> hazardId = "HAZ-PAYLOAD-010";
        attribute title :>> title = "Disarm During Actuation";
        attribute description :>> description = "Disarm command received while payload actuation is in progress";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Unsafe state transition, Payload malfunction, Unpredictable actuation";
        attribute causes :>> causes = "Operator error, Timing fault, Communication race condition";
    }
    
    requirement HAZ_PAYLOAD_011 : Hazard {
        doc /* No state monitoring active */
        attribute hazardId :>> hazardId = "HAZ-PAYLOAD-011";
        attribute title :>> title = "Loss of State Monitoring";
        attribute description :>> description = "Payload state monitoring system fails, leaving state changes undetected";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Payload state changes undetected, Loss of safety oversight";
        attribute causes :>> causes = "Monitor software fault, Sensor failure, Communication loss, Power loss";
    }
    
    requirement HAZ_PAYLOAD_012 : Hazard {
        doc /* Partial enable - not fully ready */
        attribute hazardId :>> hazardId = "HAZ-PAYLOAD-012";
        attribute title :>> title = "Partial Actuation Enable";
        attribute description :>> description = "Actuation logic is partially enabled but not fully ready for engagement";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Actuation logic partially enabled, Undefined safety state";
        attribute causes :>> causes = "Enable sequence fault, Interlock inconsistency, Software logic error";
    }
    
    requirement HAZ_PAYLOAD_013 : Hazard {
        doc /* Actuation failure or false success */
        attribute hazardId :>> hazardId = "HAZ-PAYLOAD-013";
        attribute title :>> title = "Actuation Verification Failure";
        attribute description :>> description = "Payload fails to actuate or system falsely reports successful actuation";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Payload does not actuate or false indication, Mission failure";
        attribute causes :>> causes = "Actuator failure, Sensor false positive, Feedback circuit fault";
    }
    
    requirement HAZ_PAYLOAD_014 : Hazard {
        doc /* Incomplete actuation */
        attribute hazardId :>> hazardId = "HAZ-PAYLOAD-014";
        attribute title :>> title = "Incomplete Actuation";
        attribute description :>> description = "Payload actuation sequence begins but does not complete fully";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Payload partially actuates, Unpredictable payload state";
        attribute causes :>> causes = "Power interruption, Mechanical jam, Control signal loss";
    }
    
    requirement HAZ_PAYLOAD_015 : Hazard {
        doc /* Overheat condition or thermal runaway */
        attribute hazardId :>> hazardId = "HAZ-PAYLOAD-015";
        attribute title :>> title = "Payload Overheat Condition";
        attribute description :>> description = "Payload temperature exceeds safe operating limits";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Payload overheating creates fire hazard, Component damage";
        attribute causes :>> causes = "Cooling system failure, Excessive current draw, Environmental conditions";
    }
    
    // NEW TARGET/ROE HAZARDS
    requirement HAZ_TARGET_001 : Hazard {
        doc /* Wrong target identified and engaged */
        attribute hazardId :>> hazardId = "HAZ-TARGET-001";
        attribute title :>> title = "Target Misidentification";
        attribute description :>> description = "Perception system incorrectly identifies target, leading to engagement of wrong entity";
        attribute severity :>> severity = SeverityEnum::catastrophic;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Payload deployed against wrong target, Collateral damage, Mission failure";
        attribute causes :>> causes = "Sensor error, Classification algorithm fault, Environmental conditions";
    }
    
    requirement HAZ_ROE_001 : Hazard {
        doc /* Rules of engagement violated */
        attribute hazardId :>> hazardId = "HAZ-ROE-001";
        attribute title :>> title = "ROE Violation";
        attribute description :>> description = "System executes engagement that violates defined rules of engagement";
        attribute severity :>> severity = SeverityEnum::catastrophic;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Engagement outside authorized parameters, Legal violation, Mission compromise";
        attribute causes :>> causes = "ROE validation failure, Corrupted ROE data, Software logic error";
    }
    
    requirement HAZ_LEGAL_001 : Hazard {
        doc /* Unlawful engagement executed */
        attribute hazardId :>> hazardId = "HAZ-LEGAL-001";
        attribute title :>> title = "Unlawful Engagement";
        attribute description :>> description = "System executes payload actuation that violates international law or authorization";
        attribute severity :>> severity = SeverityEnum::catastrophic;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Legal violations in payload deployment, International incident";
        attribute causes :>> causes = "ROE failure, Authorization bypass, Mission planning error";
    }
    
    requirement HAZ_LEGAL_002 : Hazard {
        doc /* Loss of legal documentation */
        attribute hazardId :>> hazardId = "HAZ-LEGAL-002";
        attribute title :>> title = "Loss of Legal Audit Trail";
        attribute description :>> description = "Critical documentation for legal compliance is lost or corrupted";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Cannot prove legal compliance, Cannot reconstruct decisions";
        attribute causes :>> causes = "Data logging failure, Storage corruption, Audit trail truncation";
    }
    
    // NEW GEOFENCE HAZARDS
    requirement HAZ_GEO_001 : Hazard {
        doc /* Corrupted or wrong geofence loaded */
        attribute hazardId :>> hazardId = "HAZ-GEO-001";
        attribute title :>> title = "Incorrect Geofence Definition";
        attribute description :>> description = "System loads corrupted or incorrect geographic boundary definition";
        attribute severity :>> severity = SeverityEnum::catastrophic;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Operating with incorrect boundaries, Arming in unauthorized location";
        attribute causes :>> causes = "Data corruption, Configuration error, Malicious modification, Storage fault";
    }
    
    // NEW CONFIGURATION HAZARDS
    requirement HAZ_CONFIG_001 : Hazard {
        doc /* Malicious or erroneous configuration change */
        attribute hazardId :>> hazardId = "HAZ-CONFIG-001";
        attribute title :>> title = "Unauthorized Configuration Change";
        attribute description :>> description = "System configuration is changed without proper authorization or validation";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::allPhases;
        attribute effects :>> effects = "System operating with compromised configuration, Security breach";
        attribute causes :>> causes = "Access control bypass, Malicious actor, Software vulnerability, Human error";
    }
    
    // NEW SECURITY HAZARDS
    requirement HAZ_SEC_001 : Hazard {
        doc /* Cryptographic system compromised */
        attribute hazardId :>> hazardId = "HAZ-SEC-001";
        attribute title :>> title = "Cryptographic Compromise";
        attribute description :>> description = "Encryption keys or authentication system is compromised by adversary";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::allPhases;
        attribute effects :>> effects = "Encryption keys or authentication compromised, Spoofed commands possible";
        attribute causes :>> causes = "Key leak, Algorithm weakness, Side-channel attack, Implementation flaw";
    }
    
    requirement HAZ_SEC_002 : Hazard {
        doc /* Weak or failed encryption */
        attribute hazardId :>> hazardId = "HAZ-SEC-002";
        attribute title :>> title = "Encryption Failure";
        attribute description :>> description = "Encryption system fails or uses weak cryptography";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::allPhases;
        attribute effects :>> effects = "Telemetry or commands transmitted in clear, Data interception possible";
        attribute causes :>> causes = "Encryption module failure, Weak algorithm, Key generation fault";
    }
    
    // NEW DATA MANAGEMENT HAZARDS
    requirement HAZ_DATA_001 : Hazard {
        doc /* Loss of critical audit/evidence trail */
        attribute hazardId :>> hazardId = "HAZ-DATA-001";
        attribute title :>> title = "Audit Trail Loss";
        attribute description :>> description = "Critical event logs or forensic data is lost or corrupted";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::allPhases;
        attribute effects :>> effects = "Cannot reconstruct mission events, Loss of accountability";
        attribute causes :>> causes = "Storage failure, Logging fault, Data corruption, Buffer overflow";
    }
    
    requirement HAZ_DATA_002 : Hazard {
        doc /* Telemetry corruption or loss */
        attribute hazardId :>> hazardId = "HAZ-DATA-002";
        attribute title :>> title = "Telemetry Loss or Corruption";
        attribute description :>> description = "Telemetry data is lost or corrupted during transmission or storage";
        attribute severity :>> severity = SeverityEnum::marginal;
        attribute phase :>> phase = OperationalPhaseEnum::allPhases;
        attribute effects :>> effects = "Operators lack situational awareness, Degraded monitoring capability";
        attribute causes :>> causes = "Transmission error, Encoding fault, Storage corruption";
    }
    
    // NEW PERCEPTION HAZARDS
    requirement HAZ_PERC_003 : Hazard {
        doc /* Target misclassification */
        attribute hazardId :>> hazardId = "HAZ-PERC-003";
        attribute title :>> title = "Target Misclassification";
        attribute description :>> description = "Target classification algorithm incorrectly identifies target type";
        attribute severity :>> severity = SeverityEnum::marginal;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Wrong target type identified, Degraded target engagement accuracy";
        attribute causes :>> causes = "Classification algorithm error, Insufficient training data, Environmental conditions";
    }
    
    // NEW ELECTRICAL HAZARDS
    requirement HAZ_ELEC_001 : Hazard {
        doc /* Electrical arming fault or hardware mismatch */
        attribute hazardId :>> hazardId = "HAZ-ELEC-001";
        attribute title :>> title = "Hardware State Mismatch";
        attribute description :>> description = "Physical hardware state differs from software commanded state";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Hardware state differs from software state, Unsafe arming condition";
        attribute causes :>> causes = "Sensor failure, Actuator fault, Wiring error, State feedback failure";
    }
    
    requirement HAZ_ELEC_002 : Hazard {
        doc /* Actuation timing error */
        attribute hazardId :>> hazardId = "HAZ-ELEC-002";
        attribute title :>> title = "Actuation Timing Error";
        attribute description :>> description = "Payload actuator fires at incorrect time relative to command";
        attribute severity :>> severity = SeverityEnum::critical;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Payload actuates at wrong time, Mission effectiveness compromised";
        attribute causes :>> causes = "Timer fault, Clock synchronization error, Signal propagation delay";
    }
    
    // NEW FIRE HAZARD
    requirement HAZ_FIRE_001 : Hazard {
        doc /* Thermal runaway leading to fire */
        attribute hazardId :>> hazardId = "HAZ-FIRE-001";
        attribute title :>> title = "Thermal Runaway Fire";
        attribute description :>> description = "Uncontrolled exothermic reaction leads to fire aboard vessel";
        attribute severity :>> severity = SeverityEnum::catastrophic;
        attribute phase :>> phase = OperationalPhaseEnum::payloadOperations;
        attribute effects :>> effects = "Uncontrolled fire onboard vessel, Loss of vessel, Personnel hazard";
        attribute causes :>> causes = "Battery thermal runaway, Electrical short, Payload overheat, Cooling system failure";
    }
}