package SafetyPerformanceIndicators_Enhanced {
    doc /* Enhanced SPIs including Single-Point-Failure tracking for catastrophic/critical hazards */
    private import GARC_Model::*;
    private import ScalarValues::*;
    private import SI::*;
    private import Hazards::*;
    private import EnhancedHazards::*;
    private import SafetyPerformanceIndicators::*;

    // ============================================================================
    // SPI DEFINITION: Single-Point-Failure to Catastrophic/Critical Hazard Count
    // ============================================================================
    
    requirement SPI_SPF_CRITIC_001 : SPIMetadata {
        doc /* Single-Point-Failure paths to catastrophic or critical hazards */
        attribute spiId :>> spiId = "SPI-SPF-CRITIC-001";
        attribute name :>> name = "Single-Point-Failure Count (Catastrophic/Critical)";
        attribute description :>> description = "Count of identified single-point-failure paths that result in hazards rated catastrophic or critical";
        attribute measuredSubsystem :>> measuredSubsystem = "System";
        attribute targetValue :>> targetValue = "= 0";
        attribute currentValue :>> currentValue = "TBD";
        attribute units :>> units = "count";
        attribute complianceStatus :>> complianceStatus = ComplianceEnum::notMeasured;
        attribute trend :>> trend = TrendEnum::unknown;
        attribute measurementFrequency :>> measurementFrequency = 0.5[Hz];  // Twice daily analysis run
        attribute violationConsequence :>> violationConsequence = "Unmitigated single-point failures to hazardous states pose existential safety risk";
    }

    requirement SPI_SPF_CRITIC_002 : SPIMetadata {
        doc /* Critical path failure modes without redundancy */
        attribute spiId :>> spiId = "SPI-SPF-CRITIC-002";
        attribute name :>> name = "Unmitigated Critical Action Failure Modes";
        attribute description :>> description = "Count of action failure modes (LOF, IF, INCF, EF, LF) with no identified mitigation that propagate to catastrophic/critical hazards";
        attribute measuredSubsystem :>> measuredSubsystem = "System";
        attribute targetValue :>> targetValue = "= 0";
        attribute currentValue :>> currentValue = "TBD";
        attribute units :>> units = "count";
        attribute complianceStatus :>> complianceStatus = ComplianceEnum::notMeasured;
        attribute trend :>> trend = TrendEnum::unknown;
        attribute measurementFrequency :>> measurementFrequency = 0.5[Hz];  // Twice daily analysis run
        attribute violationConsequence :>> violationConsequence = "Unmitigated failure modes leave system susceptible to catastrophic outcomes";
    }

    requirement SPI_SPF_CRITIC_003 : SPIMetadata {
        doc /* SPF hazard coverage by safety requirements */
        attribute spiId :>> spiId = "SPI-SPF-CRITIC-003";
        attribute name :>> name = "SPF Hazard Requirement Coverage";
        attribute description :>> description = "Percentage of identified SPF hazards (catastrophic/critical) with corresponding safety requirements";
        attribute measuredSubsystem :>> measuredSubsystem = "System";
        attribute targetValue :>> targetValue = ">= 100%";
        attribute currentValue :>> currentValue = "TBD";
        attribute units :>> units = "percent";
        attribute complianceStatus :>> complianceStatus = ComplianceEnum::notMeasured;
        attribute trend :>> trend = TrendEnum::unknown;
        attribute measurementFrequency :>> measurementFrequency = 0.5[Hz];  // Twice daily analysis run
        attribute violationConsequence :>> violationConsequence = "Identified hazards without requirements leave mitigation gaps";
    }

    requirement SPI_SPF_CRITIC_004 : SPIMetadata {
        doc /* SPF hazard verification coverage */
        attribute spiId :>> spiId = "SPI-SPF-CRITIC-004";
        attribute name :>> name = "SPF Hazard Verification Coverage";
        attribute description :>> description = "Percentage of SPF-related safety requirements with completed verification cases";
        attribute measuredSubsystem :>> measuredSubsystem = "System";
        attribute targetValue :>> targetValue = ">= 100%";
        attribute currentValue :>> currentValue = "TBD";
        attribute units :>> units = "percent";
        attribute complianceStatus :>> complianceStatus = ComplianceEnum::notMeasured;
        attribute trend :>> trend = TrendEnum::unknown;
        attribute measurementFrequency :>> measurementFrequency = 0.5[Hz];  // Twice daily analysis run
        attribute violationConsequence :>> violationConsequence = "Unverified SPF mitigations cannot be trusted";
    }

    requirement SPI_SPF_CRITIC_005 : SPIMetadata {
        doc /* Mean Time Between Critical Failures (MTBCF) */
        attribute spiId :>> spiId = "SPI-SPF-CRITIC-005";
        attribute name :>> name = "Mean Time Between Critical Failures (Estimated)";
        attribute description :>> description = "Calculated MTBCF based on identified failure rates and SPF propagation paths";
        attribute measuredSubsystem :>> measuredSubsystem = "System";
        attribute targetValue :>> targetValue = "> 10000 hours";
        attribute currentValue :>> currentValue = "TBD";
        attribute units :>> units = "hours";
        attribute complianceStatus :>> complianceStatus = ComplianceEnum::notMeasured;
        attribute trend :>> trend = TrendEnum::unknown;
        attribute measurementFrequency :>> measurementFrequency = 0.5[Hz];  // Twice daily analysis run
        attribute violationConsequence :>> violationConsequence = "Insufficient MTBCF indicates high probability of critical failure during mission";
    }

    // ============================================================================
    // ANALYSIS METADATA: FTA/FHA Analysis Results Storage
    // ============================================================================

    requirement def FTAAnalysisMetadata {
        doc /* Stores results of Fault Tree / Failure Hazard Analysis */
        attribute analysisId : String;
        attribute analysisTimestamp : String;
        attribute modelVersion : String;
        attribute analysisStatus : AnalysisStatusEnum;
        attribute totalHazardsAnalyzed : Integer;
        attribute totalSPFPathsFound : Integer;
        attribute catastrophicSPFCount : Integer;
        attribute criticalSPFCount : Integer;
        attribute uncoveredSPFCount : Integer;
        attribute reportLocation : String;
    }

    requirement SPF_ANALYSIS_RESULTS : FTAAnalysisMetadata {
        doc /* Current FTA/FHA analysis results for SPF to catastrophic/critical hazards */
        attribute analysisId :>> analysisId = "FTA-SPF-ANALYSIS";
        attribute analysisTimestamp :>> analysisTimestamp = "TBD";
        attribute modelVersion :>> modelVersion = "TBD";
        attribute analysisStatus :>> analysisStatus = AnalysisStatusEnum::pending;
        attribute totalHazardsAnalyzed :>> totalHazardsAnalyzed = 0;
        attribute totalSPFPathsFound :>> totalSPFPathsFound = 0;
        attribute catastrophicSPFCount :>> catastrophicSPFCount = 0;
        attribute criticalSPFCount :>> criticalSPFCount = 0;
        attribute uncoveredSPFCount :>> uncoveredSPFCount = 0;
        attribute reportLocation :>> reportLocation = "fta_spf_analysis.json";
    }

    // ============================================================================
    // ENUMERATIONS
    // ============================================================================

    enum def AnalysisStatusEnum {
        pending;        // Analysis not yet run or queued
        in_progress;    // Analysis currently running
        completed;      // Analysis finished successfully
        failed;         // Analysis encountered error
        partial;        // Analysis completed with warnings
    }

}