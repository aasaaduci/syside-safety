"""
safety_analyzer_spf.py - Enhanced FTA/FHA Analysis with SPF Detection and Model Update

This analyzer:
1. Extracts action definitions with canonical failure modes (LOF/IF/INCF/EF/LF)
2. Extracts hazard references and severity levels
3. Performs backward tracing to identify Single-Point-Failure (SPF) paths
4. Filters for SPF paths leading to catastrophic or critical hazards
5. Identifies unmitigated failure modes
6. Updates SPI metrics in the SysML v2 model
7. Exports comprehensive FTA/FMEA reports
"""
from __future__ import annotations

import argparse
import json
import pathlib
import os
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Any, Tuple
import sys
from datetime import datetime
from enum import Enum

import syside

CURRENT_DIR = pathlib.Path(__file__).parent

print(sys.platform)
# %%
if sys.platform == 'win32':
    print("Configuring UTF-8 output for Windows console...")
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# ============================================================================
# Enumerations
# ============================================================================

class FailureMode(Enum):
    """Canonical failure modes per IEEE 1233/IEC 61508"""
    LOF = "Loss of Function"      # Output missing/null
    IF = "Inadvertent Function"   # Executes when shouldn't
    INCF = "Incorrect Function"   # Output wrong value
    EF = "Early Function"         # Too early
    LF = "Late Function"          # Too late

class HazardSeverity(Enum):
    """Hazard severity levels"""
    CATASTROPHIC = "catastrophic"
    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"
    MARGINAL = "marginal"

# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class SPFPath:
    """Single-Point-Failure path from root fault to critical hazard"""
    path_id: str
    root_action: str
    root_mode: str
    hazard_id: str
    hazard_title: str
    hazard_severity: str
    propagation_chain: List[Tuple[str, str]]  # [(action, mode), ...]
    is_spf: bool  # True if only single point of failure
    mitigation_req_id: Optional[str] = None  # Safety requirement that mitigates this

@dataclass
class ActionDefinition:
    """SysML action definition with failure mode refs"""
    action_name: str
    doc_string: str
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    failure_mode_refs: Dict[str, str] = field(default_factory=dict)  # {"LOF": "HAZ_ID", ...}

@dataclass
class HazardDefinition:
    """Hazard definition from SysML"""
    hazard_id: str
    title: str
    severity: str  # catastrophic, critical, major, minor
    effects: str
    phase: str = ""

@dataclass
class SPIResult:
    """Result of SPI measurement"""
    spi_id: str
    name: str
    current_value: str
    compliance_status: str
    trend: str
    timestamp: str

# ============================================================================
# Main Analyzer
# ============================================================================

class SPFAnalyzer:
    """Performs FTA/FHA with SPF detection targeting catastrophic/critical hazards"""

    def __init__(self, model_files):
        self.model, self.diagnostics = syside.try_load_model(model_files)
        
        # Data structures
        self.actions: Dict[str, ActionDefinition] = {}
        self.hazards: Dict[str, HazardDefinition] = {}
        self.flows: List[Tuple[str, str, str, str]] = []  # (src_action, src_port, dst_action, dst_port)
        
        # Results
        self.all_spf_paths: List[SPFPath] = []
        self.catastrophic_spf: List[SPFPath] = []
        self.critical_spf: List[SPFPath] = []
        self.unmitigated_modes: Dict[str, List[str]] = {}  # {action: [modes]}
        self.spi_results: Dict[str, SPIResult] = {}
        
        # Mappings
        self.hazard_to_actions: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
        self.action_to_outputs: Dict[str, List[str]] = defaultdict(list)
        self.action_to_inputs: Dict[str, List[str]] = defaultdict(list)
        self.safety_requirements: Dict[str, str] = {}  # {hazard_id: req_id}

    def extract_all_data(self) -> None:
        """Main extraction orchestrator"""
        print("\n" + "="*80)
        print("PHASE 1: EXTRACT (Actions, Hazards, Flows, Requirements)")
        print("="*80)
        
        self.extract_hazards()
        self.extract_actions()
        self.extract_data_flows()
        self.extract_safety_requirements()
        self.map_hazard_triggers()

    def extract_hazards(self) -> None:
        """Extract all hazard definitions with severity"""
        print("\nExtracting hazards...")
        
        for req in self.model.elements(syside.RequirementUsage):
            if req.requirement_definition and req.requirement_definition.name == "Hazard":
                hazard_id = req.name or f"HAZ_{len(self.hazards)}"
                
                # Extract attributes
                severity = self._extract_attribute(req, "severity") or "unknown"
                title = self._extract_attribute(req, "title") or hazard_id
                effects = self._extract_attribute(req, "effects") or ""
                phase = self._extract_attribute(req, "phase") or "allPhases"
                
                hazard = HazardDefinition(
                    hazard_id=hazard_id,
                    title=title,
                    severity=severity.lower(),
                    effects=effects,
                    phase=phase
                )
                
                self.hazards[hazard_id] = hazard
                print(f"  ✓ {hazard_id}: {title} [{severity}]")

    def extract_actions(self) -> None:
        """Extract all action definitions with failure mode refs"""
        print("\nExtracting actions...")
        
        for action_def in self.model.elements(syside.ActionDefinition):
            action_name = action_def.name or f"ACTION_{len(self.actions)}"
            doc_str = ""
            
            if action_def.documentation:
                for doc in action_def.documentation:
                    if hasattr(doc, 'body'):
                        doc_str = doc.body
            
            # Extract ports
            inputs = []
            outputs = []
            
            for port in action_def.owned_features.collect():
                port_name = port.name or "port"
                if port.direction == syside.FeatureDirectionKind.In:
                    inputs.append(port_name)
                elif port.direction == syside.FeatureDirectionKind.Out:
                    outputs.append(port_name)
            
            # Extract failure mode refs (LOF, IF, INCF, EF, LF)
            mode_refs = {}
            for member in action_def.owned_members.collect():
                ref_usage = member.try_cast(syside.ReferenceUsage)
                if ref_usage and ref_usage.name in ["LOF", "IF", "INCF", "EF", "LF"]:
                    hazard_id = self._get_hazard_usage_id(ref_usage)
                    if hazard_id:
                        mode_refs[ref_usage.name] = hazard_id
            
            action = ActionDefinition(
                action_name=action_name,
                doc_string=doc_str,
                inputs=inputs,
                outputs=outputs,
                failure_mode_refs=mode_refs
            )
            
            self.actions[action_name] = action
            self.action_to_outputs[action_name] = outputs
            self.action_to_inputs[action_name] = inputs
            
            if mode_refs:
                print(f"  ✓ {action_name} (modes: {list(mode_refs.keys())})")

    def extract_data_flows(self) -> None:
        """Extract data flow connections"""
        print("\nExtracting data flows...")
        
        for flow in self.model.elements(syside.FlowUsage):
            try:
                src_action = flow.source.name if flow.source else None
                src_port = flow.source_output_feature.name if flow.source_output_feature else None
                
                dst_action = flow.targets.at(0).name if flow.targets and flow.targets.at(0) else None
                dst_port = flow.target_input_feature.name if flow.target_input_feature else None
                
                if src_action and src_port and dst_action and dst_port:
                    self.flows.append((src_action, src_port, dst_action, dst_port))
                    print(f"  ✓ {src_action}.{src_port}  ->  {dst_action}.{dst_port}")
            except Exception as e:
                print(f"  ✗ Error processing flow: {e}")

    def extract_safety_requirements(self) -> None:
        """Extract safety requirements that mitigate hazards"""
        print("\nExtracting safety requirements...")
        
        for req in self.model.elements(syside.RequirementUsage):
            if req.requirement_definition and req.requirement_definition.name == "SafetyRequirementMetadata":
                req_id = req.name or ""
                
                # Try to find mitigated hazards via relationships
                mitigated_hazards = self._extract_mitigated_hazards(req)
                
                for haz_id in mitigated_hazards:
                    self.safety_requirements[haz_id] = req_id
                    print(f"  ✓ {req_id} mitigates {haz_id}")

    def map_hazard_triggers(self) -> None:
        """Map which (action, mode) pairs trigger which hazards"""
        print("\nMapping hazard triggers...")
        
        for action_name, action in self.actions.items():
            for mode, hazard_id in action.failure_mode_refs.items():
                if hazard_id in self.hazards:
                    self.hazard_to_actions[hazard_id].append((action_name, mode))
                    print(f"  ✓ {action_name}.{mode}  ->  {hazard_id}")

    # ========================================================================
    # SPF Detection Methods
    # ========================================================================

    def analyze_spf_paths(self) -> None:
        """Identify all SPF paths leading to catastrophic/critical hazards"""
        print("\n" + "="*80)
        print("PHASE 2: ANALYZE (SPF Detection)")
        print("="*80)
        
        # For each catastrophic/critical hazard, find SPF paths
        critical_hazards = {
            hid: h for hid, h in self.hazards.items()
            if h.severity in ["catastrophic", "critical"]
        }
        
        print(f"\nAnalyzing {len(critical_hazards)} catastrophic/critical hazards for SPF paths...")
        
        for hazard_id, hazard in critical_hazards.items():
            # Get all (action, mode) pairs that trigger this hazard
            triggers = self.hazard_to_actions.get(hazard_id, [])
            
            for action_name, mode in triggers:
                # Trace backward to find contributing paths
                spf_paths = self._find_spf_paths(
                    hazard_id=hazard_id,
                    root_action=action_name,
                    root_mode=mode,
                    hazard=hazard
                )
                
                self.all_spf_paths.extend(spf_paths)
                
                # Categorize by severity
                for path in spf_paths:
                    if path.hazard_severity == "catastrophic":
                        self.catastrophic_spf.append(path)
                    elif path.hazard_severity == "critical":
                        self.critical_spf.append(path)

    def _find_spf_paths(self, hazard_id: str, root_action: str, root_mode: str,
                        hazard: HazardDefinition) -> List[SPFPath]:
        """Find SPF paths from root cause to hazard"""
        paths = []
        
        # Direct trigger (single point of failure if no upstream redundancy)
        path = SPFPath(
            path_id=f"{root_action}.{root_mode} -> {hazard_id}",
            root_action=root_action,
            root_mode=root_mode,
            hazard_id=hazard_id,
            hazard_title=hazard.title,
            hazard_severity=hazard.severity,
            propagation_chain=[(root_action, root_mode)],
            is_spf=True,  # Direct trigger is always SPF
            mitigation_req_id=self.safety_requirements.get(hazard_id)
        )
        paths.append(path)
        
        # Trace backward to find contributing factors
        contributing = self._trace_backward_for_spf(root_action, root_mode, set())
        for contrib_path in contributing:
            path = SPFPath(
                path_id=f"{contrib_path[0][0]}.{contrib_path[0][1]} -> {hazard_id}",
                root_action=contrib_path[0][0],
                root_mode=contrib_path[0][1],
                hazard_id=hazard_id,
                hazard_title=hazard.title,
                hazard_severity=hazard.severity,
                propagation_chain=contrib_path,
                is_spf=len(contrib_path) == 1,  # SPF if only one step
                mitigation_req_id=self.safety_requirements.get(hazard_id)
            )
            paths.append(path)
        
        return paths

    def _trace_backward_for_spf(self, action_name: str, mode: str,
                                visited: Set[str]) -> List[List[Tuple[str, str]]]:
        """Trace backward to find contributing failure paths (minimal SPF chains)"""
        path_id = f"{action_name}.{mode}"
        if path_id in visited:
            return []
        
        visited.add(path_id)
        paths = []
        
        action = self.actions.get(action_name)
        if not action:
            return []
        
        # For each input port, find what produces it
        for input_port in action.inputs:
            # Find flows that feed this input
            sources = [f for f in self.flows 
                      if f[2] == action_name and f[3] == input_port]
            
            if not sources:
                continue  # No upstream source = dead-end SPF
            
            # Only one source = potential SPF
            if len(sources) == 1:
                src_action, src_port, _, _ = sources[0]
                src_action_obj = self.actions.get(src_action)
                
                if not src_action_obj:
                    continue
                
                # What modes from source can cause this mode?
                for src_mode in src_action_obj.failure_mode_refs.keys():
                    # Check if this mode propagates to our required mode
                    if self._can_propagate(src_mode, mode):
                        paths.append([(src_action, src_mode)])
                        
                        # Recursively trace further back
                        sub_paths = self._trace_backward_for_spf(src_action, src_mode, visited.copy())
                        for sub_path in sub_paths:
                            paths.append([(src_action, src_mode)] + sub_path)
        
        return paths

    def _can_propagate(self, from_mode: str, to_mode: str) -> bool:
        """Check if a failure mode can propagate to another"""
        propagation_rules = {
            "LOF": ["LOF", "IF"],
            "IF": ["IF"],
            "INCF": ["INCF", "IF"],
            "EF": ["EF", "IF"],
            "LF": ["LF"]
        }
        return to_mode in propagation_rules.get(from_mode, [])

    def identify_unmitigated_modes(self) -> None:
        """Find failure modes in critical hazard paths without safety requirements"""
        print("\n" + "="*80)
        print("PHASE 3: IDENTIFY (Unmitigated Failure Modes)")
        print("="*80)
        
        for spf_path in self.all_spf_paths:
            if spf_path.hazard_severity not in ["catastrophic", "critical"]:
                continue
            
            # Check if hazard has mitigation requirement
            if not spf_path.mitigation_req_id:
                action = spf_path.root_action
                mode = spf_path.root_mode
                
                if action not in self.unmitigated_modes:
                    self.unmitigated_modes[action] = []
                
                if mode not in self.unmitigated_modes[action]:
                    self.unmitigated_modes[action].append(mode)
                    print(f"  ⚠ UNMITIGATED: {action}.{mode}  ->  {spf_path.hazard_id}")

    # ========================================================================
    # SPI Calculation Methods
    # ========================================================================

    def calculate_spi_metrics(self) -> None:
        """Calculate all SPI metrics"""
        print("\n" + "="*80)
        print("PHASE 4: CALCULATE (SPI Metrics)")
        print("="*80)
        
        timestamp = datetime.now().isoformat()
        
        # SPI-SPF-CRITIC-001: Single-Point-Failure Count (Catastrophic/Critical)
        total_spf = len(self.catastrophic_spf) + len(self.critical_spf)
        self.spi_results["SPI-SPF-CRITIC-001"] = SPIResult(
            spi_id="SPI-SPF-CRITIC-001",
            name="Single-Point-Failure Count (Catastrophic/Critical)",
            current_value=str(total_spf),
            compliance_status="compliant" if total_spf == 0 else "nonCompliant",
            trend="stable",
            timestamp=timestamp
        )
        print(f"  ✓ SPI-SPF-CRITIC-001: {total_spf} SPF paths identified")
        
        # SPI-SPF-CRITIC-002: Unmitigated Critical Action Failure Modes
        unmitigated_count = sum(len(modes) for modes in self.unmitigated_modes.values())
        self.spi_results["SPI-SPF-CRITIC-002"] = SPIResult(
            spi_id="SPI-SPF-CRITIC-002",
            name="Unmitigated Critical Action Failure Modes",
            current_value=str(unmitigated_count),
            compliance_status="compliant" if unmitigated_count == 0 else "nonCompliant",
            trend="stable",
            timestamp=timestamp
        )
        print(f"  ✓ SPI-SPF-CRITIC-002: {unmitigated_count} unmitigated modes")
        
        # SPI-SPF-CRITIC-003: SPF Hazard Requirement Coverage
        spf_hazards = set(p.hazard_id for p in self.all_spf_paths)
        covered_hazards = sum(1 for h in spf_hazards if h in self.safety_requirements)
        coverage = (covered_hazards / len(spf_hazards) * 100) if spf_hazards else 100
        
        self.spi_results["SPI-SPF-CRITIC-003"] = SPIResult(
            spi_id="SPI-SPF-CRITIC-003",
            name="SPF Hazard Requirement Coverage",
            current_value=f"{coverage:.1f}%",
            compliance_status="compliant" if coverage == 100 else "marginal",
            trend="stable",
            timestamp=timestamp
        )
        print(f"  ✓ SPI-SPF-CRITIC-003: {coverage:.1f}% requirement coverage")
        
        # SPI-SPF-CRITIC-004: SPF Hazard Verification Coverage (TBD - requires verification case data)
        self.spi_results["SPI-SPF-CRITIC-004"] = SPIResult(
            spi_id="SPI-SPF-CRITIC-004",
            name="SPF Hazard Verification Coverage",
            current_value="TBD",
            compliance_status="notMeasured",
            trend="unknown",
            timestamp=timestamp
        )
        print(f"  ✓ SPI-SPF-CRITIC-004: Verification coverage (requires VerificationCase data)")

    # ========================================================================
    # Helper Methods
    # ========================================================================

    def _extract_attribute(self, element: syside.Element, attr_name: str) -> Optional[str]:
        """Extract string attribute value from element"""
        for owned in element.owned_members.collect():
            attr = owned.try_cast(syside.AttributeUsage)
            if not attr or attr.name != attr_name:
                continue
            
            for child in attr.owned_elements:
                if lit := child.try_cast(syside.LiteralString):
                    return lit.value
                if lit := child.try_cast(syside.LiteralInteger):
                    return str(lit.value)
                if lit := child.try_cast(syside.FeatureReferenceExpression):
                    return str(lit.referent.name)
        return None

    def _get_hazard_usage_id(self, ref_usage: syside.ReferenceUsage) -> Optional[str]:
        """Extract hazard ID from reference usage"""
        try:
            for member in ref_usage.feature_value_expression.members.collect():
                req_usage = member.try_cast(syside.RequirementUsage)
                if req_usage:
                    return req_usage.name
        except:
            pass
        return None

    def _extract_mitigated_hazards(self, req: syside.RequirementUsage) -> List[str]:
        """Extract hazard IDs mitigated by this requirement"""
        hazards = []
        try:
            for attr in req.owned_members.collect():
                attr_usage = attr.try_cast(syside.AttributeUsage)
                if attr_usage and attr_usage.name == "mitigatesHazards":
                    for member in attr_usage.feature_value_expression.members.collect():
                        haz_usage = member.try_cast(syside.RequirementUsage)
                        if haz_usage:
                            hazards.append(haz_usage.name)
        except:
            pass
        return hazards

    # ========================================================================
    # Model Update Methods
    # ========================================================================

    def update_model_with_spi_results(self, output_dir: str = ".") -> None:
        """Update SysML v2 model with calculated SPI results"""
        print("\n" + "="*80)
        print("PHASE 5: UPDATE (Model with SPI Results)")
        print("="*80)
        
        # Generate SPI update script
        update_script = self._generate_spi_update_script()
        
        script_file = pathlib.Path(output_dir) / "update_spis.sh"
        with open(script_file, 'w') as f:
            f.write(update_script)
        
        print(f"\n  ✓ Generated model update script: {script_file}")
        print(f"    (Manual or automated SysML v2 API integration required)")

    def _generate_spi_update_script(self) -> str:
        """Generate pseudo-code for updating SPIs in model"""
        script = """#!/bin/bash
# SPI Update Script (Pseudo-code)
# This script demonstrates how to update SPI values in the SysML v2 model
# Requires SysML v2 REST API or Python syside API integration

"""
        for spi_id, result in self.spi_results.items():
            script += f"""
# Update {spi_id}: {result.name}
# POST /api/elements/{spi_id}/attributes/currentValue
# Body: {{"value": "{result.current_value}"}}
# POST /api/elements/{spi_id}/attributes/complianceStatus
# Body: {{"value": "{result.compliance_status}"}}
# POST /api/elements/{spi_id}/attributes/trend
# Body: {{"value": "{result.trend}"}}
"""
        
        script += """
# Update analysis metadata
# POST /api/elements/SPF_ANALYSIS_RESULTS/attributes/analysisTimestamp
# Body: {"value": "ISO-8601-TIMESTAMP"}
# POST /api/elements/SPF_ANALYSIS_RESULTS/attributes/analysisStatus
# Body: {"value": "completed"}
# POST /api/elements/SPF_ANALYSIS_RESULTS/attributes/totalSPFPathsFound
# Body: {"value": "COUNT"}
"""
        return script

    # ========================================================================
    # Export Methods
    # ========================================================================

    def export_results(self, output_dir: str = ".") -> None:
        """Export all analysis results"""
        print("\n" + "="*80)
        print("PHASE 6: EXPORT (Results)")
        print("="*80)
        
        output_path = pathlib.Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Export JSON
        self.export_json(str(output_path / "spf_analysis.json"))
        
        # Export CSV FMEA
        self.export_fmea_csv(str(output_path / "spf_fmea.csv"))
        
        # Export text report
        self.export_text_report(str(output_path / "spf_analysis_report.txt"))
        
        # Export SPI results
        self.export_spi_results(str(output_path / "spi_results.json"))

    def export_json(self, output_file: str) -> None:
        """Export complete analysis to JSON"""
        output = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_actions": len(self.actions),
                "total_hazards": len(self.hazards),
                "total_flows": len(self.flows),
                "total_spf_paths": len(self.all_spf_paths),
                "catastrophic_spf": len(self.catastrophic_spf),
                "critical_spf": len(self.critical_spf),
            },
            "spf_paths": [
                {
                    "path_id": p.path_id,
                    "root_action": p.root_action,
                    "root_mode": p.root_mode,
                    "hazard_id": p.hazard_id,
                    "hazard_title": p.hazard_title,
                    "hazard_severity": p.hazard_severity,
                    "is_spf": p.is_spf,
                    "propagation_chain": p.propagation_chain,
                    "mitigation_req": p.mitigation_req_id,
                }
                for p in self.all_spf_paths
            ],
            "unmitigated_modes": self.unmitigated_modes,
            "spi_results": {
                spi_id: asdict(result)
                for spi_id, result in self.spi_results.items()
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"  ✓ Exported JSON: {output_file}")

    def export_fmea_csv(self, output_file: str) -> None:
        """Export SPF hazards as FMEA CSV"""
        import csv
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                "Path ID", "Root Action", "Root Mode", "Hazard ID", "Hazard Title",
                "Severity", "Effects", "Is SPF", "Mitigation Req", "Propagation Chain"
            ])
            
            for path in self.all_spf_paths:
                writer.writerow([
                    path.path_id,
                    path.root_action,
                    path.root_mode,
                    path.hazard_id,
                    path.hazard_title,
                    path.hazard_severity,
                    self.hazards[path.hazard_id].effects,
                    "Yes" if path.is_spf else "No",
                    path.mitigation_req_id or "UNMITIGATED",
                    "  ->  ".join([f"{a}.{m}" for a, m in path.propagation_chain])
                ])
        
        print(f"  ✓ Exported FMEA CSV: {output_file}")

    def export_text_report(self, output_file: str) -> None:
        """Export detailed text report"""
        with open(output_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("SINGLE-POINT-FAILURE ANALYSIS REPORT\n")
            f.write("="*80 + "\n\n")
            
            # Summary
            f.write("SUMMARY\n")
            f.write("-"*80 + "\n")
            f.write(f"Total Actions: {len(self.actions)}\n")
            f.write(f"Total Hazards: {len(self.hazards)}\n")
            f.write(f"Total Data Flows: {len(self.flows)}\n")
            f.write(f"Total SPF Paths: {len(self.all_spf_paths)}\n")
            f.write(f"  - Catastrophic: {len(self.catastrophic_spf)}\n")
            f.write(f"  - Critical: {len(self.critical_spf)}\n")
            f.write(f"Unmitigated Failure Modes: {sum(len(m) for m in self.unmitigated_modes.values())}\n\n")
            
            # SPF Paths by Severity
            f.write("SPF PATHS - CATASTROPHIC\n")
            f.write("-"*80 + "\n")
            for path in self.catastrophic_spf:
                f.write(f"\n{path.path_id}\n")
                f.write(f"  Root Cause: {path.root_action}.{path.root_mode}\n")
                f.write(f"  Hazard: {path.hazard_id} - {path.hazard_title}\n")
                f.write(f"  Effects: {self.hazards[path.hazard_id].effects}\n")
                f.write(f"  Mitigation: {path.mitigation_req_id or 'UNMITIGATED'}\n")
            
            f.write("\nSPF PATHS - CRITICAL\n")
            f.write("-"*80 + "\n")
            for path in self.critical_spf:
                f.write(f"\n{path.path_id}\n")
                f.write(f"  Root Cause: {path.root_action}.{path.root_mode}\n")
                f.write(f"  Hazard: {path.hazard_id} - {path.hazard_title}\n")
                f.write(f"  Effects: {self.hazards[path.hazard_id].effects}\n")
                f.write(f"  Mitigation: {path.mitigation_req_id or 'UNMITIGATED'}\n")
            
            # Unmitigated modes
            if self.unmitigated_modes:
                f.write("\nUNMITIGATED FAILURE MODES\n")
                f.write("-"*80 + "\n")
                for action, modes in self.unmitigated_modes.items():
                    f.write(f"\n{action}:\n")
                    for mode in modes:
                        f.write(f"  - {mode}\n")
            
            # SPI Results
            f.write("\nSPI MEASUREMENT RESULTS\n")
            f.write("-"*80 + "\n")
            for spi_id, result in self.spi_results.items():
                f.write(f"\n{spi_id}: {result.name}\n")
                f.write(f"  Current Value: {result.current_value}\n")
                f.write(f"  Compliance: {result.compliance_status}\n")
                f.write(f"  Timestamp: {result.timestamp}\n")
        
        print(f"  ✓ Exported text report: {output_file}")

    def export_spi_results(self, output_file: str) -> None:
        """Export SPI results as JSON for model update"""
        output = {
            "timestamp": datetime.now().isoformat(),
            "spi_metrics": {
                spi_id: {
                    "spi_id": result.spi_id,
                    "name": result.name,
                    "current_value": result.current_value,
                    "compliance_status": result.compliance_status,
                    "trend": result.trend
                }
                for spi_id, result in self.spi_results.items()
            },
            "analysis_summary": {
                "total_spf_paths": len(self.all_spf_paths),
                "catastrophic_spf": len(self.catastrophic_spf),
                "critical_spf": len(self.critical_spf),
                "unmitigated_count": sum(len(m) for m in self.unmitigated_modes.values())
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"  ✓ Exported SPI results: {output_file}")


# ============================================================================
# Main
# ============================================================================

def main():
    """Main execution"""
    parser = argparse.ArgumentParser(
        description="Single-Point-Failure (SPF) Analysis for Safety-Critical Systems"
    )
    
    parser.add_argument(
        "--directory", "-d", default=None,
        help="Directory containing SysML files"
    )
    
    parser.add_argument(
        "--output", "-o", default="spf_analysis_results",
        help="Output directory for results"
    )
    
    args = parser.parse_args()
    
    # Collect model files
    if args.directory:
        model_dir = pathlib.Path(args.directory)
    else:
        model_dir = CURRENT_DIR
    
    model_files = syside.collect_files_recursively(model_dir)
    
    print(f"Found {len(model_files)} .sysml files")
    
    # Run analysis
    analyzer = SPFAnalyzer(model_files)
    analyzer.extract_all_data()
    analyzer.analyze_spf_paths()
    analyzer.identify_unmitigated_modes()
    analyzer.calculate_spi_metrics()
    analyzer.export_results(args.output)
    analyzer.update_model_with_spi_results(args.output)
    
    print("\n" + "="*80)
    print("SPF ANALYSIS COMPLETE!")
    print("="*80)
    print(f"\nResults saved to: {args.output}/")


if __name__ == "__main__":
    main()
