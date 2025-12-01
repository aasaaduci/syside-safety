"""
generate_fha_implicit.py - Implicit FTA/FHA Analysis Generator

Uses implicit fault propagation through SysML action definitions with hazard refs
and automatic backward tracing through data flows.

This analyzer:
1. Extracts action definitions with canonical failure modes (LOF/IF/INCF/EF/LF)
2. Extracts hazard references mapped to failure modes
3. Extracts data flow connections between actions
4. Performs backward tracing from each hazard to find all contributing paths
5. Generates complete fault trees with mode propagation
6. Produces FMEA with risk assessment
"""
# %%
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

# ============================================================================
# Failure Mode Enum
# ============================================================================

class FailureMode(Enum):
    """Canonical failure modes per IEEE 1233/IEC 61508"""
    LOF = "Loss of Function"      # Output missing/null
    IF = "Inadvertent Function"   # Executes when shouldn't
    INCF = "Incorrect Function"   # Output wrong value
    EF = "Early Function"         # Too early
    LF = "Late Function"          # Too late

# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class ModeRefPair:
    """Failure mode mapped to hazard reference"""
    mode: str  # LOF, IF, INCF, EF, LF
    hazard_id: str

@dataclass
class ActionPort:
    """Input or output port of an action"""
    name: str
    direction: str  # "in" or "out"
    port_type: Optional[str] = None

@dataclass
class ActionDefinition:
    """SysML action definition with failure mode refs"""
    action_name: str
    doc_string: str
    inputs: List[ActionPort] = field(default_factory=list)
    outputs: List[ActionPort] = field(default_factory=list)
    failure_mode_refs: Dict[str, str] = field(default_factory=dict)  # {"LOF": "HAZ_ID", ...}

@dataclass
class HazardDefinition:
    """Hazard definition from SysML"""
    hazard_id: str
    title: str
    severity: str  # Catastrophic, Critical, Major, Minor
    effects: str
    affected_systems: Optional[str] = None

@dataclass
class DataFlowConnection:
    """Data flow between action ports"""
    flow_name: str
    source_action: str
    source_port: str
    dest_action: str
    dest_port: str

@dataclass
class ModePropagationRule:
    """How failure modes propagate through connections"""
    source_mode: str
    can_propagate_to: List[str]  # Which modes can result

@dataclass
class FaultContributionPath:
    """Path from root cause to hazard through actions"""
    path_id: str
    root_fault_action: str
    root_fault_mode: str
    propagation_chain: List[Tuple[str, str]]  # [(action, mode), ...]
    final_hazard: str
    probability: Optional[float] = None

@dataclass
class FMEARow:
    """FMEA row: System/Function/Failure Mode/Effects/Severity/Risk"""
    system: str
    function: str
    failure_mode: str
    local_effects: str
    end_effects: str
    severity: str
    detection_method: str
    risk_level: str


class SafetyAnalyzer:
    """Performs FTA/FHA using implicit propagation through action definitions."""

    def __init__(self, model_files):
        self.model, self.diagnostics = syside.try_load_model(model_files)
        #print(f"Model loaded successfully")

        # Data structures
        self.actions: Dict[str, ActionDefinition] = {}
        self.hazards: Dict[str, HazardDefinition] = {}
        self.flows: List[DataFlowConnection] = []
        self.fmea_rows: List[FMEARow] = []
        self.fault_trees: Dict[str, Dict] = {}  # hazard_id -> fault tree

        # Mappings
        self.hazard_to_actions: Dict[str, List[Tuple[str, str]]] = defaultdict(list)  # hazard_id -> [(action, mode), ...]
        self.action_to_outputs: Dict[str, List[ActionPort]] = defaultdict(list)
        self.action_to_inputs: Dict[str, List[ActionPort]] = defaultdict(list)

        # Propagation rules (IEEE 1233)
        self.propagation_rules = self._init_propagation_rules()

    def _init_propagation_rules(self) -> Dict[str, List[str]]:
        """Initialize failure mode propagation rules"""
        return {
            "LOF": ["LOF", "IF"],      # Loss can cause inadvertent execution
            "IF": ["IF"],               # Inadvertent propagates as inadvertent
            "INCF": ["INCF", "IF"],    # Incorrect value can cause inadvertent
            "EF": ["EF", "IF"],         # Early execution can cause inadvertent
            "LF": ["LF"],               # Late execution stays late
        }

    # --------------------
    # Extraction Methods
    # --------------------

    def extract_all_data(self) -> None:
        """Main extraction orchestrator"""
        #print("\n" + "="*80)
        #print("PHASE 1: EXTRACT (Actions, Hazards, Flows)")
        #print("="*80)
        
        self.extract_hazards()
        self.extract_actions()
        self.extract_data_flows()
        self.map_hazard_triggers()

    def extract_hazards(self) -> None:
        """Extract all hazard definitions."""
        #print("\nExtracting hazards from model...")
        for req in self.model.elements(syside.RequirementUsage):
            if (req.requirement_definition and req.requirement_definition.name == "Hazard"):
            
                hazard_node = self._parse_hazard(req)
                if hazard_node:
                    self.hazards[hazard_node.hazard_id] = hazard_node
                    #print(f"  Extracted hazard: {hazard_node.hazard_id} - {hazard_node.title}")
        #print(f"Total hazards extracted: {len(self.hazards)}")

    def extract_actions(self) -> None:
        """Extract all action definitions with failure mode refs"""
        #print("\nExtracting actions...")
        for action_def in self.model.elements(syside.ActionDefinition):  
            action = self._parse_action(action_def)
            if action:
                self.actions[action.action_name] = action
                self.action_to_outputs[action.action_name] = action.outputs
                self.action_to_inputs[action.action_name] = action.inputs
                print(f"  ✓ {action.action_name} (refs: {len(action.failure_mode_refs)})")

        #print(f"Total actions extracted: {len(self.actions)}")

    def extract_data_flows(self) -> None:
        """Extract data flow connections using syside Flow elements"""
        print("\nExtracting data flows...")

        for flow in self.model.elements(syside.FlowUsage):

            try: 
                # Get source and target (connector ends)
                source_action = flow.source.name
                source_port = flow.source_output_feature.name
                dest_action = flow.targets.at(0).name
                dest_port = flow.target_input_feature.name

                if not source_port or not dest_port:
                    continue

                

                if source_action and source_port and dest_action and dest_port:
                    connection = DataFlowConnection(
                        flow_name=flow.name or f"f_{len(self.flows)}",
                        source_action=source_action,
                        source_port=source_port,
                        dest_action=dest_action,
                        dest_port=dest_port
                    )
                    self.flows.append(connection)
                    print(f"  ✓ {source_action}.{source_port} → {dest_action}.{dest_port}")
            except Exception as e:
                print(f"  ✗ Error processing flow {flow.name}: {e}")
                continue
        print(f"Total data flows extracted: {len(self.flows)}")

    def map_hazard_triggers(self) -> None:
        """Map which (action, mode) pairs trigger which hazards"""
        #print("\nMapping hazard triggers...")

        for action_name, action in self.actions.items():
            for mode, hazard_id in action.failure_mode_refs.items():
                if hazard_id in self.hazards:
                    self.hazard_to_actions[hazard_id].append((action_name, mode))
                    print(f"  ✓ {action_name}.{mode} triggers {hazard_id}")

    # --------------------
    # Parsing Methods
    # --------------------

    def _parse_hazard(self, req: syside.RequirementUsage) -> Optional[HazardDefinition]:
        """Parse hazard definition from requirement"""
        hazard_id = req.name

        # Extract attributes
        severity = self._extract_attribute(req, "severity") or "Unknown"
        effects = self._extract_attribute(req, "effects") or ""
        systems = self._extract_attribute(req, "affectedSystems") or ""

        # Use doc string as title
        title = ""
        if req.documentation:
            for doc in req.documentation:
                if hasattr(doc, 'body'):
                    title = doc.body[:100]  # First 100 chars

        return HazardDefinition(
            hazard_id=hazard_id,
            title=title or hazard_id,
            severity=severity,
            effects=effects,
            affected_systems=systems
        )
    

    def get_hazard_usage_id(self, ref_usage : syside.ReferenceUsage):
        
        for member in ref_usage.feature_value_expression.members.collect():
            req_usage = member.try_cast(syside.RequirementUsage)
            if req_usage:
                return req_usage.name
        return None




    def _parse_action(self, action_def: syside.ActionDefinition) -> Optional[ActionDefinition]:
        """Parse action definition with ports and refs"""
        action_name = action_def.name

        # Get doc
        doc_str = ""
        if action_def.documentation:
            for doc in action_def.documentation:
                if hasattr(doc, 'body'):
                    doc_str = doc.body

        # Extract ports
        inputs = []
        outputs = []
        for port in action_def.owned_features.collect():
            if port.direction == syside.FeatureDirectionKind.In:
                inputs.append(ActionPort(name=port.name or "port", direction="in"))
            elif port.direction == syside.FeatureDirectionKind.Out:
                outputs.append(ActionPort(name=port.name or "port", direction="out"))

        # Extract failure mode refs (LOF, IF, INCF, EF, LF)
        mode_refs = {}
        for member in action_def.owned_members.collect():
            ref_usage = member.try_cast(syside.ReferenceUsage)
            if ref_usage and ref_usage.name in ["LOF", "IF", "INCF", "EF", "LF"]:
                hazard_id = self.get_hazard_usage_id(ref_usage)
                print(f"    Found ref: {ref_usage.name} -> {hazard_id}")
                if hazard_id:
                    mode_refs[ref_usage.name] = hazard_id
        return ActionDefinition(
            action_name=action_name,
            doc_string=doc_str,
            inputs=inputs,
            outputs=outputs,
            failure_mode_refs=mode_refs
        )

    def _parse_feature_ref(self, feature: syside.Feature) -> Tuple[Optional[str], Optional[str]]:
        """Parse action.port from a feature reference"""
        if not feature:
            return None, None

        # Get the owning action
        owner_type = feature.owning_type
        if owner_type and hasattr(owner_type, 'name'):
            action_name = owner_type.name
            port_name = feature.name
            return action_name, port_name

        return None, None

    def _extract_attribute(self, element: syside.Element, attr_name: str) -> Optional[str]:
        """Extract string attribute value from element"""
        for owned in element.owned_members.collect():
            attr = owned.try_cast(syside.AttributeUsage)
            if not attr or attr.name != attr_name:
                continue

            # Try to extract value
            for child in attr.owned_elements:
                if lit := child.try_cast(syside.LiteralString):
                    return lit.value
                if lit := child.try_cast(syside.LiteralInteger):
                    return str(lit.value)

        return None

    # --------------------
    # Helper Methods
    # --------------------

    def _find_all_requirements(self, element: syside.Element, in_package: Optional[str] = None) -> List[syside.Element]:
        """Find all requirement definitions"""
        results = []
        
        # Check if this is the target package
        if in_package:
            pkg = element.try_cast(syside.Package)
            if pkg and pkg.name == in_package:
                return [e for e in pkg.owned_elements]

        # Recurse
        for child in element.owned_elements:
            results.extend(self._find_all_requirements(child, in_package))

        return results

    def _find_all_actions(self, element: syside.Element, in_package: Optional[str] = None) -> List[syside.Element]:
        """Find all action definitions"""
        results = []

        if in_package:
            pkg = element.try_cast(syside.Package)
            if pkg and pkg.name == in_package:
                return [e for e in pkg.owned_elements]

        for child in element.owned_elements:
            results.extend(self._find_all_actions(child, in_package))

        return results

    def _find_all_flows(self, element: syside.Element) -> List[syside.Element]:
        """Find all flow elements (data flows)"""
        results = []

        # Check if element is a flow
        if element.try_cast(syside.Flow):
            results.append(element)

        # Recurse
        for child in element.owned_elements:
            results.extend(self._find_all_flows(child))

        return results

    # --------------------
    # Analysis Methods
    # --------------------

    def analyze_backward_from_hazard(self, hazard_id: str) -> Dict:
        """Build complete fault tree by tracing backward from hazard"""
        print(f"\nTracing backward from {hazard_id}...")

        hazard = self.hazards.get(hazard_id)
        if not hazard:
            print(f"  ✗ Hazard {hazard_id} not found")
            return {}

        # Find all actions that trigger this hazard
        triggers = self.hazard_to_actions.get(hazard_id, [])
        
        fault_tree = {
            "hazard_id": hazard_id,
            "hazard_title": hazard.title,
            "severity": hazard.severity,
            "triggered_by": triggers,
            "contribution_paths": []
        }

        # For each direct trigger, create a root contribution path
        for action_name, mode in triggers:
            # ✅ FIX: Initialize path with the direct trigger as root cause
            root_path = {
                "root_cause_action": action_name,
                "root_cause_mode": mode,
                "final_hazard": hazard_id,
                "path_chain": [(action_name, mode)],  # Start with direct trigger
                "sub_paths": []
            }
            
            # ✅ FIX: Trace backward from this trigger to find contributing factors
            sub_paths = self._trace_backward(action_name, mode, set())
            root_path["sub_paths"] = sub_paths
            
            # ✅ Log the root cause
            if sub_paths:
                print(f"  ✓ {action_name}.{mode} → {hazard_id} (with {len(sub_paths)} contributing paths)")
            else:
                print(f"  ✓ {action_name}.{mode} → {hazard_id} (direct trigger)")
            
            fault_tree["contribution_paths"].append(root_path)

        return fault_tree

    def _trace_backward(self, action_name: str, mode: str, visited: Set[str]) -> List[Dict]:
        """Recursively trace backward to find what can cause this action.mode"""
        path_id = f"{action_name}.{mode}"
        
        if path_id in visited:
            return []  # Prevent cycles

        visited.add(path_id)


        action = self.actions.get(action_name)
        if not action:
            return []

        paths = []

        # For this action in this mode, what inputs could cause it?
        for input_port in action.inputs:
            # Find what produces this input
            sources = [f for f in self.flows if f.dest_action == action_name and f.dest_port == input_port.name]

            for source_flow in sources:
                source_action = source_flow.source_action
                source_port = source_flow.source_port

                # What modes from source_action can lead to this mode?
                source_action_obj = self.actions.get(source_action)
                if not source_action_obj:
                    continue

                for source_mode, source_hazard in source_action_obj.failure_mode_refs.items():
                    # Can source_mode propagate to cause our mode?
                    if mode in self.propagation_rules.get(source_mode, []):
                        # Recursive trace
                        sub_paths = self._trace_backward(source_action, source_mode, visited.copy())

                        path = {
                            "from_action": source_action,
                            "from_mode": source_mode,
                            "from_hazard": source_hazard,
                            "to_action": action_name,
                            "to_mode": mode,
                            "via_port": input_port.name,
                            "via_flow": source_flow.flow_name,
                            "sub_paths": sub_paths
                        }
                        paths.append(path)
                        #print(f"  ✓ {source_action}.{source_mode} → {action_name}.{mode}")

        return paths

    def generate_fault_trees(self) -> Dict[str, Dict]:
        """Generate fault trees for all hazards"""
        #print("\n" + "="*80)
        #print("PHASE 2: BUILD (Backward Trace All Hazards)")
        #print("="*80)

        for hazard_id in self.hazards.keys():
            
            self.fault_trees[hazard_id] = self.analyze_backward_from_hazard(hazard_id)

        return self.fault_trees

    def generate_fmea(self) -> List[FMEARow]:
        """Generate FMEA from fault trees"""
        #print("\n" + "="*80)
        #print("PHASE 3: GENERATE (FMEA from Fault Trees)")
        #print("="*80)

        fmea_rows = []
        row_num = 1

        for action_name, action in self.actions.items():
            for mode, hazard_id in action.failure_mode_refs.items():
                hazard = self.hazards.get(hazard_id)
                if not hazard:
                    continue

                # Determine severity
                severity = hazard.severity

                # Determine risk level (simple: severity + detection)
                risk_level = "HIGH" if severity in ["Catastrophic", "Critical"] else "MEDIUM"

                row = FMEARow(
                    system="Payload Arming System",
                    function=action_name,
                    failure_mode=mode,
                    local_effects=f"Action {action_name} in {mode} state",
                    end_effects=hazard.effects,
                    severity=severity,
                    detection_method="Model checking",
                    risk_level=risk_level
                )
                fmea_rows.append(row)
                #print(f"  {row_num:3d}. {action_name:<20} {mode:<6} → {hazard_id:<20} {severity:<12} {risk_level}")
                row_num += 1

        self.fmea_rows = fmea_rows
        #print(f"\nTotal FMEA rows: {len(fmea_rows)}")
        return fmea_rows

    # --------------------
    # Export Methods
    # --------------------

    def export_json(self, output_file: str) -> None:
        """Export complete analysis to JSON"""
        #print(f"\nExporting JSON to {output_file}...")

        output = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_actions": len(self.actions),
                "total_hazards": len(self.hazards),
                "total_flows": len(self.flows),
                "total_fmea_rows": len(self.fmea_rows),
            },
            "actions": {
                name: {
                    "doc": action.doc_string,
                    "inputs": [p.name for p in action.inputs],
                    "outputs": [p.name for p in action.outputs],
                    "failure_mode_refs": action.failure_mode_refs,
                }
                for name, action in self.actions.items()
            },
            "hazards": {
                hid: {
                    "title": h.title,
                    "severity": h.severity,
                    "effects": h.effects,
                }
                for hid, h in self.hazards.items()
            },
            "flows": [asdict(f) for f in self.flows],
            "fault_trees": self.fault_trees,
            "fmea": [asdict(r) for r in self.fmea_rows],
        }

        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)

        #print(f"✓ Exported to {output_file}")

    def export_fmea_csv(self, output_file: str) -> None:
        """Export FMEA as CSV"""
        #print(f"\nExporting FMEA CSV to {output_file}...")

        import csv

        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                "Item", "System", "Function", "Failure Mode", "Local Effects",
                "End Effects", "Severity", "Detection Method", "Risk Level"
            ])

            for i, row in enumerate(self.fmea_rows, 1):
                writer.writerow([
                    i, row.system, row.function, row.failure_mode,
                    row.local_effects, row.end_effects, row.severity,
                    row.detection_method, row.risk_level
                ])

        #print(f"✓ Exported {len(self.fmea_rows)} rows to {output_file}")

    def export_text_report(self, output_file: str) -> None:
        """Export detailed text report"""
        #print(f"\nExporting text report to {output_file}...")

        with open(output_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("IMPLICIT FTA ANALYSIS REPORT\n")
            f.write("="*80 + "\n\n")

            # Summary
            f.write("SUMMARY\n")
            f.write("-"*80 + "\n")
            f.write(f"Actions: {len(self.actions)}\n")
            f.write(f"Hazards: {len(self.hazards)}\n")
            f.write(f"Data Flows: {len(self.flows)}\n")
            f.write(f"FMEA Rows: {len(self.fmea_rows)}\n\n")

            # Fault trees
            f.write("FAULT TREES (By Hazard)\n")
            f.write("-"*80 + "\n\n")

            for hazard_id, tree in self.fault_trees.items():
                f.write(f"HAZARD: {hazard_id}\n")
                f.write(f"Title: {tree.get('hazard_title', 'N/A')}\n")
                f.write(f"Severity: {tree.get('severity', 'Unknown')}\n")
                f.write(f"Triggered by:\n")

                for action, mode in tree.get('triggered_by', []):
                    f.write(f"  - {action}.{mode}\n")

                f.write(f"\nContribution Paths: {len(tree.get('contribution_paths', []))}\n")
                self._write_paths(f, tree.get('contribution_paths', []), indent=2)
                f.write("\n\n")

            # FMEA
            f.write("FAILURE MODE AND EFFECTS ANALYSIS\n")
            f.write("-"*80 + "\n\n")

            for i, row in enumerate(self.fmea_rows, 1):
                f.write(f"{i:3d}. {row.function:<20} {row.failure_mode:<8}\n")
                f.write(f"     Effects: {row.end_effects}\n")
                f.write(f"     Severity: {row.severity:<12} Risk: {row.risk_level}\n\n")

        #print(f"✓ Exported to {output_file}")

    def _write_paths(self, f, paths: List[Dict], indent: int = 0) -> None:
        """
        Recursively write fault paths.
        FIXED: Handles both root cause paths and sub-paths with different structures.
        """
        for path in paths:
            indent_str = " " * indent
            
            # ✅ FIX: Check if this is a root cause path (from analyze_backward_from_hazard)
            if "root_cause_action" in path:
                # Root cause path structure
                f.write(f"{indent_str}ROOT CAUSE: {path['root_cause_action']}.{path['root_cause_mode']}\n")
                f.write(f"{indent_str}FINAL HAZARD: {path['final_hazard']}\n")
                
                # Process sub-paths recursively
                if path.get('sub_paths'):
                    f.write(f"{indent_str}Contributing factors:\n")
                    self._write_paths(f, path['sub_paths'], indent + 2)
            
            # ✅ FIX: Handle sub-paths (from _trace_backward)
            elif "from_action" in path:
                # Sub-path structure
                f.write(f"{indent_str}• {path['from_action']}.{path['from_mode']} ")
                f.write(f"→ {path['to_action']}.{path['to_mode']} ")
                f.write(f"(via {path['via_port']})\n")
                
                # Recurse for deeper levels
                if path.get('sub_paths'):
                    self._write_paths(f, path['sub_paths'], indent + 2)
            
            else:
                # Unknown path structure - log warning
                f.write(f"{indent_str}⚠ Unknown path structure: {path.keys()}\n")

# ============================================================================
# Main
# ============================================================================

def main():
    """Main execution"""
    parser = argparse.ArgumentParser(
        description="Implicit FTA/FHA Analysis from SysML v2 model with action refs"
    )
    parser.add_argument(
        "--directory", "-d", default=None,
        help="Directory containing SysML files"
    )
    parser.add_argument(
        "--json", default="implicit_fta_analysis.json",
        help="Output JSON file"
    )
    parser.add_argument(
        "--fmea", default="fmea_analysis.csv",
        help="Output FMEA CSV file"
    )
    parser.add_argument(
        "--report", default="implicit_fta_report.txt",
        help="Output text report"
    )

    args = parser.parse_args()

    # Collect model files
    if args.directory:
        model_dir = pathlib.Path(args.directory)
    else:
        model_dir = CURRENT_DIR

    model_files = syside.collect_files_recursively(model_dir)
    #print(f"Found {len(model_files)} .sysml files\n")

    # Run analysis
    analyzer = SafetyAnalyzer(model_files)
    analyzer.extract_all_data()
    analyzer.generate_fault_trees()
    analyzer.generate_fmea()

    # Export results
    analyzer.export_json(args.json)
    analyzer.export_fmea_csv(args.fmea)
    analyzer.export_text_report(args.report)

    print("\n" + "="*80)
    print("IMPLICIT FTA ANALYSIS COMPLETE!")
    print("="*80)
    print(f"\nOutputs:")
    print(f"  • {args.json}")
    print(f"  • {args.fmea}")
    print(f"  • {args.report}")

# %%
if __name__ == "__main__":
    main()

    # # %%
    # # For interactive testing
    # model_files = syside.collect_files_recursively(CURRENT_DIR = pathlib.Path(__file__).parent)
    # analyzer = SafetyAnalyzer(model_files)
    # analyzer.extract_all_data()


# %%
