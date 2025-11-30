"""
GARC Fault Tree Analysis Generator using SysIDE
Parses SysML v2 model and generates FTA from fault modes and propagation paths.
"""
# %%
from __future__ import annotations

import argparse
import json
import pathlib
import os
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
import sys

import syside

CURRENT_DIR = pathlib.Path(__file__).parent


# %%
@dataclass
class FaultNode:
    """Represents a node in the fault tree."""

    fault_id: str
    component: str
    description: str
    failure_rate: Optional[float] = None
    detection_coverage: Optional[float] = None
    propagates_to: List[str] = field(default_factory=list)
    causes_hazards: List[str] = field(default_factory=list)
    mitigations: str = ""
    gate_type: str = "OR"  # OR/AND gate


@dataclass
class HazardNode:
    """Represents a top-level hazard (top event in FTA)."""

    hazard_id: str
    title: str
    description: str
    severity: str
    effects: str = ""
    causes: str = ""


@dataclass
class PropagationPath:
    """Represents a fault propagation path."""

    path_id: str
    source_fault: str
    source_component: str
    destination_component: str
    propagation_mechanism: str
    can_be_blocked: bool
    blocking_mechanism: str

class SysideJSONEncoder(json.JSONEncoder):
    """JSON encoder that handles Syside objects automatically."""
    
    def default(self, obj: Any) -> Any:
        # Handle QualifiedName
        if hasattr(obj, 'segments'):
            segments = list(obj.segments)
            return '::'.join(segments) if segments else str(obj)
        
        # Handle any other Syside object with __str__
        if hasattr(obj, '__module__') and 'syside' in obj.__module__:
            return str(obj)
        
        # Default behavior
        return super().default(obj)
# %%
class FaultTreeAnalyzer:
    """Main class for extracting and analyzing fault trees from a SysML v2 model."""

    def __init__(self, model_files: List[str]):
        print(f"Loading SysML v2 model files: {model_files}")
        self.model, self.diagnostics = syside.try_load_model(model_files)
        # if self.diagnostics.contains_errors(warnings_as_errors=False):
        #     print("Errors loading model:")
        #     for error in self.diagnostics.errors:
        #         print(f"  ERROR: {error.message}")
        #     sys.exit(1)
        print(f"Model loaded successfully with {len(list(self.model.user_docs))} documents")

        self.faults: Dict[str, FaultNode] = {}
        self.hazards: Dict[str, HazardNode] = {}
        self.propagations: List[PropagationPath] = []
        self.hazard_to_faults: Dict[str, Set[str]] = defaultdict(set)

    # --------------------
    # Extraction utilities
    # --------------------
    def extract_attribute_value(self, element: syside.Element, attr_name: str) -> Optional[str]:
        """
        Extract a scalar attribute value from a requirement instance.
        
        Handles the pattern:
            attribute <name> :>> <name> = "value";
        """
        for owned in element.owned_members.collect():
            attr_usage = owned.try_cast(syside.AttributeUsage)
            if not attr_usage or attr_usage.name != attr_name:
                continue

            # Try to get the value from the redefinition
            # Look for literal values in owned elements
            for owned_child in attr_usage.owned_elements:
                if lit := owned_child.try_cast(syside.LiteralString):
                    return lit.value
                if lit := owned_child.try_cast(syside.LiteralInteger):
                    return str(lit.value)
                if lit := owned_child.try_cast(syside.LiteralRational):
                    return str(lit.value)
                if lit := owned_child.try_cast(syside.LiteralBoolean):
                    return "true" if lit.value else "false"
            
            # Try evaluating expression if present
            try:
                for feature in attr_usage.owned_features.collect():
                    if expr := feature.try_cast(syside.Expression):
                        result, diagnostics = syside.Compiler().evaluate(expr)
                        if not diagnostics.fatal:
                            return str(result)
            except Exception:
                pass

        return None

    def extract_reference_value(self, element: syside.Element, attr_name: str) -> Optional[str]:
        """
        Extract a reference value (::> pattern) from an attribute.
        
        Handles the pattern:
            attribute causesHazards :>> causesHazards ::> HAZ_COMM_001;
        
        Returns the referenced element's name (e.g., "HAZ_COMM_001")
        """
        for owned in element.owned_members.collect():
            attr_usage = owned.try_cast(syside.AttributeUsage)
            if not attr_usage or attr_usage.name != attr_name:
                continue
            
            # Look for reference redefinitions
            for redef in attr_usage.owned_redefinitions.collect():
                if redef.redefined_feature:
                    # Get the qualified name or simple name
                    ref_name = redef.redefined_feature.qualified_name or redef.redefined_feature.name
                    if ref_name:
                        # Extract just the requirement name (e.g., "HAZ_COMM_001" from "Hazards::HAZ_COMM_001")
                        return ref_name.split("::")[-1] if "::" in ref_name else ref_name
            
            # Alternative: look for feature references
            for ref_feature in attr_usage.owned_references.collect():
                if ref_feature.referenced_feature:
                    ref_name = ref_feature.referenced_feature.qualified_name or ref_feature.referenced_feature.name
                    if ref_name:
                        return ref_name.split("::")[-1] if "::" in ref_name else ref_name

        return None

    def find_package_by_name(self, root: syside.Element, package_name: str) -> Optional[syside.Package]:
        """Recursively find a package by name."""
        if pkg := root.try_cast(syside.Package):
            if pkg.name == package_name:
                return pkg
        for owned in root.owned_elements:
            if result := self.find_package_by_name(owned, package_name):
                return result
        return None

    # --------------------
    # Model extraction
    # --------------------
    def extract_fault_modes(self) -> None:
        """Extract all fault mode definitions from the FaultModes package."""
        print("\nExtracting fault modes from model...")
        for doc in self.model.user_docs:
            with doc.lock() as locked:
                doc_label = getattr(locked, "url", "<unknown document>")
                fault_pkg = self.find_package_by_name(locked.root_node, "FaultModes")
                if not fault_pkg:
                    continue
                print(f"Found FaultModes package in {doc_label}")
                for element in fault_pkg.owned_elements:
                    # Look for requirement usage (instances), not definitions
                    req_usage = element.try_cast(syside.RequirementUsage)
                    if req_usage and req_usage.name and req_usage.name.startswith("FM_"):
                        fault_node = self._parse_fault_mode(req_usage)
                        if fault_node:
                            self.faults[fault_node.fault_id] = fault_node
                            print(f"  Extracted fault: {fault_node.fault_id} - {fault_node.description}")
                            for hazard_id in fault_node.causes_hazards:
                                self.hazard_to_faults[hazard_id].add(fault_node.fault_id)
        print(f"Total faults extracted: {len(self.faults)}")

    def _parse_fault_mode(self, req_usage: syside.RequirementUsage) -> Optional[FaultNode]:
        """Parse a single fault mode requirement instance."""
        fault_id = self.extract_attribute_value(req_usage, "faultId")
        if not fault_id:
            return None

        component = self.extract_attribute_value(req_usage, "component") or ""
        description = self.extract_attribute_value(req_usage, "description") or ""

        failure_rate = None
        failure_rate_str = self.extract_attribute_value(req_usage, "failureRate")
        if failure_rate_str:
            try:
                failure_rate = float(failure_rate_str)
            except ValueError:
                pass

        detection_coverage = None
        detection_cov_str = self.extract_attribute_value(req_usage, "detectionCoverage")
        if detection_cov_str:
            try:
                detection_coverage = float(detection_cov_str)
            except ValueError:
                pass

        # Extract reference to hazard (using ::> pattern)
        hazard_ref = self.extract_reference_value(req_usage, "causesHazards")
        causes_hazards = [hazard_ref] if hazard_ref else []

        mitigations = self.extract_attribute_value(req_usage, "mitigations") or ""

        return FaultNode(
            fault_id=fault_id,
            component=component,
            description=description,
            failure_rate=failure_rate,
            detection_coverage=detection_coverage,
            propagates_to=[],  # Populated from propagation paths
            causes_hazards=causes_hazards,
            mitigations=mitigations,
        )

    def extract_hazards(self) -> None:
        """Extract all hazard definitions from the Hazards package."""
        print("\nExtracting hazards from model...")
        for req in self.model.elements(syside.RequirementUsage):
            if hasattr(req,'name'):
                hazard_node = self._parse_hazard(req)
                if hazard_node:
                    print(f"  Extracted hazard: {hazard_node.hazard_id} - {hazard_node.title}")
                print(f"Total hazards extracted: {len(self.hazards)}")
# %%
    def _parse_hazard(self, req_usage: syside.RequirementUsage) -> Optional[HazardNode]:
        """Parse a single hazard requirement instance."""
        hazard_id = self.extract_attribute_value(req_usage, "hazardId")
        if not hazard_id:
            return None
        title = self.extract_attribute_value(req_usage, "title") or ""
        description = self.extract_attribute_value(req_usage, "description") or ""
        severity = self.extract_attribute_value(req_usage, "severity") or "unknown"
        effects = self.extract_attribute_value(req_usage, "effects") or ""
        causes = self.extract_attribute_value(req_usage, "causes") or ""

        return HazardNode(
            hazard_id=hazard_id,
            title=title,
            description=description,
            severity=severity,
            effects=effects,
            causes=causes,
        )
# %%
    def extract_propagation_paths(self) -> None:
        """Extract fault propagation paths from the FaultPropagation package."""
        print("\nExtracting fault propagation paths...")
        for doc in self.model.user_docs:
            with doc.lock() as locked:
                doc_label = getattr(locked, "url", "<unknown document>")
                prop_pkg = self.find_package_by_name(locked.root_node, "FaultPropagation")
                if not prop_pkg:
                    continue
                print(f"Found FaultPropagation package in {doc_label}")
                for element in prop_pkg.owned_elements:
                    # Look for attribute usage (propagation path instances)
                    attr_usage = element.try_cast(syside.AttributeUsage)
                    if attr_usage and attr_usage.name and attr_usage.name.startswith("FP_"):
                        path = self._parse_propagation(attr_usage)
                        if path:
                            self.propagations.append(path)
                            print(f"  Extracted propagation: {path.path_id} ({path.source_fault} -> {path.destination_component})")
        print(f"Total propagation paths extracted: {len(self.propagations)}")

    def _parse_propagation(self, attr_usage: syside.AttributeUsage) -> Optional[PropagationPath]:
        path_id = self.extract_attribute_value(attr_usage, "pathId")
        source_fault = self.extract_attribute_value(attr_usage, "sourceFault")
        source_component = self.extract_attribute_value(attr_usage, "sourceComponent") or ""
        destination_component = self.extract_attribute_value(attr_usage, "destinationComponent") or ""
        propagation_mechanism = self.extract_attribute_value(attr_usage, "propagationMechanism") or ""
        can_be_blocked_str = self.extract_attribute_value(attr_usage, "canBeBlocked") or "false"
        blocking_mechanism = self.extract_attribute_value(attr_usage, "blockingMechanism") or ""

        if not path_id or not source_fault:
            return None

        can_be_blocked = can_be_blocked_str.lower() in ("true", "1", "yes")
        
        # Convert propagation_mechanism to string if it's a QualifiedName or enum
        if hasattr(propagation_mechanism, '__str__'):
            propagation_mechanism = str(propagation_mechanism)

        return PropagationPath(
            path_id=path_id,
            source_fault=source_fault,
            source_component=source_component,
            destination_component=destination_component,
            propagation_mechanism=propagation_mechanism,
            can_be_blocked=can_be_blocked,
            blocking_mechanism=blocking_mechanism,
        )

    # --------------------
    # Fault tree assembly
    # --------------------
    def _build_fault_tree_node(self, fault_id: str, visited: Set[str]) -> Optional[Dict]:
        if fault_id in visited:
            return None  # avoid cycles
        fault = self.faults.get(fault_id)
        if not fault:
            return None
        visited.add(fault_id)

        node = {
            "fault_id": fault.fault_id,
            "component": fault.component,
            "description": fault.description,
            "failure_rate": fault.failure_rate,
            "detection_coverage": fault.detection_coverage,
            "gate_type": fault.gate_type,
            "mitigations": fault.mitigations,
            "children": [],
        }

        # Find propagation paths that start from this fault
        downstream_components = [
            p.destination_component
            for p in self.propagations
            if p.source_fault == fault_id
        ]

        # Attach child faults whose component matches downstream components
        for comp in downstream_components:
            for child_fault in self.faults.values():
                if child_fault.component == comp:
                    child_node = self._build_fault_tree_node(child_fault.fault_id, visited)
                    if child_node:
                        node["children"].append(child_node)

        visited.remove(fault_id)
        return node

    def generate_fault_tree_for_hazard(self, hazard_id: str) -> Dict:
        hazard = self.hazards.get(hazard_id)
        if not hazard:
            return {}
        root_faults = sorted(self.hazard_to_faults.get(hazard_id, []))
        fault_trees = []
        for fault_id in root_faults:
            tree = self._build_fault_tree_node(fault_id, set())
            if tree:
                fault_trees.append(tree)
        return {
            "hazard_id": hazard.hazard_id,
            "title": hazard.title,
            "description": hazard.description,
            "severity": hazard.severity,
            "effects": hazard.effects,
            "causes": hazard.causes,
            "fault_trees": fault_trees,
        }

    def generate_all_fault_trees(self) -> Dict[str, Dict]:
        return {haz_id: self.generate_fault_tree_for_hazard(haz_id) for haz_id in self.hazards}

    # --------------------
    # Output
    # --------------------

    
    def export_to_json(self, output_file: str) -> None:
        """Export fault trees, faults, and propagations to JSON."""
        fault_trees = self.generate_all_fault_trees()
        output = {
            "model_info": {
                "total_hazards": len(self.hazards),
                "total_faults": len(self.faults),
                "total_propagations": len(self.propagations),
            },
            "fault_trees": fault_trees,
            "fault_catalog": {
                fid: {
                    "fault_id": f.fault_id,
                    "component": f.component,
                    "description": f.description,
                    "failure_rate": f.failure_rate,
                    "detection_coverage": f.detection_coverage,
                    "propagates_to": f.propagates_to,
                    "causes_hazards": f.causes_hazards,
                    "mitigations": f.mitigations,
                }
                for fid, f in self.faults.items()
            },
            "propagation_paths": [
                {
                    "path_id": p.path_id,
                    "source_fault": p.source_fault,
                    "source_component": p.source_component,
                    "destination_component": p.destination_component,
                    "propagation_mechanism": p.propagation_mechanism,
                    "can_be_blocked": p.can_be_blocked,
                    "blocking_mechanism": p.blocking_mechanism,
                }
                for p in self.propagations
            ],
        }
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, cls=SysideJSONEncoder)
        print(f"\nFTA analysis exported to: {output_file}")

    def print_text_report(self, output_file: str) -> None:
        """Generate human-readable text report of FTA."""
        all_trees = self.generate_all_fault_trees()
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("GARC FAULT TREE ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n\n")
            f.write("Model Summary:\n")
            f.write(f"  Total Hazards: {len(self.hazards)}\n")
            f.write(f"  Total Fault Modes: {len(self.faults)}\n")
            f.write(f"  Total Propagation Paths: {len(self.propagations)}\n\n")

            def print_tree(node: Dict, indent: int = 0) -> None:
                prefix = "  " * indent
                f.write(f"{prefix}[{node['gate_type']}] {node['fault_id']}: {node['description']}\n")
                f.write(f"{prefix}     Component: {node['component']}\n")
                if node.get("failure_rate") is not None:
                    f.write(f"{prefix}     Failure Rate: {node['failure_rate']:.2e} /hr\n")
                if node.get("detection_coverage") is not None:
                    f.write(f"{prefix}     Detection Coverage: {node['detection_coverage']:.2f}\n")
                if node.get("mitigations"):
                    f.write(f"{prefix}     Mitigations: {node['mitigations']}\n")
                f.write("\n")
                for child in node.get("children", []):
                    print_tree(child, indent + 1)

            for hazard_id, tree in all_trees.items():
                f.write("-" * 80 + "\n")
                f.write(f"HAZARD: {tree['hazard_id']}\n")
                f.write(f"Title: {tree['title']}\n")
                f.write(f"Severity: {tree['severity']}\n")
                f.write(f"Description: {tree['description']}\n")
                f.write(f"Effects: {tree['effects']}\n")
                f.write(f"Causes: {tree['causes']}\n")
                f.write("\nFault Tree:\n\n")
                for root_fault in tree["fault_trees"]:
                    print_tree(root_fault)
                f.write("\n")
        print(f"Text report exported to: {output_file}")


def main() -> None:
    """Main execution function."""
    # parser = argparse.ArgumentParser(description="Generate FTA from GARC SysML v2 model")
    # parser.add_argument(
    #     "model_files",
    #     nargs="+",
    #     help="SysML v2 model files (.sysml) to analyze",
    # )
    # parser.add_argument(
    #     "--json",
    #     default="garc_fta.json",
    #     help="Output JSON file (default: garc_fta.json)",
    # )
    # parser.add_argument(
    #     "--report",
    #     default="garc_fta_report.txt",
    #     help="Output text report file (default: garc_fta_report.txt)",
    # )
    # args = parser.parse_args()
    CURRENT_DIR = pathlib.Path(__file__).parent
    model_files = syside.collect_files_recursively(CURRENT_DIR)
    model, diagnostics = syside.try_load_model(model_files)

    analyzer = FaultTreeAnalyzer(model_files)
    analyzer.extract_hazards()
    analyzer.extract_fault_modes()
    analyzer.extract_propagation_paths()

    analyzer.export_to_json("output.json")
    analyzer.print_text_report("report.txt")

    print("\n" + "=" * 80)
    print("FTA Generation Complete!")
    print("=" * 80)


if __name__ == "__main__":
    main()

# %%

# def parse_hazard(req_usage: syside.RequirementUsage) -> Optional[HazardNode]:
#         """Parse a single hazard requirement instance."""
#         hazard_id = test_extract_attribute_value(req_usage, "hazardId")
#         if not hazard_id:
#             return None
#         title = test_extract_attribute_value(req_usage, "title") or ""
#         description = test_extract_attribute_value(req_usage, "description") or ""
#         severity = test_extract_attribute_value(req_usage, "severity") or "unknown"
#         effects = test_extract_attribute_value(req_usage, "effects") or ""
#         causes = test_extract_attribute_value(req_usage, "causes") or ""

#         return HazardNode(
#             hazard_id=hazard_id,
#             title=title,
#             description=description,
#             severity=severity,
#             effects=effects,
#             causes=causes,
#         )
# # %%

# def test_extract_attribute_value(element: syside.Element, attr_name: str) -> Optional[str]:
#         """
#         Extract a scalar attribute value from a requirement instance.
        
#         Handles the pattern:
#             attribute <name> :>> <name> = "value";
#         """
#         for owned in element.owned_members.collect():
#             attr_usage = owned.try_cast(syside.AttributeUsage)
#             if not attr_usage or attr_usage.name != attr_name:
#                 continue

#             # Try to get the value from the redefinition
#             # Look for literal values in owned elements
#             for owned_child in attr_usage.owned_elements:
#                 if lit := owned_child.try_cast(syside.LiteralString):
#                     return lit.value
#                 if lit := owned_child.try_cast(syside.LiteralInteger):
#                     return str(lit.value)
#                 if lit := owned_child.try_cast(syside.LiteralRational):
#                     return str(lit.value)
#                 if lit := owned_child.try_cast(syside.LiteralBoolean):
#                     return "true" if lit.value else "false"
            
#             # Try evaluating expression if present
#             try:
#                 for feature in attr_usage.owned_features.collect():
#                     if expr := feature.try_cast(syside.Expression):
#                         result, diagnostics = syside.Compiler().evaluate(expr)
#                         if not diagnostics.fatal:
#                             return str(result)
#             except Exception:
#                 pass

#         return None

# # %%
# CURRENT_DIR = pathlib.Path(__file__).parent
# model_files = syside.collect_files_recursively(CURRENT_DIR)
# model, diagnostics = syside.try_load_model(model_files)

# for req in model.elements(syside.RequirementUsage):
#     if hasattr(req,'name'):
#         hazard_node = parse_hazard(req)
#         if hazard_node:
#             print(f"  Extracted hazard: {hazard_node.hazard_id} - {hazard_node.title}")

# # %%
