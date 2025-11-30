"""
GARC Visual Diagram Generator
Generates fault tree diagrams, bow-tie diagrams, and safety analysis visualizations.
"""

import graphviz
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass
import colorsys
from safety_analyzer import SafetyAnalyzer
import syside

CURRENT_DIR = Path(__file__).parent

class FaultTreeVisualizer:
    """Generates visual fault tree diagrams using Graphviz."""
    
    def __init__(self, output_dir: str = "diagrams"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Color scheme
        self.colors = {
            "catastrophic": "#DC2626",  # Red
            "critical": "#EA580C",      # Orange
            "marginal": "#EAB308",      # Yellow
            "negligible": "#10B981",    # Green
            "hazard": "#EF4444",        # Light red
            "fault": "#60A5FA",         # Blue
            "component": "#8B5CF6",     # Purple+
            "and_gate": "#F59E0B",      # Amber
            "or_gate": "#3B82F6",       # Blue
            "propagation": "#6B7280",   # Gray
        }
    
    def generate_fault_tree(
        self, 
        hazard_id: str, 
        tree_data: Dict, 
        analyzer: 'EnhancedFaultTreeAnalyzer'
    ) -> str:
        """Generate a fault tree diagram for a specific hazard."""
        
        dot = graphviz.Digraph(
            name=f'FTA_{hazard_id}',
            comment=f'Fault Tree: {hazard_id}',
            engine='dot'
        )
        
        # Graph attributes
        dot.attr(
            rankdir='TB',
            splines='ortho',
            nodesep='0.5',
            ranksep='0.8',
            bgcolor='white'
        )
        
        # Node defaults
        dot.attr('node', 
            shape='box',
            style='rounded,filled',
            fontname='Arial',
            fontsize='10'
        )
        
        # Edge defaults
        dot.attr('edge',
            arrowhead='vee',
            arrowsize='0.8'
        )
        
        # Add hazard (top event)
        hazard = analyzer.hazards.get(hazard_id)
        if hazard:
            severity_color = self.colors.get(hazard.severity.lower(), self.colors['hazard'])
            dot.node(
                hazard_id,
                label=self._format_hazard_label(hazard),
                shape='box',
                style='filled,rounded',
                fillcolor=severity_color,
                fontcolor='white',
                fontsize='12',
                penwidth='2'
            )
        
        # Add fault trees
        for i, fault_tree in enumerate(tree_data.get('fault_trees', [])):
            self._add_fault_subtree(dot, fault_tree, hazard_id, analyzer)
        
        # Save diagram
        output_path = self.output_dir / f"fta_{hazard_id}"
        dot.render(output_path, format='png', cleanup=True)
        print(f"  Generated: {output_path}.png")
        
        return str(output_path) + ".png"
    
    def _format_hazard_label(self, hazard: 'HazardNode') -> str:
        """Format hazard node label."""
        label = f"{hazard.hazard_id}\n"
        label += f"{hazard.title}\n"
        label += f"Severity: {hazard.severity.upper()}"
        return label
    
    def _add_fault_subtree(
        self, 
        dot: graphviz.Digraph, 
        node: Dict, 
        parent_id: str,
        analyzer: 'EnhancedFaultTreeAnalyzer',
        visited: Optional[Set[str]] = None
    ):
        """Recursively add fault nodes to the tree."""
        if visited is None:
            visited = set()
        
        node_id = node['fault_id']
        
        if node_id in visited:
            return
        visited.add(node_id)
        
        # Create fault node
        label = self._format_fault_label(node)
        
        # Color by failure rate
        fillcolor = self._get_failure_rate_color(node.get('failure_rate'))
        
        dot.node(
            node_id,
            label=label,
            fillcolor=fillcolor,
            fontsize='9'
        )
        
        # Connect to parent
        dot.edge(parent_id, node_id)
        
        # Add children
        children = node.get('children', [])
        if children:
            # Add gate node
            gate_id = f"{node_id}_gate"
            gate_type = node.get('gate_type', 'OR')
            gate_label = gate_type
            gate_color = self.colors['or_gate'] if gate_type == 'OR' else self.colors['and_gate']
            
            dot.node(
                gate_id,
                label=gate_label,
                shape='circle',
                fillcolor=gate_color,
                fontcolor='white',
                width='0.5',
                height='0.5',
                fontsize='10',
                style='filled'
            )
            
            dot.edge(node_id, gate_id, style='dashed')
            
            # Add child faults
            for child in children:
                self._add_fault_subtree(dot, child, gate_id, analyzer, visited)
    
    def _format_fault_label(self, node: Dict) -> str:
        """Format fault node label."""
        label = f"{node['fault_id']}\n"
        label += f"{node['component']}\n"
        
        # Wrap description
        desc = node['description']
        if len(desc) > 40:
            words = desc.split()
            lines = []
            current_line = []
            current_length = 0
            for word in words:
                if current_length + len(word) > 35:
                    lines.append(' '.join(current_line))
                    current_line = [word]
                    current_length = len(word)
                else:
                    current_line.append(word)
                    current_length += len(word) + 1
            if current_line:
                lines.append(' '.join(current_line))
            label += '\n'.join(lines[:2])  # Max 2 lines
            if len(lines) > 2:
                label += '...'
        else:
            label += desc
        
        # Add failure rate if present
        if node.get('failure_rate'):
            label += f"\nλ = {node['failure_rate']:.2e}/hr"
        
        return label
    
    def _get_failure_rate_color(self, failure_rate: Optional[float]) -> str:
        """Get color based on failure rate."""
        if failure_rate is None:
            return '#E5E7EB'  # Gray for unknown
        
        # Color scale from green (low) to red (high)
        if failure_rate < 1e-7:
            return '#10B981'  # Green
        elif failure_rate < 1e-6:
            return '#84CC16'  # Lime
        elif failure_rate < 1e-5:
            return '#EAB308'  # Yellow
        elif failure_rate < 1e-4:
            return '#F59E0B'  # Orange
        else:
            return '#EF4444'  # Red
    
    def generate_all_fault_trees(
        self, 
        analyzer: 'EnhancedFaultTreeAnalyzer'
    ) -> List[str]:
        """Generate fault tree diagrams for all hazards."""
        print("\nGenerating fault tree diagrams...")
        
        all_trees = analyzer.generate_all_fault_trees()
        output_files = []
        
        for hazard_id, tree_data in all_trees.items():
            output_file = self.generate_fault_tree(hazard_id, tree_data, analyzer)
            output_files.append(output_file)
        
        print(f"Generated {len(output_files)} fault tree diagrams")
        return output_files


class BowTieVisualizer:
    """Generates bow-tie diagrams showing causes and consequences."""
    
    def __init__(self, output_dir: str = "diagrams"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_bowtie(
        self,
        hazard_id: str,
        analyzer: 'EnhancedFaultTreeAnalyzer'
    ) -> str:
        """Generate a bow-tie diagram for a hazard."""
        
        dot = graphviz.Digraph(
            name=f'BowTie_{hazard_id}',
            comment=f'Bow-Tie Diagram: {hazard_id}',
            engine='dot'
        )
        
        dot.attr(rankdir='LR', splines='ortho')
        dot.attr('node', fontname='Arial', fontsize='9')
        
        hazard = analyzer.hazards.get(hazard_id)
        if not hazard:
            return ""
        
        # Create subgraphs for left (causes) and right (consequences)
        with dot.subgraph(name='cluster_causes') as c:
            c.attr(label='Threat/Causes', style='dashed')
            
            # Get all faults that cause this hazard
            causing_faults = analyzer.hazard_to_faults.get(hazard_id, set())
            
            for fault_id in causing_faults:
                fault = analyzer.faults.get(fault_id)
                if fault:
                    c.node(
                        f"cause_{fault_id}",
                        label=f"{fault_id}\n{fault.component}",
                        shape='box',
                        style='filled',
                        fillcolor='#FCA5A5'
                    )
        
        # Central hazard (critical event)
        dot.node(
            hazard_id,
            label=f"{hazard_id}\n{hazard.title}\n[{hazard.severity.upper()}]",
            shape='diamond',
            style='filled',
            fillcolor='#EF4444',
            fontcolor='white',
            width='2',
            height='1.5',
            fontsize='11'
        )
        
        # Right side - consequences/effects
        with dot.subgraph(name='cluster_consequences') as c:
            c.attr(label='Consequences', style='dashed')
            
            # Parse effects
            effects = hazard.effects.split(';') if hazard.effects else []
            for i, effect in enumerate(effects[:5]):  # Limit to 5
                effect = effect.strip()
                if effect:
                    c.node(
                        f"effect_{i}",
                        label=effect,
                        shape='box',
                        style='filled',
                        fillcolor='#FED7AA'
                    )
        
        # Connect causes to hazard
        for fault_id in causing_faults:
            # Add preventive barriers
            fault = analyzer.faults.get(fault_id)
            if fault and fault.mitigations:
                barrier_id = f"barrier_{fault_id}"
                dot.node(
                    barrier_id,
                    label=f"Prevention:\n{fault.mitigations[:30]}...",
                    shape='rectangle',
                    style='filled',
                    fillcolor='#86EFAC',
                    fontsize='8'
                )
                dot.edge(f"cause_{fault_id}", barrier_id)
                dot.edge(barrier_id, hazard_id, style='bold', color='green')
            else:
                dot.edge(f"cause_{fault_id}", hazard_id, color='red')
        
        # Connect hazard to consequences
        effects = hazard.effects.split(';') if hazard.effects else []
        for i, effect in enumerate(effects[:5]):
            if effect.strip():
                dot.edge(hazard_id, f"effect_{i}")
        
        # Save
        output_path = self.output_dir / f"bowtie_{hazard_id}"
        dot.render(output_path, format='png', cleanup=True)
        print(f"  Generated: {output_path}.png")
        
        return str(output_path) + ".png"
    
    def generate_all_bowties(
        self, 
        analyzer: 'EnhancedFaultTreeAnalyzer'
    ) -> List[str]:
        """Generate bow-tie diagrams for all hazards."""
        print("\nGenerating bow-tie diagrams...")
        
        output_files = []
        for hazard_id in analyzer.hazards.keys():
            output_file = self.generate_bowtie(hazard_id, analyzer)
            if output_file:
                output_files.append(output_file)
        
        print(f"Generated {len(output_files)} bow-tie diagrams")
        return output_files


class PropagationVisualizer:
    """Generates fault propagation network diagrams."""
    
    def __init__(self, output_dir: str = "diagrams"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_propagation_network(
        self,
        analyzer: 'EnhancedFaultTreeAnalyzer',
        filter_component: Optional[str] = None
    ) -> str:
        """Generate complete fault propagation network."""
        
        dot = graphviz.Digraph(
            name='Fault_Propagation_Network',
            comment='Fault Propagation Network',
            engine='dot'
        )
        
        dot.attr(rankdir='LR', splines='spline')
        dot.attr('node', fontname='Arial', fontsize='9')
        dot.attr('edge', fontsize='8')
        
        # Group by component
        components = set()
        for fault in analyzer.faults.values():
            if not filter_component or fault.component == filter_component:
                components.add(fault.component)
        
        # Create subgraphs for each component
        component_clusters = {}
        for i, component in enumerate(sorted(components)):
            with dot.subgraph(name=f'cluster_{i}') as c:
                c.attr(label=component, style='rounded', color='lightgray')
                component_clusters[component] = c
                
                # Add faults in this component
                for fault_id, fault in analyzer.faults.items():
                    if fault.component == component:
                        color = self._get_severity_color(fault, analyzer)
                        c.node(
                            fault_id,
                            label=f"{fault_id}\n{fault.description[:30]}...",
                            shape='box',
                            style='filled,rounded',
                            fillcolor=color
                        )
        
        # Add propagation edges
        for prop in analyzer.propagations:
            if filter_component and prop.source_component != filter_component:
                continue
            
            # Edge label with mechanism and time
            label = prop.propagation_mechanism
            if prop.propagation_time:
                label += f"\n{prop.propagation_time:.2f}s"
            
            # Find destination faults
            dest_faults = analyzer.component_faults.get(prop.destination_component, [])
            for dest_fault_id in dest_faults:
                dot.edge(
                    prop.source_fault,
                    dest_fault_id,
                    label=label,
                    color='red' if not prop.can_be_blocked else 'orange',
                    style='solid' if not prop.can_be_blocked else 'dashed'
                )
        
        # Save
        filename = f"propagation_network_{filter_component}" if filter_component else "propagation_network"
        output_path = self.output_dir / filename
        dot.render(output_path, format='png', cleanup=True)
        print(f"  Generated: {output_path}.png")
        
        return str(output_path) + ".png"
    
    def _get_severity_color(self, fault: 'FaultNode', analyzer: 'EnhancedFaultTreeAnalyzer') -> str:
        """Get color based on caused hazard severity."""
        max_severity = 0
        severity_map = {'negligible': 1, 'marginal': 2, 'critical': 3, 'catastrophic': 4}
        
        for hazard_id in fault.causes_hazards:
            hazard = analyzer.hazards.get(hazard_id)
            if hazard:
                severity = severity_map.get(hazard.severity.lower(), 0)
                max_severity = max(max_severity, severity)
        
        if max_severity == 4:
            return '#FCA5A5'  # Red
        elif max_severity == 3:
            return '#FDBA74'  # Orange
        elif max_severity == 2:
            return '#FDE047'  # Yellow
        else:
            return '#D1FAE5'  # Green


class RiskMatrixVisualizer:
    """Generates risk matrix heatmaps."""
    
    def __init__(self, output_dir: str = "diagrams"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_risk_matrix(
        self,
        scenarios: List['FailureScenario'],
        output_name: str = "risk_matrix"
    ) -> str:
        """Generate risk matrix visualization."""
        
        dot = graphviz.Digraph(
            name='Risk_Matrix',
            comment='Risk Assessment Matrix',
            engine='neato'
        )
        
        dot.attr(
            bgcolor='white',
            size='10,10'
        )
        
        # Define matrix grid
        severity_levels = ['Negligible', 'Marginal', 'Critical', 'Catastrophic']
        probability_levels = ['Remote', 'Occasional', 'Probable', 'Frequent']
        
        # Risk colors
        risk_colors = {
            (0, 0): '#10B981', (0, 1): '#10B981', (0, 2): '#EAB308', (0, 3): '#F59E0B',
            (1, 0): '#10B981', (1, 1): '#EAB308', (1, 2): '#F59E0B', (1, 3): '#EF4444',
            (2, 0): '#EAB308', (2, 1): '#F59E0B', (2, 2): '#EF4444', (2, 3): '#DC2626',
            (3, 0): '#F59E0B', (3, 1): '#EF4444', (3, 2): '#DC2626', (3, 3): '#991B1B',
        }
        
        # Count scenarios in each cell
        matrix_counts = {}
        for scenario in scenarios:
            # Map severity
            sev_idx = {'negligible': 0, 'marginal': 1, 'critical': 2, 'catastrophic': 3}.get(
                scenario.severity.lower(), 0
            )
            
            # Map probability
            if scenario.probability:
                if scenario.probability > 1e-3:
                    prob_idx = 3
                elif scenario.probability > 1e-5:
                    prob_idx = 2
                elif scenario.probability > 1e-7:
                    prob_idx = 1
                else:
                    prob_idx = 0
            else:
                continue
            
            key = (prob_idx, sev_idx)
            matrix_counts[key] = matrix_counts.get(key, 0) + 1
        
        # Create grid nodes
        for i, prob_level in enumerate(probability_levels):
            for j, sev_level in enumerate(severity_levels):
                node_id = f"cell_{i}_{j}"
                count = matrix_counts.get((i, j), 0)
                color = risk_colors.get((i, j), '#FFFFFF')
                
                label = f"{prob_level}\n{sev_level}\n({count})"
                
                # Position
                pos = f"{j*2},{i*2}!"
                
                dot.node(
                    node_id,
                    label=label,
                    shape='box',
                    style='filled',
                    fillcolor=color,
                    fontcolor='white' if count > 0 else 'black',
                    width='1.5',
                    height='1.5',
                    pos=pos,
                    fontsize='10'
                )
        
        # Save
        output_path = self.output_dir / output_name
        dot.render(output_path, format='png', cleanup=True)
        print(f"  Generated: {output_path}.png")
        
        return str(output_path) + ".png"


class ComponentCriticalityVisualizer:
    """Generates component criticality charts."""
    
    def __init__(self, output_dir: str = "diagrams"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_criticality_chart(
        self,
        critical_components: Dict[str, Dict[str, Any]],
        top_n: int = 15
    ) -> str:
        """Generate horizontal bar chart of component criticality."""
        
        dot = graphviz.Digraph(
            name='Component_Criticality',
            comment='Component Criticality Ranking',
            engine='dot'
        )
        
        dot.attr(rankdir='LR', bgcolor='white')
        dot.attr('node', fontname='Arial', fontsize='10', shape='box')
        
        # Get top N components
        top_components = list(critical_components.items())[:top_n]
        
        # Create table-like structure
        with dot.subgraph(name='cluster_chart') as c:
            c.attr(label='Top Critical Components', fontsize='14')
            
            for i, (component, analysis) in enumerate(top_components):
                score = analysis['criticality_score']
                cat_faults = analysis['catastrophic_faults']
                crit_faults = analysis['critical_faults']
                total_faults = analysis['total_faults']
                
                # Color based on score
                if score > 50:
                    color = '#DC2626'
                elif score > 30:
                    color = '#F59E0B'
                elif score > 15:
                    color = '#EAB308'
                else:
                    color = '#10B981'
                
                label = f"{i+1}. {component}\n"
                label += f"Score: {score} | Faults: {total_faults}\n"
                label += f"Catastrophic: {cat_faults} | Critical: {crit_faults}"
                
                c.node(
                    f"comp_{i}",
                    label=label,
                    style='filled',
                    fillcolor=color,
                    fontcolor='white'
                )
        
        # Save
        output_path = self.output_dir / "component_criticality"
        dot.render(output_path, format='png', cleanup=True)
        print(f"  Generated: {output_path}.png")
        
        return str(output_path) + ".png"


# ============================================================================
# Integration with EnhancedFaultTreeAnalyzer
# ============================================================================

def add_visualization_methods_to_analyzer():
    """Add visualization methods to the EnhancedFaultTreeAnalyzer class."""
    
    def generate_all_diagrams(self, output_dir: str = "diagrams") -> Dict[str, List[str]]:
        """Generate all visual diagrams."""
        print("\n" + "=" * 80)
        print("GENERATING VISUAL DIAGRAMS")
        print("=" * 80)
        
        output_files = {
            'fault_trees': [],
            'bowties': [],
            'propagation': [],
            'risk_matrix': [],
            'criticality': []
        }
        
        # Fault tree diagrams
        ft_viz = FaultTreeVisualizer(output_dir)
        output_files['fault_trees'] = ft_viz.generate_all_fault_trees(self)
        
        # Bow-tie diagrams
        bt_viz = BowTieVisualizer(output_dir)
        output_files['bowties'] = bt_viz.generate_all_bowties(self)
        
        # Propagation network
        prop_viz = PropagationVisualizer(output_dir)
        output_files['propagation'].append(
            prop_viz.generate_propagation_network(self)
        )
        
        # Risk matrix
        scenarios = self.generate_failure_scenarios()
        risk_viz = RiskMatrixVisualizer(output_dir)
        output_files['risk_matrix'].append(
            risk_viz.generate_risk_matrix(scenarios)
        )
        
        # Component criticality
        critical_components = self.analyze_critical_components()
        crit_viz = ComponentCriticalityVisualizer(output_dir)
        output_files['criticality'].append(
            crit_viz.generate_criticality_chart(critical_components)
        )
        
        print("\n" + "=" * 80)
        print("DIAGRAM GENERATION COMPLETE")
        print("=" * 80)
        
        total_diagrams = sum(len(files) for files in output_files.values())
        print(f"Total diagrams generated: {total_diagrams}")
        print(f"Output directory: {output_dir}")
        
        return output_files
    
    # Add method to class
    EnhancedFaultTreeAnalyzer.generate_all_diagrams = generate_all_diagrams


# Add to main function
def main_with_diagrams():
    """Enhanced main with diagram generation."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced FTA Generator with Visualizations")
    parser.add_argument("--directory", "-d", default=None)
    parser.add_argument("--json", default="garc_analysis.json")
    parser.add_argument("--report", default="garc_fta_report.txt")
    parser.add_argument("--summary", default="garc_summary.txt")
    parser.add_argument("--diagrams", default="diagrams", help="Diagram output directory")
    parser.add_argument("--no-diagrams", action="store_true", help="Skip diagram generation")
    args = parser.parse_args()
    
    # Collect model files
    if args.directory:
        model_dir = Path(args.directory)
    else:
        model_dir = CURRENT_DIR
    
    model_files = syside.collect_files_recursively(model_dir)
    print(f"Found {len(model_files)} .sysml files in {model_dir}")
    
    # Create analyzer and extract data
    analyzer = SafetyAnalyzer(model_files)
    analyzer.extract_hazards()
    analyzer.extract_fault_modes()
    analyzer.extract_propagation_paths()
    analyzer.extract_safety_goals()
    
    # Generate outputs
    analyzer.export_comprehensive_json(args.json)
    analyzer.print_text_report(args.report)
    analyzer.export_summary_report(args.summary)
    
    # Generate diagrams
    if not args.no_diagrams:
        add_visualization_methods_to_analyzer()
        analyzer.generate_all_diagrams(args.diagrams)
    
    print("\n" + "=" * 80)
    print("COMPLETE!")
    print("=" * 80)


if __name__ == "__main__":
    main_with_diagrams()
