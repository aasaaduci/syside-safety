"""
Enhanced main script with FHA Excel generation
Call this to generate complete safety analysis package
"""

import argparse
import pathlib
from pathlib import Path
from typing import List

import syside

# Import the analyzer
from generate_fha_4 import EnhancedFaultTreeAnalyzer

# Import visualizers
from fta_visualizer import (
    FaultTreeVisualizer,
    BowTieVisualizer,
    PropagationVisualizer,
    RiskMatrixVisualizer,
    ComponentCriticalityVisualizer,
)

# Import FHA generator
from fha_excel_generator import FHAExcelGenerator, generate_fha_excel


CURRENT_DIR = pathlib.Path(__file__).parent


def main() -> None:
    """Main execution function with complete analysis generation."""
    
    parser = argparse.ArgumentParser(
        description="Complete Safety Analysis Generator from GARC SysML v2 Model",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate everything in default locations
  python main_complete.py
  
  # Custom directory and output names
  python main_complete.py --directory ./Safety --json analysis.json --fha garc_fha.xlsx
  
  # Skip specific outputs
  python main_complete.py --no-diagrams --no-fha
        """
    )
    
    parser.add_argument(
        "--directory", "-d",
        default=None,
        help="Directory containing SysML v2 files (default: current directory)",
    )
    parser.add_argument(
        "--json",
        default="garc_analysis.json",
        help="Output JSON file (default: garc_analysis.json)",
    )
    parser.add_argument(
        "--report",
        default="garc_fta_report.txt",
        help="Output detailed FTA report file (default: garc_fta_report.txt)",
    )
    parser.add_argument(
        "--summary",
        default="garc_summary.txt",
        help="Output executive summary file (default: garc_summary.txt)",
    )
    parser.add_argument(
        "--diagrams",
        default="diagrams",
        help="Diagram output directory (default: diagrams)",
    )
    parser.add_argument(
        "--fha",
        default="GARC_FHA.xlsx",
        help="FHA Excel output file (default: GARC_FHA.xlsx)",
    )
    parser.add_argument(
        "--template",
        default=None,
        help="Optional FHA template file to use as base",
    )
    parser.add_argument(
        "--no-diagrams",
        action="store_true",
        help="Skip diagram generation",
    )
    parser.add_argument(
        "--no-fha",
        action="store_true",
        help="Skip FHA Excel generation",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output",
    )
    
    args = parser.parse_args()
    
    # Print banner
    print("\n" + "=" * 80)
    print("GARC COMPLETE SAFETY ANALYSIS GENERATOR")
    print("=" * 80)
    
    # Collect model files
    if args.directory:
        model_dir = Path(args.directory)
    else:
        model_dir = CURRENT_DIR
    
    model_files = syside.collect_files_recursively(model_dir)
    print(f"\n✓ Found {len(model_files)} .sysml files in {model_dir}")
    
    if args.verbose:
        print("  Files:", [f.name for f in model_files])
    
    # Create analyzer and extract data
    print("\n" + "-" * 80)
    print("PHASE 1: SysML Model Analysis")
    print("-" * 80)
    
    analyzer = EnhancedFaultTreeAnalyzer(model_files)
    analyzer.extract_hazards()
    analyzer.extract_fault_modes()
    analyzer.extract_propagation_paths()
    analyzer.extract_safety_goals()
    
    print(f"✓ Extracted {len(analyzer.hazards)} hazards")
    print(f"✓ Extracted {len(analyzer.faults)} fault modes")
    print(f"✓ Extracted {len(analyzer.propagations)} propagation paths")
    print(f"✓ Extracted {len(analyzer.safety_goals)} safety goals")
    
    # Generate analysis outputs
    print("\n" + "-" * 80)
    print("PHASE 2: Analysis Report Generation")
    print("-" * 80)
    
    print(f"\n→ Comprehensive JSON: {args.json}")
    analyzer.export_comprehensive_json(args.json)
    
    print(f"→ Detailed FTA Report: {args.report}")
    analyzer.print_text_report(args.report)
    
    print(f"→ Executive Summary: {args.summary}")
    analyzer.export_summary_report(args.summary)
    
    # Generate diagrams
    if not args.no_diagrams:
        print("\n" + "-" * 80)
        print("PHASE 3: Visual Diagram Generation")
        print("-" * 80)
        
        Path(args.diagrams).mkdir(exist_ok=True)
        
        # Fault trees
        print("\n→ Fault Tree Diagrams")
        ft_viz = FaultTreeVisualizer(args.diagrams)
        ft_files = ft_viz.generate_all_fault_trees(analyzer)
        print(f"  Generated {len(ft_files)} fault tree diagrams")
        
        # Bow-ties
        print("\n→ Bow-Tie Diagrams")
        bt_viz = BowTieVisualizer(args.diagrams)
        bt_files = bt_viz.generate_all_bowties(analyzer)
        print(f"  Generated {len(bt_files)} bow-tie diagrams")
        
        # Propagation network
        print("\n→ Propagation Network")
        prop_viz = PropagationVisualizer(args.diagrams)
        prop_file = prop_viz.generate_propagation_network(analyzer)
        print(f"  Generated complete propagation network")
        
        # Risk matrix
        print("\n→ Risk Assessment Matrix")
        scenarios = analyzer.generate_failure_scenarios()
        risk_viz = RiskMatrixVisualizer(args.diagrams)
        risk_file = risk_viz.generate_risk_matrix(scenarios)
        print(f"  Generated risk matrix heatmap")
        
        # Component criticality
        print("\n→ Component Criticality Analysis")
        critical_components = analyzer.analyze_critical_components()
        crit_viz = ComponentCriticalityVisualizer(args.diagrams)
        crit_file = crit_viz.generate_criticality_chart(critical_components)
        print(f"  Generated criticality ranking")
    
    # Generate FHA Excel
    if not args.no_fha:
        print("\n" + "-" * 80)
        print("PHASE 4: Functional Hazard Assessment (FHA)")
        print("-" * 80)
        
        print(f"\n→ FHA Excel Workbook: {args.fha}")
        generate_fha_excel(
            analyzer,
            template_path=args.template,
            output_path=args.fha
        )
    
    # Print summary
    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)
    
    print("\nOutput Files Generated:")
    print(f"  📊 JSON Analysis     : {args.json}")
    print(f"  📄 FTA Report        : {args.report}")
    print(f"  📋 Summary Report    : {args.summary}")
    
    if not args.no_diagrams:
        print(f"  📈 Diagrams          : {args.diagrams}/")
    
    if not args.no_fha:
        print(f"  📗 FHA Spreadsheet   : {args.fha}")
    
    print("\n" + "=" * 80)


if __name__ == "__main__":
    main()
