#!/usr/bin/env python3
"""
Main runner for MaynDrive automation system.
Single entry point for running LLM-supervised automation flows.
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from loop import OrchestrationLoop
from state_graph import StateGraphBuilder
from learning import LearningManager
from llm_client import GLMClient
from gps_client import GPSClient
from adb_tools import ADBTools

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def init_environment():
    """Initialize the automation environment"""
    print("🚀 Initializing MaynDrive Automation Environment...")

    # Check required environment variables
    required_env = ['ZAI_API_KEY']
    missing_env = [env for env in required_env if not os.getenv(env)]

    if missing_env:
        print(f"❌ Missing required environment variables: {', '.join(missing_env)}")
        print("Please set the following environment variables:")
        print("- ZAI_API_KEY: Your Z.ai API key for GLM-4.6")
        print("- ZAI_BASE_URL: (Optional) Z.ai API base URL")
        return False

    # Create required directories
    dirs_to_create = [
        'storage/sessions',
        'storage/learning',
        'storage/logs'
    ]

    for dir_path in dirs_to_create:
        Path(dir_path).mkdir(parents=True, exist_ok=True)

    print("✅ Environment initialized successfully")
    return True

def check_dependencies():
    """Check if all dependencies are available"""
    print("🔍 Checking dependencies...")

    # Check ADB
    try:
        import subprocess
        result = subprocess.run(['adb', 'version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("✅ ADB found")
        else:
            print("❌ ADB not found or not working")
            return False
    except Exception as e:
        print(f"❌ ADB check failed: {e}")
        return False

    # Check device connectivity
    try:
        adb_tools = ADBTools()
        if adb_tools.is_device_connected():
            print("✅ Device connected")
        else:
            print("❌ Device not connected")
            print("Please ensure your device/emulator is running and ADB is properly configured")
            return False
    except Exception as e:
        print(f"❌ Device check failed: {e}")
        return False

    # Check GLM client connectivity
    try:
        llm_client = GLMClient()
        if llm_client.test_connection():
            print("✅ GLM-4.6 API connection successful")
        else:
            print("❌ GLM-4.6 API connection failed")
            print("Please check your ZAI_API_KEY and network connection")
            return False
    except Exception as e:
        print(f"❌ GLM client check failed: {e}")
        return False

    # Check GPS sidecar
    try:
        gps_client = GPSClient()
        if gps_client.health_check():
            print("✅ GPS sidecar healthy")
        else:
            print("⚠️  GPS sidecar not responding (continuing anyway)")
    except Exception as e:
        print(f"⚠️  GPS sidecar check failed: {e}")

    return True

def build_state_graph():
    """Build state graph from discovery data"""
    print("🏗️  Building state graph from discovery data...")

    try:
        builder = StateGraphBuilder()
        graph = builder.build_state_graph()

        if builder.save_graph("state_graph.json"):
            print(f"✅ State graph built with {len(graph['states'])} states")
            print(f"📋 Created {len(graph['transitions'])} transitions")

            # Display available routes
            print("\n🛣️  Available routes:")
            for route_name, route_states in builder.routes.items():
                print(f"  {route_name}: {' → '.join(route_states)}")

            return True
        else:
            print("❌ Failed to save state graph")
            return False

    except Exception as e:
        print(f"❌ State graph building failed: {e}")
        return False

def run_automation(args):
    """Run automation with provided arguments"""
    print(f"🎯 Starting automation for goal: {args.goal}")
    print(f"📱 Using device: {args.device}")
    print(f"⏱️  Max steps: {args.max_steps}")

    try:
        # Create orchestration loop
        loop = OrchestrationLoop(args.device, args.session_dir)

        # Run automation
        success = loop.run_automation(args.goal, args.max_steps)

        if success:
            print(f"\n🎉 SUCCESS: Goal '{args.goal}' achieved!")
            print(f"📁 Session saved to: {loop.session_dir}")
            print(f"📊 Total steps: {loop.step_count}")

            # Show next steps
            print("\n📋 Next steps:")
            print("- Review session screenshots and logs")
            print("- Check learning updates in storage/learning/")
            print("- Run 'python runner.py --merge-learning' to incorporate new patterns")
        else:
            print(f"\n❌ FAILED: Goal '{args.goal}' not achieved")
            print(f"📁 Session data saved to: {loop.session_dir}")
            print(f"📊 Total steps attempted: {loop.step_count}")

            if loop.step_count >= args.max_steps:
                print("⚠️  Maximum steps reached - try increasing --max-steps")

        return 0 if success else 1

    except KeyboardInterrupt:
        print("\n⏹️  Automation interrupted by user")
        return 130  # Standard exit code for SIGINT
    except Exception as e:
        print(f"\n💥 FATAL ERROR: {e}")
        return 1

def merge_learning():
    """Merge learning from all completed sessions"""
    print("📚 Merging learning data from sessions...")

    try:
        learning_manager = LearningManager()

        # Find all session directories
        sessions_path = Path("storage/sessions")
        if not sessions_path.exists():
            print("❌ No session data found")
            return False

        session_dirs = [d for d in sessions_path.iterdir() if d.is_dir()]
        print(f"📂 Found {len(session_dirs)} session directories")

        merged_count = 0
        for session_dir in session_dirs:
            try:
                learning_manager.merge_session_learning(str(session_dir))
                merged_count += 1
            except Exception as e:
                logger.error(f"Failed to merge session {session_dir}: {e}")

        # Save merged learning
        learning_manager.save_learning_data()

        # Generate learning report
        report = learning_manager.generate_learning_report()

        print(f"✅ Merged learning from {merged_count} sessions")
        print(f"📊 Learning summary:")
        print(f"  - Total patterns: {report['summary']['total_patterns']}")
        print(f"  - Total transitions: {report['summary']['total_transitions']}")
        print(f"  - Route success rates: {report['summary']['total_routes']}")

        if report['problematic_transitions']:
            print(f"  - Problematic transitions: {len(report['problematic_transitions'])}")

        return True

    except Exception as e:
        print(f"❌ Learning merge failed: {e}")
        return False

def show_status():
    """Show current system status"""
    print("📊 System Status")
    print("=" * 50)

    # Check state graph
    if os.path.exists("state_graph.json"):
        try:
            import json
            with open("state_graph.json", 'r') as f:
                graph = json.load(f)
            print(f"📈 State Graph: {len(graph['states'])} states, {len(graph['transitions'])} transitions")
        except Exception as e:
            print(f"📈 State Graph: Error loading ({e})")
    else:
        print("📈 State Graph: Not built (run --build-graph first)")

    # Check learning data
    learning_manager = LearningManager()
    print(f"🧠 Learning Data: {len(learning_manager.learned_patterns)} patterns")
    print(f"📈 Transition Metrics: {len(learning_manager.transition_metrics)} tracked")

    # Check device
    try:
        adb_tools = ADBTools()
        if adb_tools.is_device_connected():
            device_info = adb_tools.device_info
            print(f"📱 Device: {device_info.device} ({device_info.width}x{device_info.height}, density: {device_info.density})")
        else:
            print("📱 Device: Not connected")
    except Exception as e:
        print(f"📱 Device: Error checking ({e})")

    # Check GPS
    try:
        gps_client = GPSClient()
        if gps_client.health_check():
            status = gps_client.get_status()
            if status and status.current_location:
                print(f"🛰️  GPS: Active (last: {status.current_location.latitude:.4f}, {status.current_location.longitude:.4f})")
            else:
                print("🛰️  GPS: Active (no recent location)")
        else:
            print("🛰️  GPS: Not responding")
    except Exception as e:
        print(f"🛰️  GPS: Error checking ({e})")

    # Check LLM
    try:
        llm_client = GLMClient()
        if llm_client.test_connection():
            print("🤖 LLM (GLM-4.6): Connected")
        else:
            print("🤖 LLM (GLM-4.6): Connection failed")
    except Exception as e:
        print(f"🤖 LLM (GLM-4.6): Error checking ({e})")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="MaynDrive LLM-Supervised Automation System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --goal UNLOCK_VEHICLE           # Unlock a vehicle
  %(prog)s --goal LOGIN --max-steps 20  # Login with 20 step limit
  %(prog)s --build-graph                   # Build state graph from discovery data
  %(prog)s --merge-learning                 # Merge session learning data
  %(prog)s --status                       # Show system status
        """
    )

    # Main arguments
    parser.add_argument("--goal", choices=[
        "UNLOCK_VEHICLE", "LOGIN", "SIGNUP", "RENTAL", "MAP_ACCESS"
    ], help="Automation goal to achieve")

    parser.add_argument("--device", default="emulator-5556",
                       help="Device ID (default: emulator-5556)")

    parser.add_argument("--max-steps", type=int, default=50,
                       help="Maximum number of automation steps (default: 50)")

    parser.add_argument("--session-dir",
                       help="Specific session directory to use")

    # Utility arguments
    parser.add_argument("--init", action="store_true",
                       help="Initialize environment and check dependencies")

    parser.add_argument("--build-graph", action="store_true",
                       help="Build state graph from discovery data")

    parser.add_argument("--merge-learning", action="store_true",
                       help="Merge learning data from completed sessions")

    parser.add_argument("--status", action="store_true",
                       help="Show current system status")

    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose logging")

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Handle utility commands
    if args.init:
        if not init_environment():
            return 1
        if not check_dependencies():
            return 1
        return 0

    if args.build_graph:
        if not init_environment():
            return 1
        return 0 if build_state_graph() else 1

    if args.merge_learning:
        return 0 if merge_learning() else 1

    if args.status:
        show_status()
        return 0

    # Handle automation command
    if not args.goal:
        parser.print_help()
        print("\n❌ --goal is required when running automation")
        return 1

    # Initialize environment for automation
    if not init_environment():
        return 1

    if not check_dependencies():
        return 1

    # Ensure state graph exists
    if not os.path.exists("state_graph.json"):
        print("⚠️  State graph not found, building from discovery data...")
        if not build_state_graph():
            return 1

    # Run automation
    return run_automation(args)

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n⏹️  Operation cancelled by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        sys.exit(1)