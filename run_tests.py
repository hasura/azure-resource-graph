#!/usr/bin/env python3
"""
Test runner for Azure Resource Graph Client

This script provides convenient ways to run different types of tests.
"""

import sys
import subprocess
import argparse
from typing import List, Optional


def run_command(cmd: List[str], description: str) -> int:
    """Run a command and return exit code"""
    print(f"\n🚀 {description}")
    print(f"Command: {' '.join(cmd)}")
    print("-" * 60)

    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode
    except FileNotFoundError:
        print(f"❌ Error: Command not found. Make sure pytest is installed:")
        print("   pip install pytest")
        return 1


def main():
    """Main test runner"""
    parser = argparse.ArgumentParser(
        description="Azure Resource Graph Client Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_tests.py --all              # Run all tests
  python run_tests.py --unit             # Run only unit tests
  python run_tests.py --integration      # Run only integration tests
  python run_tests.py --auth             # Run only authentication tests
  python run_tests.py --storage          # Run only storage tests
  python run_tests.py --compliance       # Run only compliance tests
  python run_tests.py --slow             # Run only slow tests
  python run_tests.py --fast             # Run only fast tests (exclude slow)
  python run_tests.py --coverage         # Run with coverage report
  python run_tests.py --verbose          # Run with extra verbose output
  python run_tests.py --help-pytest     # Show pytest help
        """
    )

    # Test selection options
    test_group = parser.add_mutually_exclusive_group()
    test_group.add_argument("--all", action="store_true", help="Run all tests (default)")
    test_group.add_argument("--unit", action="store_true", help="Run only unit tests")
    test_group.add_argument("--integration", action="store_true", help="Run only integration tests")
    test_group.add_argument("--auth", action="store_true", help="Run only authentication tests")
    test_group.add_argument("--query", action="store_true", help="Run only query tests")
    test_group.add_argument("--storage", action="store_true", help="Run only storage tests")
    test_group.add_argument("--compliance", action="store_true", help="Run only compliance tests")
    test_group.add_argument("--slow", action="store_true", help="Run only slow tests")
    test_group.add_argument("--fast", action="store_true", help="Run fast tests (exclude slow)")

    # Output options
    parser.add_argument("--coverage", action="store_true", help="Run with coverage report")
    parser.add_argument("--verbose", action="store_true", help="Extra verbose output")
    parser.add_argument("--quiet", action="store_true", help="Minimal output")
    parser.add_argument("--html-report", action="store_true", help="Generate HTML test report")
    parser.add_argument("--junit-xml", action="store_true", help="Generate JUnit XML report")

    # Pytest options
    parser.add_argument("--help-pytest", action="store_true", help="Show pytest help")
    parser.add_argument("--list-tests", action="store_true", help="List all available tests")
    parser.add_argument("--parallel", action="store_true", help="Run tests in parallel (requires pytest-xdist)")

    args = parser.parse_args()

    # Handle special cases
    if args.help_pytest:
        return run_command(["pytest", "--help"], "Showing pytest help")

    if args.list_tests:
        return run_command(["pytest", "--collect-only", "-q"], "Listing all tests")

    # Build pytest command
    cmd = ["pytest"]

    # Test selection
    if args.unit:
        cmd.extend(["-m", "unit"])
    elif args.integration:
        cmd.extend(["-m", "integration"])
    elif args.auth:
        cmd.extend(["-m", "auth"])
    elif args.query:
        cmd.extend(["-m", "query"])
    elif args.storage:
        cmd.extend(["-m", "storage"])
    elif args.compliance:
        cmd.extend(["-m", "compliance"])
    elif args.slow:
        cmd.extend(["-m", "slow"])
    elif args.fast:
        cmd.extend(["-m", "not slow"])
    # --all or no selection runs all tests (default pytest behavior)

    # Output options
    if args.verbose:
        cmd.append("-vv")
    elif args.quiet:
        cmd.append("-q")

    # Coverage
    if args.coverage:
        cmd.extend(["--cov=azure_resource_graph", "--cov-report=term", "--cov-report=html"])

    # Reports
    if args.html_report:
        cmd.extend(["--html=test_report.html", "--self-contained-html"])

    if args.junit_xml:
        cmd.extend(["--junit-xml=test_results.xml"])

    # Parallel execution
    if args.parallel:
        cmd.extend(["-n", "auto"])

    # Run the tests
    description = "Running Azure Resource Graph Client tests"
    if args.unit:
        description += " (unit tests only)"
    elif args.integration:
        description += " (integration tests only)"
    elif args.auth:
        description += " (authentication tests only)"
    elif args.query:
        description += " (query tests only)"
    elif args.storage:
        description += " (storage tests only)"
    elif args.compliance:
        description += " (compliance tests only)"
    elif args.slow:
        description += " (slow tests only)"
    elif args.fast:
        description += " (fast tests only)"

    exit_code = run_command(cmd, description)

    # Final summary
    print("\n" + "=" * 60)
    if exit_code == 0:
        print("✅ All tests passed!")
        if args.coverage:
            print("📊 Coverage report: htmlcov/index.html")
        if args.html_report:
            print("📋 Test report: test_report.html")
    else:
        print("❌ Some tests failed!")
        print("Check the output above for details.")

    print("=" * 60)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
