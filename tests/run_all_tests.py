import unittest
import sys
import os

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Ensure current working directory is project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from tests.test_vulnerable_app import TestVulnerableApp
from tests.test_secure_app import TestSecureApp

def run_cyber_project_audit():
    print("=" * 80)
    print("      COMUNICATION_LTD CYBER SECURITY FINAL PROJECT - COMPREHENSIVE AUDIT")
    print("=" * 80)

    suite = unittest.TestSuite()
    loader = unittest.TestLoader()

    # Add both test suites
    suite.addTests(loader.loadTestsFromTestCase(TestVulnerableApp))
    suite.addTests(loader.loadTestsFromTestCase(TestSecureApp))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 80)
    print(f"AUDIT SUMMARY:")
    print(f"  Tests executed: {result.testsRun}")
    print(f"  Passed:         {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"  Failures:       {len(result.failures)}")
    print(f"  Errors:         {len(result.errors)}")
    if result.wasSuccessful():
        print("  Status:         SUCCESS - All Cyber Security Requirements Verified 100%!")
    else:
        print("  Status:         FAILED - One or more tests failed.")
    print("=" * 80)

    return 0 if result.wasSuccessful() else 1

if __name__ == "__main__":
    exit_code = run_cyber_project_audit()
    sys.exit(exit_code)
