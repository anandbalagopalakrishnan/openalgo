#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DefinedGe Securities Authentication Test
Tests the 3-step authentication process for DefinedGe broker integration
"""

import os
import sys
import json
from colorama import Fore, Style, init as colorama_init

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from broker.definedge.api.auth_api import authenticate_broker, login_step1, login_step2

colorama_init(autoreset=True)

def green(text):
    return f"{Fore.GREEN}{text}{Style.RESET_ALL}"

def red(text):
    return f"{Fore.RED}{text}{Style.RESET_ALL}"

def yellow(text):
    return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"

class DefinedGeAuthTest:
    def __init__(self):
        self.api_token = os.getenv('BROKER_API_KEY')
        self.api_secret = os.getenv('BROKER_API_SECRET')
        self.test_results = []
        
    def log_result(self, test_name, success, message=""):
        status = green("✓ PASS") if success else red("✗ FAIL")
        result = f"{status} {test_name}"
        if message:
            result += f": {message}"
        print(result)
        self.test_results.append((test_name, success, message))
        
    def check_credentials(self):
        """Check if required credentials are available"""
        print(f"\n{yellow('='*60)}")
        print(f"{yellow('DEFINEDGE AUTHENTICATION TEST')}")
        print(f"{yellow('='*60)}")
        
        if not self.api_token:
            self.log_result("Environment Check", False, "BROKER_API_KEY not set")
            return False
            
        if not self.api_secret:
            self.log_result("Environment Check", False, "BROKER_API_SECRET not set")
            return False
            
        self.log_result("Environment Check", True, "Credentials found")
        return True
        
    def test_step1_login(self):
        """Test Step 1: Login with API credentials"""
        print(f"\n{yellow('Testing Step 1: Initial Login')}")
        
        try:
            response = login_step1(self.api_token, self.api_secret)
            
            if response is None:
                self.log_result("Step 1 - API Call", False, "No response received")
                return None
                
            if not isinstance(response, dict):
                self.log_result("Step 1 - Response Format", False, "Invalid response format")
                return None
                
            self.log_result("Step 1 - API Call", True, "Response received")
            
            # Check for OTP token in response
            otp_token = response.get('otp_token')
            if otp_token:
                self.log_result("Step 1 - OTP Token", True, f"Token: {otp_token[:10]}...")
                return response
            else:
                self.log_result("Step 1 - OTP Token", False, "OTP token not found in response")
                print(f"Response keys: {list(response.keys())}")
                return None
                
        except Exception as e:
            self.log_result("Step 1 - Exception", False, str(e))
            return None
            
    def test_step2_otp_verification(self, step1_response, otp):
        """Test Step 2: OTP verification with auth code"""
        print(f"\n{yellow('Testing Step 2: OTP Verification with Auth Code')}")
        
        if not step1_response:
            self.log_result("Step 2 - Prerequisites", False, "Step 1 failed")
            return None
            
        otp_token = step1_response.get('otp_token')
        if not otp_token:
            self.log_result("Step 2 - OTP Token", False, "No OTP token from Step 1")
            return None
            
        try:
            response = login_step2(otp_token, otp, self.api_secret)
            
            if response is None:
                self.log_result("Step 2 - API Call", False, "No response received")
                return None
                
            if not isinstance(response, dict):
                self.log_result("Step 2 - Response Format", False, "Invalid response format")
                return None
                
            self.log_result("Step 2 - API Call", True, "Response received")
            
            # Check response status
            if response.get('stat') == 'Ok':
                self.log_result("Step 2 - Status", True, "Authentication successful")
            else:
                error_msg = response.get('emsg', 'Unknown error')
                self.log_result("Step 2 - Status", False, f"Auth failed: {error_msg}")
                return None
            
            # Check for session keys
            api_session_key = response.get('api_session_key')
            susertoken = response.get('susertoken')
            
            if api_session_key:
                self.log_result("Step 2 - Session Key", True, f"Key: {api_session_key[:10]}...")
            else:
                self.log_result("Step 2 - Session Key", False, "Session key not found")
                
            if susertoken:
                self.log_result("Step 2 - User Token", True, f"Token: {susertoken[:10]}...")
            else:
                self.log_result("Step 2 - User Token", False, "User token not found")
                
            if api_session_key and susertoken:
                return response
            else:
                print(f"Response keys: {list(response.keys())}")
                return None
                
        except Exception as e:
            self.log_result("Step 2 - Exception", False, str(e))
            return None
            
            
    def test_full_authentication(self, otp):
        """Test the complete authentication flow"""
        print(f"\n{yellow('Testing Complete Authentication Flow')}")
        
        try:
            auth_string, error = authenticate_broker(self.api_token, self.api_secret, otp)
            
            if error:
                self.log_result("Full Auth - Error", False, error)
                return False
                
            if not auth_string:
                self.log_result("Full Auth - Result", False, "No auth string returned")
                return False
                
            # Validate auth string format
            parts = auth_string.split(':::')
            if len(parts) == 3:
                self.log_result("Full Auth - Format", True, "Auth string format valid")
                self.log_result("Full Auth - Success", True, f"Auth: {auth_string[:20]}...")
                return True
            else:
                self.log_result("Full Auth - Format", False, f"Invalid format: {len(parts)} parts")
                return False
                
        except Exception as e:
            self.log_result("Full Auth - Exception", False, str(e))
            return False
            
    def run_interactive_test(self):
        """Run interactive test with user-provided OTP"""
        if not self.check_credentials():
            return False
            
        # Test individual steps first
        step1_response = self.test_step1_login()
        
        if step1_response:
            print(f"\n{yellow('OTP should have been sent to your registered mobile/email')}")
            otp = input("Enter OTP: ").strip()
            
            if otp:
                step2_response = self.test_step2_otp_verification(step1_response, otp)
                
                if step2_response:
                    # Test full flow
                    self.test_full_authentication(otp)
            else:
                print(red("No OTP provided, skipping remaining tests"))
                
        self.print_summary()
        
    def run_mock_test(self):
        """Run test with mock responses (for CI/CD)"""
        print(f"\n{yellow('Running Mock Authentication Test')}")
        
        if not self.check_credentials():
            return False
            
        # Test Step 1 only (doesn't require OTP)
        self.test_step1_login()
        
        print(f"\n{yellow('Note: Full authentication requires OTP verification')}")
        print("Run with interactive mode to test complete flow")
        
        self.print_summary()
        
    def print_summary(self):
        """Print test summary"""
        print(f"\n{yellow('='*60)}")
        print(f"{yellow('TEST SUMMARY')}")
        print(f"{yellow('='*60)}")
        
        passed = sum(1 for _, success, _ in self.test_results if success)
        failed = len(self.test_results) - passed
        
        for test_name, success, message in self.test_results:
            status = green("✓") if success else red("✗")
            print(f"{status} {test_name}")
            if message and not success:
                print(f"    {message}")
                
        color = Fore.GREEN if failed == 0 else Fore.RED
        print(f"\n{color}{passed} tests passed, {failed} tests failed{Style.RESET_ALL}")
        
        return failed == 0

def main():
    """Main test runner"""
    tester = DefinedGeAuthTest()
    
    if len(sys.argv) > 1 and sys.argv[1] == '--interactive':
        success = tester.run_interactive_test()
    else:
        success = tester.run_mock_test()
        
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
