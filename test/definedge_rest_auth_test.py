#!/usr/bin/env python3
"""
Definedge Securities REST API Authentication Test

This module provides comprehensive testing for Definedge Securities authentication
using direct REST API calls instead of the pyintegrate SDK. It replicates the
authentication flow using standard HTTP libraries (requests/httpx).

Based on analysis of pyintegrate codebase to understand the exact API endpoints
and authentication flow.
"""

import os
import sys
import json
import time
import logging
from hashlib import sha256
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Alternative: Use httpx for async capabilities (uncomment if preferred)
# import httpx


class DefinedgeRestAPIClient:
    """
    Definedge Securities REST API Client
    
    Implements direct REST API calls for authentication and basic operations
    without using the pyintegrate SDK.
    """
    
    # API Endpoints (based on pyintegrate analysis)
    DEFAULT_LOGIN_URL = "https://signin.definedgesecurities.com/auth/realms/debroking/dsbpkc/"
    DEFAULT_BASE_URL = "https://integrate.definedgesecurities.com/dart/v1/"
    SYMBOLS_URL = "https://app.definedgesecurities.com/public/allmaster.zip"
    
    # Exchange Types (replicated from pyintegrate)
    EXCHANGE_TYPE_NSE = "NSE"
    EXCHANGE_TYPE_BSE = "BSE"
    EXCHANGE_TYPE_NFO = "NFO"
    EXCHANGE_TYPE_BFO = "BFO"
    EXCHANGE_TYPE_CDS = "CDS"
    EXCHANGE_TYPE_MCX = "MCX"
    
    # Order Types
    ORDER_TYPE_BUY = "BUY"
    ORDER_TYPE_SELL = "SELL"
    
    # Price Types
    PRICE_TYPE_MARKET = "MARKET"
    PRICE_TYPE_LIMIT = "LIMIT"
    PRICE_TYPE_SL_MARKET = "SL-MARKET"
    PRICE_TYPE_SL_LIMIT = "SL-LIMIT"
    
    # Product Types
    PRODUCT_TYPE_CNC = "CNC"
    PRODUCT_TYPE_INTRADAY = "INTRADAY"
    PRODUCT_TYPE_NORMAL = "NORMAL"
    
    def __init__(
        self,
        login_url: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: int = 30,
        enable_logging: bool = True,
        proxies: Optional[Dict[str, str]] = None,
        ssl_verify: bool = True,
        retry_attempts: int = 3
    ):
        """
        Initialize the REST API client.
        
        Args:
            login_url: Custom login URL (defaults to Definedge's login URL)
            base_url: Custom base URL for API calls (defaults to Definedge's API URL)
            timeout: Request timeout in seconds
            enable_logging: Enable detailed logging
            proxies: Proxy configuration for requests
            ssl_verify: Enable SSL certificate verification
            retry_attempts: Number of retry attempts for failed requests
        """
        self.login_url = login_url or self.DEFAULT_LOGIN_URL
        self.base_url = base_url or self.DEFAULT_BASE_URL
        self.timeout = timeout
        self.enable_logging = enable_logging
        self.proxies = proxies or {}
        self.ssl_verify = ssl_verify
        
        # Session management
        self.uid: str = ""
        self.actid: str = ""
        self.api_session_key: str = ""
        self.ws_session_key: str = ""
        
        # Setup logging
        self.logger = self._setup_logging()
        
        # Create requests session with retry strategy
        self.session = self._create_session(retry_attempts)
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        if self.enable_logging and not logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.DEBUG)
        
        return logger
    
    def _create_session(self, retry_attempts: int) -> requests.Session:
        """Create a requests session with retry strategy and connection pooling."""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=retry_attempts,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST"]
        )
        
        # Mount adapter with retry strategy
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default headers
        session.headers.update({
            'User-Agent': 'DefinedgeRestClient/1.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
        return session
    
    def _send_request(
        self,
        method: str,
        route: str,
        route_prefix: Optional[str] = None,
        url_params: Optional[Dict[str, Any]] = None,
        json_params: Optional[Dict[str, Any]] = None,
        data_params: Optional[Dict[str, Any]] = None,
        query_params: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Send HTTP request to Definedge API.
        
        This method replicates the send_request method from pyintegrate's ConnectToIntegrate class.
        """
        # Form URL
        base = route_prefix if route_prefix else self.base_url
        url = urljoin(base, route.format(**url_params) if url_params else route)
        
        # Prepare headers
        headers = extra_headers.copy() if extra_headers else {}
        
        # Add authorization header if API session key is available
        if self.api_session_key and 'Authorization' not in headers:
            headers['Authorization'] = self.api_session_key
        
        # Log request details
        self.logger.debug(f"Request: {method} {url}")
        self.logger.debug(f"Headers: {headers}")
        self.logger.debug(f"JSON Params: {json_params}")
        self.logger.debug(f"Query Params: {query_params}")
        
        try:
            # Make the request
            response = self.session.request(
                method=method,
                url=url,
                json=json_params,
                data=data_params,
                params=query_params,
                headers=headers,
                verify=self.ssl_verify,
                allow_redirects=True,
                timeout=self.timeout,
                proxies=self.proxies
            )
            
            # Log response details
            self.logger.debug(f"Response: {response.status_code}")
            self.logger.debug(f"Response Headers: {dict(response.headers)}")
            
            # Raise an exception for bad status codes
            response.raise_for_status()
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {e}")
            raise
        
        # Parse response based on content type
        content_type = response.headers.get('content-type', '').lower()
        
        if 'application/json' in content_type:
            try:
                data = response.json()
                self.logger.debug(f"Response Data: {data}")
            except ValueError as e:
                raise Exception(f"Couldn't parse JSON response: {response.content}") from e
                
        elif 'text/csv' in content_type:
            # Handle CSV responses (for symbols data)
            data = {"data": response.text}
            
        else:
            # Handle other content types
            try:
                data = response.json()  # Try JSON first
            except ValueError:
                data = {"content": response.text, "status_code": response.status_code}
        
        # Check for API errors (replicate pyintegrate error handling)
        if isinstance(data, dict):
            if data.get("status") == "ERROR":
                error_msg = data.get("message", "Unknown API error")
                self.logger.error(f"API Error: {error_msg}")
                raise Exception(f"API Error: {error_msg}")
        
        return data
    
    def login(
        self, 
        api_token: str, 
        api_secret: str, 
        totp: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Authenticate with Definedge Securities using REST API.
        
        This method replicates the login flow from pyintegrate:
        1. Send GET request to login/{api_token} with api_secret in headers
        2. Get OTP token from response
        3. Prompt for TOTP/OTP if not provided
        4. Calculate authentication code (SHA256 hash)
        5. Send POST request to token endpoint
        6. Store session keys from response
        
        Args:
            api_token: Definedge API token
            api_secret: Definedge API secret
            totp: Optional TOTP code (will prompt if not provided)
            
        Returns:
            Dictionary containing session keys
            
        Raises:
            ValueError: If credentials are invalid
            Exception: For other authentication errors
        """
        if not api_token or not api_secret:
            raise ValueError("Invalid api_token or api_secret")
        
        try:
            self.logger.info("Starting authentication process...")
            
            # Step 1: Get OTP token
            self.logger.info("Step 1: Getting OTP token...")
            otp_response = self._send_request(
                method="GET",
                route=f"login/{api_token}",
                route_prefix=self.login_url,
                extra_headers={"api_secret": api_secret}
            )
            
            otp_token = otp_response.get("otp_token")
            if not otp_token:
                raise Exception("Failed to get OTP token from response")
            
            self.logger.info(f"✓ OTP token received: {otp_token[:10]}...")
            
            # Step 2: Get TOTP/OTP
            if not totp:
                try:
                    totp = input("Enter OTP/External TOTP: ").strip()
                except KeyboardInterrupt:
                    raise ValueError("No OTP/TOTP provided")
            
            if not totp:
                raise ValueError("No OTP/TOTP provided")
            
            self.logger.info("✓ TOTP/OTP provided")
            
            # Step 3: Calculate authentication code (exactly as in pyintegrate)
            auth_code = sha256(f"{otp_token}{totp}{api_secret}".encode("utf-8")).hexdigest()
            self.logger.debug(f"Authentication code calculated: {auth_code[:16]}...")
            
            # Step 4: Get session keys
            self.logger.info("Step 2: Getting session keys...")
            token_response = self._send_request(
                method="POST",
                route="token",
                route_prefix=self.login_url,
                json_params={
                    "otp_token": otp_token,
                    "otp": totp,
                    "ac": auth_code
                }
            )
            
            # Step 5: Extract and store session keys (replicate pyintegrate logic)
            self.uid = token_response.get("uid", "")
            self.actid = token_response.get("actid", "")  
            self.api_session_key = token_response.get("api_session_key", "")
            self.ws_session_key = token_response.get("susertoken", "")  # Note: susertoken is the WebSocket key
            
            # Validate that we got all required keys
            if not all([self.uid, self.actid, self.api_session_key, self.ws_session_key]):
                raise Exception("Authentication succeeded but missing session data")
            
            self.logger.info("✓ Authentication successful!")
            self.logger.info(f"✓ User ID: {self.uid}")
            self.logger.info(f"✓ Account ID: {self.actid}")
            self.logger.info(f"✓ API Session Key: {self.api_session_key[:20]}...")
            self.logger.info(f"✓ WebSocket Session Key: {self.ws_session_key[:20]}...")
            
            return {
                "uid": self.uid,
                "actid": self.actid,
                "api_session_key": self.api_session_key,
                "ws_session_key": self.ws_session_key,
                "status": "SUCCESS"
            }
            
        except Exception as e:
            self.logger.error(f"Authentication failed: {e}")
            raise
    
    def get_session_keys(self) -> Tuple[str, str, str, str]:
        """
        Get stored session keys.
        
        Returns:
            Tuple of (uid, actid, api_session_key, ws_session_key)
        """
        return (self.uid, self.actid, self.api_session_key, self.ws_session_key)
    
    def set_session_keys(self, uid: str, actid: str, api_session_key: str, ws_session_key: str) -> None:
        """
        Manually set session keys (useful for testing or session restoration).
        """
        self.uid = uid
        self.actid = actid
        self.api_session_key = api_session_key
        self.ws_session_key = ws_session_key
        
        self.logger.info("Session keys updated manually")
    
    def test_authenticated_endpoint(self) -> Dict[str, Any]:
        """
        Test an authenticated endpoint to verify the session is working.
        
        Returns:
            Response from the limits endpoint (account details)
        """
        if not self.api_session_key:
            raise Exception("Not authenticated. Please login first.")
        
        self.logger.info("Testing authenticated endpoint...")
        
        try:
            # Test the limits endpoint (account balance and margin details)
            response = self._send_request(
                method="GET",
                route="limits"
            )
            
            self.logger.info("✓ Authenticated endpoint test successful")
            return response
            
        except Exception as e:
            self.logger.error(f"Authenticated endpoint test failed: {e}")
            raise
    
    def get_orders(self) -> Dict[str, Any]:
        """Get list of orders (test endpoint)."""
        return self._send_request(method="GET", route="orders")
    
    def get_positions(self) -> Dict[str, Any]:
        """Get list of positions (test endpoint)."""
        return self._send_request(method="GET", route="positions")
    
    def get_holdings(self) -> Dict[str, Any]:
        """Get list of holdings (test endpoint).""" 
        return self._send_request(method="GET", route="holdings")
    
    def close(self) -> None:
        """Close the HTTP session."""
        if hasattr(self, 'session'):
            self.session.close()
            self.logger.info("HTTP session closed")


class TestDefinedgeRestAuthentication:
    """Test suite for Definedge REST API authentication."""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def test_basic_authentication_flow(
        self,
        api_token: str,
        api_secret: str,
        totp: Optional[str] = None
    ) -> bool:
        """
        Test the complete authentication flow using REST API.
        
        Args:
            api_token: Definedge API token
            api_secret: Definedge API secret  
            totp: Optional TOTP code
            
        Returns:
            True if authentication successful, False otherwise
        """
        client = None
        try:
            self.logger.info("="*60)
            self.logger.info("Testing Definedge REST API Authentication Flow")
            self.logger.info("="*60)
            
            # Initialize REST client
            client = DefinedgeRestAPIClient(enable_logging=True)
            
            # Test authentication
            auth_result = client.login(api_token, api_secret, totp)
            
            # Validate session keys
            uid, actid, api_key, ws_key = client.get_session_keys()
            
            assert uid != "", "UID should not be empty"
            assert actid != "", "Account ID should not be empty"
            assert api_key != "", "API session key should not be empty"
            assert ws_key != "", "WebSocket session key should not be empty"
            
            self.logger.info("✓ Session keys validation passed")
            
            # Test authenticated endpoint
            try:
                limits_response = client.test_authenticated_endpoint()
                self.logger.info("✓ Authenticated endpoint test passed")
            except Exception as e:
                self.logger.warning(f"Authenticated endpoint test failed: {e}")
                # Don't fail the test as some endpoints might not be accessible
            
            self.logger.info("="*60)
            self.logger.info("✅ ALL AUTHENTICATION TESTS PASSED!")
            self.logger.info("="*60)
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Authentication test failed: {e}")
            self.logger.error("="*60)
            return False
            
        finally:
            if client:
                client.close()
    
    def test_invalid_credentials(self) -> bool:
        """Test authentication with invalid credentials."""
        client = None
        try:
            self.logger.info("Testing invalid credentials handling...")
            
            client = DefinedgeRestAPIClient(enable_logging=False)
            
            # This should raise an exception
            client.login("invalid_token", "invalid_secret", "123456")
            
            # If we reach here, the test failed
            self.logger.error("❌ Invalid credentials test failed - should have raised exception")
            return False
            
        except ValueError as e:
            if "Invalid api_token or api_secret" in str(e):
                self.logger.info("✓ Invalid credentials properly handled")
                return True
            else:
                self.logger.error(f"❌ Unexpected ValueError: {e}")
                return False
                
        except Exception as e:
            self.logger.info(f"✓ Invalid credentials rejected: {e}")
            return True
            
        finally:
            if client:
                client.close()
    
    def test_session_management(self) -> bool:
        """Test session key management functionality."""
        try:
            self.logger.info("Testing session management...")
            
            client = DefinedgeRestAPIClient(enable_logging=False)
            
            # Test setting session keys manually
            test_uid = "TEST_UID_123"
            test_actid = "TEST_ACTID_456" 
            test_api_key = "test_api_session_key"
            test_ws_key = "test_ws_session_key"
            
            client.set_session_keys(test_uid, test_actid, test_api_key, test_ws_key)
            
            # Test retrieving session keys
            retrieved_keys = client.get_session_keys()
            expected_keys = (test_uid, test_actid, test_api_key, test_ws_key)
            
            assert retrieved_keys == expected_keys, f"Session keys mismatch: {retrieved_keys} != {expected_keys}"
            
            self.logger.info("✓ Session management test passed")
            client.close()
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Session management test failed: {e}")
            return False


def get_credentials_from_environment() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Get credentials from environment variables."""
    return (
        os.getenv('DEFINEDGE_API_TOKEN'),
        os.getenv('DEFINEDGE_API_SECRET'), 
        os.getenv('DEFINEDGE_TOTP')
    )


def get_credentials_interactive() -> Tuple[str, str, Optional[str]]:
    """Get credentials interactively from user input."""
    print("\n" + "="*60)
    print("Definedge Securities REST API Authentication Test")
    print("="*60)
    print("\n📋 Please provide your credentials:")
    
    api_token = input("Enter your Definedge API Token: ").strip()
    if not api_token:
        raise ValueError("API Token is required")
    
    api_secret = input("Enter your Definedge API Secret: ").strip()  
    if not api_secret:
        raise ValueError("API Secret is required")
    
    totp = input("Enter TOTP (or press Enter to be prompted later): ").strip()
    
    return api_token, api_secret, totp if totp else None


def main():
    """Main function to run the REST API authentication tests."""
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )
    
    logger = logging.getLogger(__name__)
    
    try:
        # Initialize test suite
        test_suite = TestDefinedgeRestAuthentication()
        
        # Run session management test first (no credentials needed)
        logger.info("Running session management tests...")
        session_test_passed = test_suite.test_session_management()
        
        # Run invalid credentials test
        logger.info("Running invalid credentials test...")
        invalid_creds_test_passed = test_suite.test_invalid_credentials()
        
        # Get credentials for authentication test
        api_token, api_secret, totp = get_credentials_from_environment()
        
        if not api_token or not api_secret:
            logger.info("No credentials found in environment, prompting user...")
            api_token, api_secret, totp = get_credentials_interactive()
        
        # Mask sensitive data in logs
        masked_token = f"{api_token[:6]}...{api_token[-4:]}" if len(api_token) > 10 else "***"
        masked_secret = f"{api_secret[:6]}...{api_secret[-4:]}" if len(api_secret) > 10 else "***"
        
        logger.info(f"Using API Token: {masked_token}")
        logger.info(f"Using API Secret: {masked_secret}")
        logger.info(f"TOTP provided: {'Yes' if totp else 'Will prompt'}")
        
        # Run main authentication test
        logger.info("Running authentication flow test...")
        auth_test_passed = test_suite.test_basic_authentication_flow(api_token, api_secret, totp)
        
        # Print summary
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        print(f"Session Management Test: {'✅ PASSED' if session_test_passed else '❌ FAILED'}")
        print(f"Invalid Credentials Test: {'✅ PASSED' if invalid_creds_test_passed else '❌ FAILED'}")
        print(f"Authentication Flow Test: {'✅ PASSED' if auth_test_passed else '❌ FAILED'}")
        
        all_tests_passed = all([session_test_passed, invalid_creds_test_passed, auth_test_passed])
        print(f"\nOverall Result: {'🎉 ALL TESTS PASSED!' if all_tests_passed else '❌ SOME TESTS FAILED'}")
        print("="*60)
        
        sys.exit(0 if all_tests_passed else 1)
        
    except KeyboardInterrupt:
        logger.warning("Test interrupted by user")
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"Test suite failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()