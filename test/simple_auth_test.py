#!/usr/bin/env python3
"""
Simple Definedge Securities Authentication Test Script

This script provides a quick way to test authentication with the Definedge Securities API.
It can be run standalone or integrated into your testing pipeline.

Usage:
    python simple_auth_test.py
    
Environment Variables:
    DEFINEDGE_API_TOKEN - Your Definedge API token
    DEFINEDGE_API_SECRET - Your Definedge API secret  
    DEFINEDGE_TOTP - Optional: Your TOTP code (if not set, will prompt)
"""

import os
import sys
import logging
from typing import Optional

try:
    from integrate import ConnectToIntegrate
except ImportError:
    print("Error: 'integrate' package not found. Please install the Definedge Python SDK:")
    print("pip install pyintegrate")
    sys.exit(1)


def setup_logging():
    """Configure logging for the test."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def get_credentials() -> tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Get authentication credentials from environment variables or user input.
    
    Returns:
        Tuple of (api_token, api_secret, totp)
    """
    # Try to get credentials from environment variables
    api_token = os.getenv('DEFINEDGE_API_TOKEN')
    api_secret = os.getenv('DEFINEDGE_API_SECRET')
    totp = os.getenv('DEFINEDGE_TOTP')
    
    # If not in environment, prompt user
    if not api_token:
        api_token = input("Enter your Definedge API Token: ").strip()
        if not api_token:
            print("Error: API Token is required")
            return None, None, None
    
    if not api_secret:
        api_secret = input("Enter your Definedge API Secret: ").strip()
        if not api_secret:
            print("Error: API Secret is required")
            return None, None, None
    
    # TOTP is optional - will be prompted by the SDK if not provided
    if not totp:
        totp_input = input("Enter TOTP (leave empty to be prompted later): ").strip()
        totp = totp_input if totp_input else None
    
    return api_token, api_secret, totp


def test_authentication(api_token: str, api_secret: str, totp: Optional[str] = None) -> bool:
    """
    Test authentication with Definedge Securities API.
    
    Args:
        api_token: Definedge API token
        api_secret: Definedge API secret
        totp: Optional TOTP code
        
    Returns:
        True if authentication successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    
    try:
        logger.info("Initializing Definedge Securities connection...")
        
        # Initialize the Definedge client
        client = ConnectToIntegrate(
            logging=True,
            timeout=30
        )
        
        logger.info(f"Login URL: {client.login_url}")
        logger.info(f"Base URL: {client.base_url}")
        
        logger.info("Starting authentication process...")
        
        # Perform authentication
        client.login(
            api_token=api_token,
            api_secret=api_secret,
            totp=totp
        )
        
        # Check if authentication was successful
        if client.uid and client.actid and client.api_session_key:
            logger.info("✓ Authentication successful!")
            logger.info(f"✓ User ID: {client.uid}")
            logger.info(f"✓ Account ID: {client.actid}")
            logger.info(f"✓ API Session Key: {client.api_session_key[:20]}...")
            logger.info(f"✓ WebSocket Session Key: {client.ws_session_key[:20]}...")
            
            # Test session key retrieval
            uid, actid, api_key, ws_key = client.get_session_keys()
            logger.info("✓ Session keys retrieved successfully")
            
            # Validate session keys match
            assert uid == client.uid, "UID mismatch in session keys"
            assert actid == client.actid, "Account ID mismatch in session keys"
            assert api_key == client.api_session_key, "API session key mismatch"
            assert ws_key == client.ws_session_key, "WebSocket session key mismatch"
            
            logger.info("✓ All authentication tests passed!")
            return True
            
        else:
            logger.error("✗ Authentication failed - missing session data")
            return False
            
    except ValueError as e:
        if "Invalid api_token or api_secret" in str(e):
            logger.error("✗ Authentication failed: Invalid credentials")
            logger.error("Please check your API token and secret")
        elif "No OTP/TOTP provided" in str(e):
            logger.error("✗ Authentication failed: TOTP required but not provided")
        else:
            logger.error(f"✗ Authentication failed: {e}")
        return False
        
    except KeyboardInterrupt:
        logger.warning("Authentication interrupted by user")
        return False
        
    except Exception as e:
        logger.error(f"✗ Unexpected error during authentication: {e}")
        logger.error(f"Error type: {type(e).__name__}")
        return False


def print_usage_info():
    """Print usage information and setup instructions."""
    print("\n" + "="*60)
    print("Definedge Securities Authentication Test")
    print("="*60)
    print("\n📋 Setup Instructions:")
    print("1. Get your API credentials from:")
    print("   https://myaccount.definedgesecurities.com/mydetails")
    print("   (Click 'Show My API Secret')")
    print("\n2. Enable TOTP at:")
    print("   https://myaccount.definedgesecurities.com/security")
    print("\n3. Set environment variables (optional):")
    print("   export DEFINEDGE_API_TOKEN='your_token_here'")
    print("   export DEFINEDGE_API_SECRET='your_secret_here'")
    print("   export DEFINEDGE_TOTP='your_6_digit_totp'  # Optional")
    print("\n4. Install the SDK if not already installed:")
    print("   pip install pyintegrate")
    print("\n" + "="*60 + "\n")


def main():
    """Main function to run the authentication test."""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    print_usage_info()
    
    # Get credentials
    api_token, api_secret, totp = get_credentials()
    
    if not api_token or not api_secret:
        logger.error("Cannot proceed without API credentials")
        sys.exit(1)
    
    # Mask credentials in logs for security
    masked_token = f"{api_token[:6]}...{api_token[-4:]}" if len(api_token) > 10 else "***"
    masked_secret = f"{api_secret[:6]}...{api_secret[-4:]}" if len(api_secret) > 10 else "***"
    
    logger.info(f"Using API Token: {masked_token}")
    logger.info(f"Using API Secret: {masked_secret}")
    logger.info(f"TOTP provided: {'Yes' if totp else 'Will prompt if needed'}")
    
    # Run authentication test
    success = test_authentication(api_token, api_secret, totp)
    
    if success:
        print("\n🎉 Authentication test completed successfully!")
        print("Your Definedge Securities API connection is working correctly.")
        sys.exit(0)
    else:
        print("\n❌ Authentication test failed.")
        print("Please check your credentials and try again.")
        sys.exit(1)


if __name__ == "__main__":
    main()