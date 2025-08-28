#!/usr/bin/env python3
"""
Simple Definedge Securities REST API Authentication Example

This is a minimal implementation showing exactly how to authenticate with 
Definedge Securities using direct REST API calls without the pyintegrate SDK.

Based on the pyintegrate source code analysis, this replicates the exact
authentication flow using standard HTTP libraries.
"""

import requests
import json
from hashlib import sha256
from typing import Dict, Any, Optional


def authenticate_definedge(api_token: str, api_secret: str, totp: Optional[str] = None) -> Dict[str, Any]:
    """
    Authenticate with Definedge Securities using direct REST API calls.
    
    This function replicates the authentication flow from the pyintegrate library:
    1. GET /login/{api_token} with api_secret header -> get otp_token
    2. POST /token with otp_token, otp, and auth_code -> get session keys
    
    Args:
        api_token: Your Definedge API token
        api_secret: Your Definedge API secret  
        totp: Optional TOTP code (will prompt if not provided)
        
    Returns:
        Dictionary containing session keys and user information
        
    Raises:
        Exception: If authentication fails
    """
    # API URLs (from pyintegrate source code)
    LOGIN_URL = "https://signin.definedgesecurities.com/auth/realms/debroking/dsbpkc/"
    
    # Create requests session for connection pooling
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'DefinedgeRestClient/1.0',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    })
    
    try:
        print("🔐 Starting Definedge Securities Authentication...")
        
        # Step 1: Get OTP token
        print("📱 Step 1: Getting OTP token...")
        
        step1_url = f"{LOGIN_URL}login/{api_token}"
        headers = {"api_secret": api_secret}
        
        print(f"   GET {step1_url}")
        print(f"   Headers: api_secret={api_secret[:6]}...")
        
        response = session.get(step1_url, headers=headers, timeout=30)
        response.raise_for_status()
        
        step1_data = response.json()
        print(f"   Response: {json.dumps(step1_data, indent=2)}")
        
        otp_token = step1_data.get("otp_token")
        if not otp_token:
            raise Exception("Failed to get otp_token from response")
        
        print(f"✅ OTP Token received: {otp_token}")
        
        # Step 2: Get TOTP/OTP from user if not provided
        if not totp:
            totp = input("📲 Enter your 6-digit TOTP/OTP: ").strip()
        
        if not totp or len(totp) != 6:
            raise Exception("Valid 6-digit TOTP/OTP is required")
        
        print(f"📱 Using TOTP: {totp}")
        
        # Step 3: Calculate authentication code (exact formula from pyintegrate)
        print("🔐 Calculating authentication code...")
        
        auth_string = f"{otp_token}{totp}{api_secret}"
        auth_code = sha256(auth_string.encode("utf-8")).hexdigest()
        
        print(f"   Auth string: {otp_token} + {totp} + {api_secret[:6]}...")
        print(f"   Auth code: {auth_code}")
        
        # Step 4: Get session keys
        print("🔑 Step 2: Getting session keys...")
        
        step2_url = f"{LOGIN_URL}token"
        payload = {
            "otp_token": otp_token,
            "otp": totp,
            "ac": auth_code
        }
        
        print(f"   POST {step2_url}")
        print(f"   Payload: {json.dumps(payload, indent=2)}")
        
        response = session.post(step2_url, json=payload, timeout=30)
        response.raise_for_status()
        
        step2_data = response.json()
        print(f"   Response: {json.dumps(step2_data, indent=2)}")
        
        # Step 5: Extract session keys
        if step2_data.get("stat") != "Ok":
            error_msg = step2_data.get("emsg", "Unknown authentication error")
            raise Exception(f"Authentication failed: {error_msg}")
        
        session_data = {
            "uid": step2_data.get("uid"),
            "actid": step2_data.get("actid"),
            "api_session_key": step2_data.get("api_session_key"), 
            "ws_session_key": step2_data.get("susertoken"),  # Note: susertoken is the WebSocket key
            "email": step2_data.get("email"),
            "username": step2_data.get("uname"),
            "broker_name": step2_data.get("brkname"),
            "branch_id": step2_data.get("brnchid"),
            "last_access_time": step2_data.get("lastaccesstime"),
            "exchanges": step2_data.get("exarr", []),
            "products": step2_data.get("prarr", []),
            "order_types": step2_data.get("orarr", [])
        }
        
        # Validate essential session data
        required_keys = ["uid", "actid", "api_session_key", "ws_session_key"]
        for key in required_keys:
            if not session_data.get(key):
                raise Exception(f"Missing required session data: {key}")
        
        print("🎉 Authentication successful!")
        print(f"   👤 User ID: {session_data['uid']}")
        print(f"   🏦 Account ID: {session_data['actid']}")
        print(f"   🔑 API Session Key: {session_data['api_session_key'][:20]}...")
        print(f"   📡 WebSocket Key: {session_data['ws_session_key'][:20]}...")
        print(f"   📧 Email: {session_data['email']}")
        print(f"   🏢 Broker: {session_data['broker_name']}")
        
        return session_data
        
    except requests.exceptions.RequestException as e:
        print(f"❌ HTTP Request failed: {e}")
        raise
    except Exception as e:
        print(f"❌ Authentication failed: {e}")
        raise
    finally:
        session.close()


def test_authenticated_api_call(session_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Test an authenticated API call to verify the session is working.
    
    Args:
        session_data: Session data from authenticate_definedge()
        
    Returns:
        Response from the API call
    """
    # Base API URL (from pyintegrate source)
    BASE_URL = "https://integrate.definedgesecurities.com/dart/v1/"
    
    session = requests.Session()
    
    try:
        print("\n🧪 Testing authenticated API call...")
        
        # Use the limits endpoint to test authentication
        url = f"{BASE_URL}limits"
        headers = {
            "Authorization": session_data["api_session_key"],
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        print(f"   GET {url}")
        print(f"   Authorization: {session_data['api_session_key'][:20]}...")
        
        response = session.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        print(f"✅ Authenticated API call successful!")
        print(f"   Response: {json.dumps(data, indent=2)}")
        
        return data
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Authenticated API call failed: {e}")
        raise
    finally:
        session.close()


def place_test_order(session_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Example of placing a test order using REST API.
    
    Args:
        session_data: Session data from authenticate_definedge()
        
    Returns:
        Order response
    """
    BASE_URL = "https://integrate.definedgesecurities.com/dart/v1/"
    
    session = requests.Session()
    
    try:
        print("\n📝 Placing test order...")
        
        # Example order payload (modify as needed)
        order_payload = {
            "exchange": "NSE",
            "tradingsymbol": "SBIN-EQ",
            "quantity": "1",
            "price": "0",
            "product_type": "INTRADAY",
            "order_type": "BUY",
            "price_type": "MARKET"
        }
        
        url = f"{BASE_URL}placeorder"
        headers = {
            "Authorization": session_data["api_session_key"],
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        print(f"   POST {url}")
        print(f"   Payload: {json.dumps(order_payload, indent=2)}")
        
        response = session.post(url, json=order_payload, headers=headers, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        print(f"✅ Order placed successfully!")
        print(f"   Response: {json.dumps(data, indent=2)}")
        
        return data
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Order placement failed: {e}")
        raise
    finally:
        session.close()


def get_orders(session_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get list of orders using REST API.
    
    Args:
        session_data: Session data from authenticate_definedge()
        
    Returns:
        Orders list response
    """
    BASE_URL = "https://integrate.definedgesecurities.com/dart/v1/"
    
    session = requests.Session()
    
    try:
        print("\n📋 Getting orders list...")
        
        url = f"{BASE_URL}orders"
        headers = {
            "Authorization": session_data["api_session_key"],
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        print(f"   GET {url}")
        
        response = session.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        print(f"✅ Orders retrieved successfully!")
        print(f"   Response: {json.dumps(data, indent=2)}")
        
        return data
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Getting orders failed: {e}")
        raise
    finally:
        session.close()


def get_positions(session_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get positions using REST API.
    
    Args:
        session_data: Session data from authenticate_definedge()
        
    Returns:
        Positions response
    """
    BASE_URL = "https://integrate.definedgesecurities.com/dart/v1/"
    
    session = requests.Session()
    
    try:
        print("\n📊 Getting positions...")
        
        url = f"{BASE_URL}positions"
        headers = {
            "Authorization": session_data["api_session_key"],
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        print(f"   GET {url}")
        
        response = session.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        print(f"✅ Positions retrieved successfully!")
        print(f"   Response: {json.dumps(data, indent=2)}")
        
        return data
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Getting positions failed: {e}")
        raise
    finally:
        session.close()


def main():
    """Main function to demonstrate the REST API authentication and usage."""
    import os
    
    print("=" * 80)
    print("🚀 DEFINEDGE SECURITIES REST API AUTHENTICATION TEST")
    print("=" * 80)
    
    # Get credentials from environment variables or user input
    api_token = os.getenv('DEFINEDGE_API_TOKEN')
    api_secret = os.getenv('DEFINEDGE_API_SECRET')
    totp = os.getenv('DEFINEDGE_TOTP')
    
    if not api_token:
        api_token = input("Enter your Definedge API Token: ").strip()
    
    if not api_secret:
        api_secret = input("Enter your Definedge API Secret: ").strip()
    
    if not api_token or not api_secret:
        print("❌ API Token and Secret are required!")
        return
    
    try:
        # Step 1: Authenticate
        session_data = authenticate_definedge(api_token, api_secret, totp)
        
        # Step 2: Test authenticated API calls
        print("\n" + "=" * 60)
        print("🧪 TESTING AUTHENTICATED API CALLS")
        print("=" * 60)
        
        # Test 1: Get account limits
        try:
            limits_data = test_authenticated_api_call(session_data)
        except Exception as e:
            print(f"⚠️  Limits API test failed: {e}")
        
        # Test 2: Get orders
        try:
            orders_data = get_orders(session_data)
        except Exception as e:
            print(f"⚠️  Orders API test failed: {e}")
        
        # Test 3: Get positions
        try:
            positions_data = get_positions(session_data)
        except Exception as e:
            print(f"⚠️  Positions API test failed: {e}")
        
        # Optional: Place a test order (uncomment if you want to test)
        # WARNING: This will place a real order! Use only in test environment
        # try:
        #     order_response = place_test_order(session_data)
        # except Exception as e:
        #     print(f"⚠️  Order placement test failed: {e}")
        
        print("\n" + "=" * 80)
        print("🎉 REST API AUTHENTICATION TEST COMPLETED SUCCESSFULLY!")
        print("=" * 80)
        print("\n📋 SESSION SUMMARY:")
        print(f"   👤 User ID: {session_data['uid']}")
        print(f"   🏦 Account ID: {session_data['actid']}")
        print(f"   📧 Email: {session_data['email']}")
        print(f"   🏢 Broker: {session_data['broker_name']}")
        print(f"   🔗 Available Exchanges: {', '.join(session_data['exchanges'])}")
        
        print("\n✅ You can now use the session keys to make authenticated API calls!")
        print(f"   API Session Key: {session_data['api_session_key']}")
        print(f"   WebSocket Key: {session_data['ws_session_key']}")
        
    except Exception as e:
        print(f"\n❌ Authentication test failed: {e}")
        return


if __name__ == "__main__":
    main()