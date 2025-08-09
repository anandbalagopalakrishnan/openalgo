import http.client
import json
import urllib.parse
from utils.logging import get_logger

logger = get_logger(__name__)

def authenticate_broker(api_token, api_secret, otp):
    """
    Authenticate with DefinedGe Securities using 3-step process:
    1. Login with API token/secret to get OTP token
    2. Verify OTP to get JWT
    3. Exchange JWT for session key
    """
    try:
        # Step 1: Login with API credentials to get OTP token
        step1_response = login_step1(api_token, api_secret)
        if not step1_response:
            return None, "Failed to initiate login"

        otp_token = step1_response.get('otp_token')
        if not otp_token:
            return None, "Failed to get OTP token"

        # Step 2: Verify OTP to get JWT
        jwt_response = login_step2(otp_token, otp, api_secret)
        if not jwt_response:
            return None, "Failed to verify OTP"

        # Step 3: Exchange JWT for session key
        session_response = login_step3(jwt_response)
        if not session_response:
            return None, "Failed to get session key"

        api_session_key = session_response.get('api_session_key')
        susertoken = session_response.get('susertoken')

        if not api_session_key:
            return None, "Failed to get API session key"

        # Return auth string in format expected by OpenAlgo
        auth_string = f"{api_session_key}:::{susertoken}:::{api_token}"
        return auth_string, None

    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return None, str(e)

def login_step1(api_token, api_secret):
    """Step 1: Login with API credentials"""
    try:
        conn = http.client.HTTPSConnection("signin.definedgesecurities.com")
        headers = {
            'api_secret': api_secret
        }

        url = f"/auth/realms/debroking/dsbpkc/login/{api_token}"
        conn.request("GET", url, headers=headers)

        res = conn.getresponse()
        data = res.read().decode("utf-8")

        if res.status == 200:
            return json.loads(data)
        else:
            logger.error(f"Step 1 failed: {data}")
            return None

    except Exception as e:
        logger.error(f"Step 1 error: {e}")
        return None

def login_step2(otp_token, otp, client_secret):
    """Step 2: Verify OTP to get JWT"""
    try:
        conn = http.client.HTTPSConnection("signin.definedgesecurities.com")

        payload = {
            "client_id": "TRTP",
            "grant_type": "password",
            "client_secret": client_secret,
            "otp_token": otp_token,
            "otp": otp
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        encoded_payload = urllib.parse.urlencode(payload)
        conn.request("POST", "/auth/realms/debroking/dsbpkc/token", encoded_payload, headers)

        res = conn.getresponse()
        data = res.read().decode("utf-8")

        if res.status == 200:
            return json.loads(data)
        else:
            logger.error(f"Step 2 failed: {data}")
            return None

    except Exception as e:
        logger.error(f"Step 2 error: {e}")
        return None

def login_step3(jwt_data):
    """Step 3: Exchange JWT for session key"""
    try:
        conn = http.client.HTTPSConnection("integrate.definedgesecurities.com")

        headers = {
            'Content-Type': 'application/json'
        }

        payload = json.dumps(jwt_data)
        conn.request("POST", "/dart/v1/token", payload, headers)

        res = conn.getresponse()
        data = res.read().decode("utf-8")

        if res.status == 200:
            return json.loads(data)
        else:
            logger.error(f"Step 3 failed: {data}")
            return None

    except Exception as e:
        logger.error(f"Step 3 error: {e}")
        return None
