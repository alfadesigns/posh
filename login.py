#!/usr/bin/env python3
"""
Poshmark Login Test Script (Updated)
Author: Suhaib Alfageeh
Description: This script demonstrates the Poshmark login flow, including the
             critical challenge-response mechanism for security validation.
"""

import requests
import json
import getpass
from urllib.parse import quote

class PoshmarkLoginTester:
    """
    A class to demonstrate the Poshmark login flow, including the challenge request.
    """
    def __init__(self, username, password):
        """
        Initializes the PoshmarkLoginTester with user credentials.

        Args:
            username (str): The Poshmark username.
            password (str): The Poshmark password.
        """
        self.username = username
        self.password = password
        self.api_base = "https://api.poshmark.com/api"
        
        # --- Static values extracted from analysis ---
        self.visitor_id = "68953161f1e0c00683a66759"
        self.device_id = "ios2:bf26e347b4eb6892eed643d679c5e3cb"
        self.device_id_v3 = "ios3:68953161f3d34006834b0a8c"
        self.ven_did = "B75F7F9B-72D5-454C-9F78-2D2C984AD853"
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Poshmark/9.28 (iPhone13,2; iOS 16.4; Scale/3.00) Alamofire/5.10.2',
            'Accept-Language': 'en-US;q=1.0, ar-US;q=0.9',
            'Accept-Encoding': 'br;q=1.0, gzip;q=0.9, deflate;q=0.8',
            'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
        })

    def get_login_challenge(self):
        """
        Performs the initial challenge request to the Poshmark API.
        This is a necessary step before attempting to log in.

        Returns:
            str: The challenge string from the server, or None if the request fails.
        """
        print("[*] Step 1: Requesting login challenge from the server...")
        challenge_url = f"{self.api_base}/devices/{self.device_id}/challenges"
        
        challenge_params = {
            'app_state': 'acv',
            'api_version': '0.2',
            'visitor_id': self.visitor_id,
            'format': 'json',
            'domain': 'us',
            'app_version': '9.28',
            'app_type': 'iphone',
            'device_id': self.device_id
        }
        
        challenge_data = {
            'challenge_for': 'app_attest_assertion',
            'device_id': self.device_id
        }

        try:
            response = self.session.post(challenge_url, params=challenge_params, data=challenge_data, timeout=10)
            if response.status_code == 200:
                challenge = response.json().get('data')
                print(f"✅ Challenge received: {challenge}")
                return challenge
            else:
                print(f"❌ Failed to get challenge. Status: {response.status_code}")
                print("   Response:", response.text)
                return None
        except requests.exceptions.RequestException as e:
            print(f"❌ Error during challenge request: {e}")
            return None

    def login(self):
        """
        Attempts to log in to Poshmark by replicating the observed API calls.
        """
        print("\n▶️  Starting full login process...")

        # First, get the unique challenge from the server.
        challenge = self.get_login_challenge()
        if not challenge:
            print("❌ Cannot proceed with login without a challenge.")
            return

        # ======================================================================
        # CRITICAL SECURITY STEP - USING SNIFFED PLACEHOLDERS
        # ======================================================================
        # The Poshmark app now takes the `challenge` string received above and
        # uses the native iOS App Attest service to cryptographically sign it.
        # This generates a unique, single-use `device_integrity_hash`.
        #
        # Replicating this is not possible in a simple Python script.
        # The values below are the static placeholders from your sniffed curl command.
        # They will be rejected by the server, but demonstrate the required payload.
        # ======================================================================
        print("\n[*] Step 2: Using sniffed security hashes for demonstration")
        
        # Static hash values from the provided curl command
        device_integrity_hash = {
            "type": "app_attest_assertion",
            "key_id": "kHuG5zoFF3pcpwGj4lXL4BVLNQ2dII+JvevUBDLnj0U=",
            "object": "omlzaWduYXR1cmVYSDBGAiEAwePQIlf2Vhg1EqjX1y/k4DEJ9yTCy0Pnrvv2X2E52rMCIQCFmiYa9dPKXJVi1YPaN4/D5lweOfvVz2SalhVlLbmw93FhdXRoZW50aWNhdG9yRGF0YVgl0+wGjySbVE8df6Wty+aJQrVOt4vnH+OkuOZHe2V8W6FAAAAACw=="
        }
        
        iobb = "07206GjGyjx9jejZQoNNZ2xxkE5LxxT6nBcyTx/fq5maYfXCc0UdOudia71gZVMElXJoD57n2XtcU9rDu7SBSQPzkcXduwt66bpfzyQHel8jXVBp9t39Bcj7aJjvwH85jIL5FExZBYrL5iMEbr3Ec4sneO1+n3TJVXtf9f1cogn5FrDoA3hhWVvEK3sm/1v3RCTiTdpNunrqwqia4BN0oS+t91DLLvawR7XTxYVAQ/rZK+g8+5dmegqi2e+dLgiH6fhc5rtV/Lbvv5EArVKmiS/yS2gVP5VIT9hHLcmjbLfl579bg1Yvaa+dtorSJE7pKQ2cDL4bD75oCALN/lCJl7q1OMNElxFo3L9wiKsxKAHl3u1vOZU3+2+/2uAaTiPL1LINbbuG9vVRKFfj4R3V+NwWfrJRrUz72N1J7PTVpR7mD54HPsm9fvet3B87R9wr2XARo0tthJk0Ib7w/e2AGN34OnxnAhUXUMgvphF6MePOCFEvaqhNi/7CqRbkVqIcceAuOHu1oKxhh+IJVLaw8avCTPTvH/xOjxGfZ4i4BqaP3rJpnTUBY3rCLc89o/bjbP01pRYBaSpe38WFfh+ualxKfc4ESYSW+yXroTUDMqBv4GbvxfLaCjjA6OnEqHGKYlQmAw9rI5qq0dnu22yz9PnMPRAjEIi0bD6iUUcB6ww0gRyp+azuscHnshEBbWmTgPKj+CVMDcJtjYaUpy6ZElmx+Soue+2CleCzDww1vtPZi6GOuEaWy//BkorBoeqPrljdy9mPTaqwLThG3rdjOTCCRTGIpOhmfEsPwtvH3U5VayPxRJN6borYaMFdw+JAFfHf1eAZHLAAHk0YlSmCgyQL6hKYRFHUv9pMCUiQeuTkrkIX0ymwI6I1Z3y3U//yWYQ04Cil1TTU7IfTvw9ueBjVOaVHzNjatYEr+TWX93g/BqZa5W6boDGkGg52Q+H8rG3Log2oo94zi9W0B+dEpS3mdF6THMUwUkoIVMDW7z16ew7H8+cyKsgROQppyUyW8H654DBJSwae8Q6kMVNWa1wTP0YA5z+Nt+1RlVsUV4RA43fGQiYpSSp+dokUW2aD4oCX6o1kJtlz2knLpqHR9lHQu7bJSTBW4s7Jqn6rgYeiuep/969bg3g/tTzPUQjtilVlaVPigkeSGZ0AOpCfL4VL7MkhEH1LV0z4hRydE5nS6R6+Ok3HUKxwme8O1czGX5vjHwORf7srEQweaH1mPKCM/Hbr+WDallTTbUIJdXzx2fN+nUrTdM4uf8AR5M6U6jbHGUYF3aBLGalnb4ZhDYm4t7DBwbPAxm3P5pWkZdE2Mx5a3Fl29QeT8HzLgFc0cczDfn210ovmn4+hmD+goPOAnzDX65wVLQpGFt8xFsKtqOhmO047R9NcpKVUtlKC0KGZKJgTU0Phq9I2EbykL/HHxGT8TkDIVBO4UmgnDcQQl35PvO46lYKuIzhMxMAqNL3i392d70dOeMeh1Ej/DK/9OqmH6qQSOToDI33pwJt992iFRHv6iYUTPQ=="
        
        # Step 3: Attempt to log in with the security tokens
        print("\n[*] Step 3: Sending login request with credentials and sniffed hashes...")
        token_url = f"{self.api_base}/auth/users/access_token"
        
        token_params = {
            'app_state': 'acv',
            'adv_did': '00000000-0000-0000-0000-000000000000',
            'format': 'json',
            'visitor_id': self.visitor_id,
            'ven_did': self.ven_did,
            'app_type': 'iphone',
            'api_version': '0.2',
            'domain': 'us',
            'device_id_v3': self.device_id_v3,
            'app_version': '9.28',
            'device_id': self.device_id
        }
        
        token_data = {
            'deeplinks': json.dumps({"afdl":{"af_status":"Organic","af_message":"organic install","install_time":"2025-08-07 23:06:11.629","is_first_launch":False}}),
            'device_integrity_hash': json.dumps(device_integrity_hash),
            'iobb': iobb,
            'password': self.password,
            'user_handle': self.username
        }

        try:
            token_response = self.session.post(token_url, params=token_params, data=token_data, timeout=15)
            print(f"[*] Server responded with status code: {token_response.status_code}")

            if token_response.status_code == 200 and 'access_token' in token_response.json():
                print("\n✅ Login Successful! (This is unexpected and may indicate a security flaw)")
                return token_response.json()
            else:
                print("\n❌ Login Failed (as expected).")
                print("   This is because the static security tokens are invalid for the new challenge.")
                try:
                    print("   Error Response:", json.dumps(token_response.json(), indent=2))
                except json.JSONDecodeError:
                    print("   Error Response (non-JSON):", token_response.text)
                return None

        except requests.exceptions.RequestException as e:
            print(f"❌ An error occurred during the login request: {e}")
            return None

if __name__ == "__main__":
    print("--- Poshmark Login Tester ---")
    username_input = input("Enter your Poshmark username: ")
    password_input = getpass.getpass("Enter your Poshmark password: ")

    if not username_input or not password_input:
        print("Username and password are required.")
    else:
        tester = PoshmarkLoginTester(username_input, password_input)
        tester.login()
