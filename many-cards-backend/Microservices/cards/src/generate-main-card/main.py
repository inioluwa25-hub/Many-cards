from uuid import uuid4
from utils import make_response, handle_exceptions, logger
import datetime
import requests
import json
import boto3
from decimal import Decimal
from os import getenv
from aws_lambda_powertools.utilities import parameters
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("many-cards-prod-main-table")
kms = boto3.client("kms")

# Environment variables
STAGE = getenv("STAGE")
APP_NAME = getenv("APP_NAME")

# Get API credentials from parameter store
SUDO_API_KEY = parameters.get_parameter(f"/{APP_NAME}/{STAGE}/SUDO_SECRET_KEY")


class SudoClient:
    def __init__(self):
        self.base_url = "https://api.sandbox.sudo.cards"
        self.headers = {
            "Authorization": f"Bearer {SUDO_API_KEY}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def create_customer(self, user_data: dict) -> dict:
        """Create a customer in Sudo sandbox"""
        url = f"{self.base_url}/customers"
        payload = {
            "type": "individual",
            "status": "active",
            "individual": {
                "firstName": user_data.get("first_name"),
                "lastName": user_data.get("last_name"),
            },
            "billingAddress": {
                "line1": "123 Main St",
                "city": "Lagos",
                "state": "Lagos",
                "postalCode": "100001",
                "country": "NG",
            },
        }

        try:
            response = requests.post(url, json=payload, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Sudo customer creation error: {str(e)}")
            raise Exception("Failed to create customer")

    def create_account(self, customer_id: str, currency: str = "NGN") -> dict:
        """Create a wallet account in Sudo sandbox"""
        url = f"{self.base_url}/accounts"
        payload = {
            "customerId": customer_id,
            "type": "wallet",
            "currency": currency,
            "status": "active",
        }

        try:
            response = requests.post(url, json=payload, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Sudo account creation error: {str(e)}")
            raise Exception("Failed to create account")

    def fund_account(self, account_id: str, amount: float, currency: str) -> dict:
        """Fund an account in Sudo sandbox (simulated funding)"""
        url = f"{self.base_url}/simulator/accounts/{account_id}/credit"
        payload = {
            "amount": amount,
            "currency": currency,
            "description": "Initial funding",
        }

        try:
            response = requests.post(url, json=payload, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Sudo account funding error: {str(e)}")
            raise Exception("Failed to fund account")

    def create_card(self, customer_id: str, account_id: str, currency: str) -> dict:
        """Create a virtual card in Sudo sandbox"""
        url = f"{self.base_url}/cards"
        payload = {
            "customerId": customer_id,
            "accountId": account_id,
            "type": "virtual",
            "currency": currency,
            "brand": "Verve",
            "status": "active",
            "spendingControls": {
                "spendingLimits": [
                    {"amount": 500000, "interval": "daily"},
                    {"amount": 1500000, "interval": "monthly"},
                ]
            },
        }

        try:
            response = requests.post(url, json=payload, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Sudo card creation error: {str(e)}")
            raise Exception("Failed to create card")

    def get_card_details(self, card_id: str) -> dict:
        """Get card details including PAN and CVV"""
        url = f"{self.base_url}/cards/{card_id}/show"

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Sudo card details error: {str(e)}")
            raise Exception("Failed to get card details")


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context=None):
    try:
        # Extract user info from event
        request_context = event.get("requestContext", {})
        authorizer = request_context.get("authorizer") or {}
        claims = authorizer.get("claims") or authorizer

        if not isinstance(claims, dict) or not claims:
            return make_response(
                401, {"error": True, "message": "Unauthorized - No claims found"}
            )

        user_id = claims.get("sub") or claims.get("cognito:username")
        if not user_id:
            return make_response(
                401, {"error": True, "message": "Unauthorized - No user identifier"}
            )

        # Parse request body
        try:
            body = json.loads(event.get("body", "{}"))
        except json.JSONDecodeError:
            return make_response(
                400, {"error": True, "message": "Invalid JSON payload"}
            )

        # Validate currency
        currency = body.get("currency", "NGN").upper()
        if currency not in ["NGN", "USD", "GBP"]:
            return make_response(
                400,
                {
                    "error": True,
                    "message": "Unsupported currency. Supported: NGN, USD, GBP",
                },
            )

        # Check for existing cards
        try:
            response = table.query(
                KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
                ExpressionAttributeValues={
                    ":pk": f"USER#{user_id}",
                    ":sk_prefix": "CARD#",
                },
            )
            if any(
                card.get("currency") == currency and card.get("is_active")
                for card in response.get("Items", [])
            ):
                return make_response(
                    400,
                    {
                        "error": True,
                        "message": f"User already has an active {currency} card",
                    },
                )
        except ClientError as e:
            logger.error(f"DynamoDB error: {str(e)}")
            return make_response(
                500, {"error": True, "message": "Error checking existing cards"}
            )

        # Initialize Sudo client
        sudo = SudoClient()

        # 1. Create customer
        customer = sudo.create_customer(
            {
                "first_name": claims.get("given_name", "User"),
                "last_name": claims.get("family_name", "Name"),
            }
        )
        customer_id = customer["id"]

        # 2. Create account
        account = sudo.create_account(customer_id, currency)
        account_id = account["id"]

        # 3. Fund account (sandbox simulation)
        initial_funding = float(
            body.get("initial_funding", 1000 if currency == "NGN" else 10)
        )
        sudo.fund_account(account_id, initial_funding, currency)

        # 4. Create card
        card = sudo.create_card(customer_id, account_id, currency)
        card_id = card["id"]

        # 5. Get card details (PAN/CVV)
        card_details = sudo.get_card_details(card_id)
        pan = card_details.get("pan")
        cvv = card_details.get("cvv")
        expiry = card_details.get("expiry")

        # Encrypt sensitive data
        encrypted_pan = (
            kms.encrypt(KeyId="alias/many-cards-data-key", Plaintext=pan.encode())[
                "CiphertextBlob"
            ]
            if pan
            else None
        )

        encrypted_cvv = (
            kms.encrypt(KeyId="alias/many-cards-data-key", Plaintext=cvv.encode())[
                "CiphertextBlob"
            ]
            if cvv
            else None
        )

        # Generate internal card ID
        internal_card_id = str(uuid4())[:8]

        # Store in DynamoDB
        card_item = {
            "pk": f"USER#{user_id}",
            "sk": f"CARD#{internal_card_id}",
            "card_id": internal_card_id,
            "user_id": user_id,
            "sudo_card_id": card_id,
            "sudo_customer_id": customer_id,
            "sudo_account_id": account_id,
            "is_active": True,
            "created_at": datetime.datetime.now().isoformat(),
            "balance": Decimal(str(initial_funding)),
            "currency": currency,
            "encrypted_pan": encrypted_pan,
            "encrypted_cvv": encrypted_cvv,
            "card_type": "virtual",
            "expiry": expiry,
            "last_four": pan[-4:] if pan else "****",
            "card_status": "active",
            "brand": "Verve",
            "issuer_country": "NGA",
            "initial_funding": Decimal(str(initial_funding)),
        }

        table.put_item(Item=card_item)

        # Return success response
        return make_response(
            201,
            {
                "error": False,
                "success": True,
                "message": "Card created successfully",
                "data": {
                    "card_id": internal_card_id,
                    "currency": currency,
                    "masked_number": f"****{pan[-4:]}" if pan else "****",
                    "expiry": expiry,
                    "balance": float(initial_funding),
                    "sudo_card_id": card_id,
                    "sudo_account_id": account_id,
                },
            },
        )

    except Exception as e:
        logger.error(f"Card creation error: {str(e)}")
        return make_response(
            500, {"error": True, "message": "Failed to create card", "details": str(e)}
        )


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
