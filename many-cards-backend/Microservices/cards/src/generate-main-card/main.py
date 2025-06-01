from uuid import uuid4
from utils import make_response, handle_exceptions, logger
import datetime
import requests
from requests.auth import HTTPBasicAuth
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
MARQETA_APP_TOKEN = parameters.get_parameter(f"/{APP_NAME}/{STAGE}/MARQETA_APP_TOKEN")
MARQETA_ACCESS_TOKEN = parameters.get_parameter(
    f"/{APP_NAME}/{STAGE}/MARQETA_ACCESS_TOKEN"
)
MARQETA_CARD_PRODUCT_TOKEN = parameters.get_parameter(
    f"/{APP_NAME}/{STAGE}/MARQETA_CARD_PRODUCT_TOKEN"
)


class MarqetaClient:
    def __init__(self):
        self.base_url = "https://sandbox-api.marqeta.com/v3"  # Remove trailing slash
        self.app_token = MARQETA_APP_TOKEN
        self.access_token = MARQETA_ACCESS_TOKEN

    def create_or_get_user(self, user_data: dict) -> dict:
        """Create or retrieve a user in Marqeta"""
        url = f"{self.base_url}/users"
        headers = {"Content-Type": "application/json"}
        auth = HTTPBasicAuth(self.app_token, self.access_token)

        payload = {
            "first_name": user_data.get("first_name", "User"),
            "last_name": user_data.get("last_name", "Name"),
            "email": user_data.get("email"),
            "token": user_data.get(
                "user_token", str(uuid4())
            ),  # Use provided token or generate one
        }

        try:
            response = requests.post(url, json=payload, headers=headers, auth=auth)

            if response.status_code == 409:  # User already exists
                # Get existing user
                user_token = payload["token"]
                get_response = requests.get(
                    f"{self.base_url}/users/{user_token}", headers=headers, auth=auth
                )
                get_response.raise_for_status()
                return get_response.json()

            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            logger.error(f"Marqeta user API error: {str(e)}")
            raise Exception("Failed to create/get user with Marqeta")

    def create_card(self, user_token: str, card_data: dict) -> dict:
        """Create a real, transaction-capable card via Marqeta API"""
        url = f"{self.base_url}/cards"
        headers = {"Content-Type": "application/json"}
        auth = HTTPBasicAuth(self.app_token, self.access_token)

        payload = {
            "user_token": user_token,
            "card_product_token": MARQETA_CARD_PRODUCT_TOKEN,
            **card_data,
        }

        try:
            response = requests.post(url, json=payload, headers=headers, auth=auth)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Marqeta card API error: {str(e)}")
            raise Exception("Failed to create card with Marqeta")

    def get_card_details(self, card_token: str) -> dict:
        """Get PAN and CVV immediately after card creation (one-time access)"""
        url = f"{self.base_url}/cards/{card_token}/showpan"
        headers = {"Content-Type": "application/json"}
        auth = HTTPBasicAuth(self.app_token, self.access_token)

        try:
            response = requests.get(url, headers=headers, auth=auth)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Marqeta showpan API error: {str(e)}")
            raise Exception("Failed to fetch card details")

    def get_card_cvv(self, card_token: str) -> str:
        """Get CVV for a card (separate from PAN)"""
        url = f"{self.base_url}/cards/{card_token}/showcvv"
        headers = {"Content-Type": "application/json"}
        auth = HTTPBasicAuth(self.app_token, self.access_token)

        try:
            response = requests.get(url, headers=headers, auth=auth)
            response.raise_for_status()
            return response.json().get("cvv_number")
        except requests.exceptions.RequestException as e:
            logger.error(f"Marqeta showcvv API error: {str(e)}")
            raise Exception("Failed to fetch CVV")


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context=None):
    try:
        request_context = event.get("requestContext", {})
        authorizer = request_context.get("authorizer") or {}

        try:
            body = json.loads(event.get("body", "{}") or "{}")
        except json.JSONDecodeError:
            body = {}

        claims = authorizer.get("claims") or authorizer

        if not isinstance(claims, dict) or not claims:
            logger.error("No valid claims found in event")
            return make_response(
                401,
                {
                    "error": True,
                    "success": False,
                    "message": "Unauthorized - No claims found",
                    "data": None,
                },
            )

        # Extract user_id from claims
        user_id = claims.get("sub") or claims.get("cognito:username")
        if not user_id:
            logger.error("No user identifier found in claims")
            return make_response(
                401,
                {
                    "error": True,
                    "success": False,
                    "message": "Unauthorized - No user identifier",
                    "data": None,
                },
            )

        # Validate required fields
        if "currency" not in body:
            return make_response(
                400,
                {
                    "error": True,
                    "success": False,
                    "message": "Missing required field: currency",
                    "data": None,
                },
            )

        currency = body["currency"].upper()  # Keep uppercase for consistency

        # Check for existing card of the same currency
        try:
            response = table.query(
                KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
                ExpressionAttributeValues={
                    ":pk": f"USER#{user_id}",
                    ":sk_prefix": "CARD#",
                },
            )

            existing_cards = response.get("Items", [])

            # Check if user already has a card with this currency
            for card in existing_cards:
                if card.get("currency", "").upper() == currency and card.get(
                    "is_active", True
                ):
                    return make_response(
                        400,
                        {
                            "error": True,
                            "success": False,
                            "message": f"User already has an active {currency} card",
                            "data": {
                                "existing_card_id": card.get("sk").replace("CARD#", ""),
                                "currency": currency,
                            },
                        },
                    )

        except ClientError as e:
            logger.error(f"DynamoDB query error: {str(e)}")
            return make_response(
                500,
                {
                    "error": True,
                    "success": False,
                    "message": "Error checking existing cards",
                    "data": None,
                },
            )

        # Create Marqeta client
        marqeta = MarqetaClient()

        # Create/get user in Marqeta
        user_response = marqeta.create_or_get_user(
            {
                "first_name": claims.get("given_name", "User"),
                "last_name": claims.get("family_name", "Name"),
                "email": claims.get("email"),
                "user_token": user_id,  # Use Cognito user_id as Marqeta user token
            }
        )

        # Create the card
        card_response = marqeta.create_card(
            user_token=user_response["token"],
            card_data={
                "metadata": {
                    "currency": currency,
                    "user_id": user_id,
                },
            },
        )

        # After getting card_response
        try:
            # Get PAN
            pan = card_response.get("pan")  # Already in response

            # Get CVV separately
            cvv = marqeta.get_card_cvv(card_response["token"])

            # Encrypt both
            encrypted_pan = (
                kms.encrypt(
                    KeyId="alias/many-cards-data-key",
                    Plaintext=pan.encode(),
                )["CiphertextBlob"]
                if pan
                else None
            )

            encrypted_cvv = (
                kms.encrypt(
                    KeyId="alias/many-cards-data-key",
                    Plaintext=cvv.encode(),
                )["CiphertextBlob"]
                if cvv
                else None
            )

        except Exception as e:
            logger.error(f"Failed to store PAN/CVV: {str(e)}")
            encrypted_pan = None
            encrypted_cvv = None

        # Generate card ID for our system
        card_id = str(uuid4())[:8]

        # Store card details in DynamoDB
        card_item = {
            "pk": f"USER#{user_id}",
            "sk": f"CARD#{card_id}",
            "card_id": card_id,
            "user_id": user_id,
            "marqeta_card_token": card_response["token"],
            "marqeta_user_token": user_response["token"],
            "is_active": True,
            "created_at": datetime.datetime.now().isoformat(),
            "balance": Decimal("0.00"),
            "currency": currency,
            "encrypted_pan": encrypted_pan,
            "encrypted_cvv": encrypted_cvv,
            "card_type": "virtual",
            "expiry": card_response["expiration"],
            "last_four": card_response["last_four"],
            "card_status": card_response["state"],
        }

        table.put_item(Item=card_item)

        # Prepare success response
        return make_response(
            201,
            {
                "error": False,
                "success": True,
                "message": "Card created successfully",
                "data": {
                    "card_id": card_id,
                    "user_id": user_id,
                    "currency": currency,
                    "card_type": "virtual",
                    "masked_number": f"****{card_response['last_four']}",
                    "expiry": card_response["expiration"],
                    "is_active": True,
                    "created_at": card_item["created_at"],
                    "balance": float(card_item["balance"]),
                    "card_status": card_response["state"],
                    "marqeta_card_token": card_response["token"],
                },
            },
        )

    except Exception as e:
        logger.error(f"Card creation error: {str(e)}")
        return make_response(
            500,
            {
                "error": True,
                "success": False,
                "message": "Failed to create card",
                "data": None,
            },
        )


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
