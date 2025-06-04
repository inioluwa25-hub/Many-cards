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

    def generate_test_card(self) -> dict:
        """Generate a test card using Sudo's simulator endpoint"""
        url = f"{self.base_url}/cards/simulator/generate"

        try:
            logger.info("Generating test card using simulator")
            response = requests.get(url, headers=self.headers, timeout=10)

            logger.info(
                f"Test card generation response: {response.status_code} - {response.text}"
            )

            if response.status_code == 200:
                card_data = response.json()
                logger.info(f"Generated test card: {card_data}")
                return card_data
            else:
                error_msg = (
                    f"Test card generation failed with status {response.status_code}"
                )
                if response.text:
                    error_msg += f": {response.text}"
                raise Exception(error_msg)

        except requests.exceptions.RequestException as e:
            logger.error(f"Test card generation error: {str(e)}")
            if hasattr(e, "response") and e.response is not None:
                logger.error(f"Error response status: {e.response.status_code}")
                logger.error(f"Error response text: {e.response.text}")
            raise Exception(f"Failed to generate test card: {str(e)}")


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

        # Validate currency (for our internal tracking, though test cards may have their own)
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

            # Count active cards for this currency
            active_cards = [
                card
                for card in response.get("Items", [])
                if card.get("currency") == currency and card.get("is_active")
            ]

            if active_cards:
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

        # Create Sudo client and generate test card
        sudo = SudoClient()

        try:
            # Generate test card directly
            test_card = sudo.generate_test_card()

            # Extract card details from test card response
            # The exact field names may vary based on Sudo's API response structure
            pan = (
                test_card.get("pan")
                or test_card.get("number")
                or test_card.get("cardNumber")
            )
            cvv = (
                test_card.get("cvv")
                or test_card.get("cvc")
                or test_card.get("securityCode")
            )
            expiry_month = test_card.get("expiryMonth") or test_card.get("expMonth")
            expiry_year = test_card.get("expiryYear") or test_card.get("expYear")

            # Format expiry date
            if expiry_month and expiry_year:
                expiry = f"{expiry_month:02d}/{str(expiry_year)[-2:]}"  # MM/YY format
            else:
                expiry = test_card.get("expiry", "12/25")  # fallback

            # Generate card ID if not provided
            card_id = test_card.get("id", str(uuid4()))

            # Get card brand/type from test card or set default
            brand = test_card.get("brand", "Verve")
            card_type = test_card.get("type", "virtual")

            # Set default test balance
            initial_funding = float(body.get("initial_funding", 1000))

            logger.info(
                f"Generated test card with PAN ending: {pan[-4:] if pan else 'N/A'}"
            )

        except Exception as e:
            logger.error(f"Test card generation failed: {str(e)}")
            return make_response(
                500,
                {
                    "error": True,
                    "success": False,
                    "message": "Failed to generate test card",
                    "data": {"error_details": str(e)},
                },
            )

        # Encrypt sensitive data
        encrypted_pan = None
        encrypted_cvv = None

        if pan:
            try:
                encrypted_pan = kms.encrypt(
                    KeyId="alias/many-cards-data-key", Plaintext=pan.encode()
                )["CiphertextBlob"]
            except Exception as e:
                logger.error(f"Failed to encrypt PAN: {str(e)}")

        if cvv:
            try:
                encrypted_cvv = kms.encrypt(
                    KeyId="alias/many-cards-data-key", Plaintext=cvv.encode()
                )["CiphertextBlob"]
            except Exception as e:
                logger.error(f"Failed to encrypt CVV: {str(e)}")

        # Generate internal card ID
        internal_card_id = str(uuid4())[:8]

        # Store in DynamoDB
        card_item = {
            "pk": f"USER#{user_id}",
            "sk": f"CARD#{internal_card_id}",
            "card_id": internal_card_id,
            "user_id": user_id,
            "sudo_card_id": card_id,
            "sudo_customer_id": "test_customer",  # Not needed for test cards
            "sudo_account_id": "test_account",  # Not needed for test cards
            "is_active": True,
            "created_at": datetime.datetime.now().isoformat(),
            "balance": Decimal(str(initial_funding)),
            "currency": currency,
            "encrypted_pan": encrypted_pan,
            "encrypted_cvv": encrypted_cvv,
            "card_type": card_type,
            "expiry": expiry,
            "last_four": pan[-4:] if pan else "****",
            "card_status": "active",
            "brand": brand,
            "issuer_country": "NGA",
            "initial_funding": Decimal(str(initial_funding)),
            "is_test_card": True,  # Mark as test card
            "test_card_data": test_card,  # Store original test card response for reference
        }

        try:
            table.put_item(Item=card_item)
            logger.info(f"Successfully stored card {internal_card_id} in DynamoDB")
        except Exception as e:
            logger.error(f"Failed to store card in DynamoDB: {str(e)}")
            return make_response(
                500,
                {
                    "error": True,
                    "success": False,
                    "message": "Failed to store card data",
                    "data": {"error_details": str(e)},
                },
            )

        # Return success response
        return make_response(
            201,
            {
                "error": False,
                "success": True,
                "message": "Test card created successfully",
                "data": {
                    "card_id": internal_card_id,
                    "currency": currency,
                    "masked_number": f"****{pan[-4:]}" if pan else "****",
                    "expiry": expiry,
                    "balance": float(initial_funding),
                    "brand": brand,
                    "card_type": card_type,
                    "is_test_card": True,
                    "sudo_card_id": card_id,
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
                "details": str(e),
            },
        )


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
