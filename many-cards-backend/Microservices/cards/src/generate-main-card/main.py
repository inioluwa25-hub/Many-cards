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

    def create_sudo_account(
        self, user_id: str, email: str, currency: str, phone_number: str = None
    ) -> dict:
        """Create a new Sudo account for the user"""
        url = f"{self.base_url}/accounts"

        # Use provided phone or default for testing
        phone = phone_number or "+2348000000000"

        payload = {
            "type": "wallet",
            "currency": currency,  # Default to NGN, can be modified based on requirements
            "accountName": f"User {user_id[:8]}",  # Truncate for cleaner display
            "phoneNumber": phone,
            "emailAddress": email,
        }

        try:
            logger.info(f"Creating Sudo account for user {user_id}")
            response = requests.post(
                url, json=payload, headers=self.headers, timeout=10
            )

            logger.info(
                f"Account creation response: {response.status_code} - {response.text}"
            )

            if response.status_code in [200, 201]:
                account_data = response.json()
                logger.info(
                    f"Created Sudo account: {account_data.get('data', {}).get('id')}"
                )
                return account_data
            else:
                error_msg = (
                    f"Account creation failed with status {response.status_code}"
                )
                if response.text:
                    error_msg += f": {response.text}"
                raise Exception(error_msg)

        except requests.exceptions.RequestException as e:
            logger.error(f"Sudo account creation error: {str(e)}")
            if hasattr(e, "response") and e.response is not None:
                logger.error(f"Error response status: {e.response.status_code}")
                logger.error(f"Error response text: {e.response.text}")
            raise Exception(f"Failed to create Sudo account: {str(e)}")

    def get_existing_account(self, user_id: str) -> str:
        """Check if user already has a Sudo account stored in DynamoDB"""
        try:
            response = table.query(
                KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
                ExpressionAttributeValues={
                    ":pk": f"USER#{user_id}",
                    ":sk_prefix": "ACCOUNT#",
                },
                Limit=1,
            )

            accounts = response.get("Items", [])
            if accounts:
                account_id = accounts[0].get("sudo_account_id")
                if account_id and account_id != "test_account":
                    logger.info(
                        f"Found existing account for user {user_id}: {account_id}"
                    )
                    return account_id

        except Exception as e:
            logger.warning(f"Error checking existing accounts: {str(e)}")

        return None

    def store_account_info(self, user_id: str, account_data: dict) -> None:
        """Store Sudo account information in DynamoDB"""
        try:
            account_info = {
                "pk": f"USER#{user_id}",
                "sk": f"ACCOUNT#{account_data.get('data', {}).get('id')}",
                "user_id": user_id,
                "sudo_account_id": account_data.get("data", {}).get("id"),
                "account_name": account_data.get("data", {}).get("accountName"),
                "account_type": account_data.get("data", {}).get("type"),
                "currency": account_data.get("data", {}).get("currency"),
                "status": account_data.get("data", {}).get("status"),
                "created_at": datetime.datetime.now().isoformat(),
                "account_data": account_data,  # Store full response for reference
            }

            table.put_item(Item=account_info)
            logger.info(f"Stored account info for user {user_id}")

        except Exception as e:
            logger.error(f"Failed to store account info: {str(e)}")
            # Don't raise here as the account was created successfully


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
        email = claims.get("email")
        phone_number = claims.get("phone_number")

        if not user_id:
            return make_response(
                401, {"error": True, "message": "Unauthorized - No user identifier"}
            )

        if not email:
            return make_response(
                400,
                {
                    "error": True,
                    "message": "User email is required for account creation",
                },
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

        # Create Sudo client
        sudo = SudoClient()

        # Get or create Sudo account
        sudo_account_id = None
        try:
            # Check for existing account first
            existing_account_id = sudo.get_existing_account(user_id)

            if existing_account_id:
                sudo_account_id = existing_account_id
                logger.info(f"Using existing Sudo account: {sudo_account_id}")
            else:
                # Create new account
                logger.info(f"Creating new Sudo account for user {user_id}")
                account_data = sudo.create_sudo_account(
                    user_id, email, currency, phone_number
                )
                sudo_account_id = account_data.get("data", {}).get("_id")

                if not sudo_account_id:
                    raise Exception("Failed to get account ID from Sudo response")

                # Store account info for future reference
                sudo.store_account_info(user_id, account_data)
                logger.info(f"Created new Sudo account: {sudo_account_id}")

        except Exception as e:
            logger.error(f"Sudo account creation/retrieval failed: {str(e)}")
            # For testing, we can fall back to a test account
            if STAGE in ["test", "dev", "staging"]:
                sudo_account_id = "test_account"
                logger.warning("Using test account ID for testing environment")
            else:
                return make_response(
                    500,
                    {
                        "error": True,
                        "success": False,
                        "message": "Failed to create/retrieve Sudo account",
                        "data": {"error_details": str(e)},
                    },
                )

        # Generate test card
        try:
            test_card = sudo.generate_test_card()

            # Extract card details from test card response
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
            "sudo_account_id": sudo_account_id,  # Now using real account ID
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
                    "sudo_account_id": sudo_account_id,
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
