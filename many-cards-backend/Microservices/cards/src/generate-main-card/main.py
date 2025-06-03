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
SUDO_ENVIRONMENT = parameters.get_parameter(
    f"/{APP_NAME}/{STAGE}/SUDO_ENVIRONMENT", transform="json"
)


class SudoClient:
    def __init__(self):
        self.environment = SUDO_ENVIRONMENT or "sandbox"
        self.base_url = (
            "https://api.sandbox.sudo.cards"
            if self.environment == "sandbox"
            else "https://api.sudo.cards"
        )
        self.api_key = SUDO_API_KEY
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def create_or_get_customer(self, user_data: dict) -> dict:
        """Create or retrieve a customer in Sudo"""
        url = f"{self.base_url}/customers"

        # Check if customer already exists by searching with email
        search_url = f"{self.base_url}/customers"
        search_params = {"email": user_data.get("email")}

        try:
            # First try to find existing customer
            search_response = requests.get(
                search_url, headers=self.headers, params=search_params
            )

            if search_response.status_code == 200:
                customers = search_response.json().get("data", [])
                if customers:
                    logger.info(f"Found existing customer: {customers[0].get('id')}")
                    return customers[0]

            # Create new customer if not found
            payload = {
                "type": "individual",
                "name": f"{user_data.get('first_name')} {user_data.get('last_name')}",
                "email": user_data.get("email"),
                "phoneNumber": user_data.get("phone_number"),
                "identity": {
                    "type": "individual",
                    "firstName": user_data.get("first_name"),
                    "lastName": user_data.get("last_name"),
                    "dateOfBirth": user_data.get("date_of_birth"),
                    "country": "NG",  # Nigeria
                },
                "billingAddress": {
                    "line1": user_data.get("address"),
                    "city": user_data.get("city"),
                    "state": user_data.get("state"),
                    "country": "NG",
                    "postalCode": user_data.get("postal_code"),
                },
            }

            response = requests.post(url, json=payload, headers=self.headers)
            response.raise_for_status()
            customer_data = response.json()
            logger.info(f"Created new customer: {customer_data.get('id')}")
            return customer_data

        except requests.exceptions.RequestException as e:
            logger.error(f"Sudo customer API error: {str(e)}")
            if hasattr(e.response, "text"):
                logger.error(f"Error response: {e.response.text}")
            raise Exception("Failed to create/get customer with Sudo")

    def create_funding_source(self, customer_id: str, currency: str = "NGN") -> dict:
        """Create a funding source for the customer"""
        url = f"{self.base_url}/accounts"

        payload = {
            "customerId": customer_id,
            "type": "current",
            "currency": currency,
            "accountName": f"Main Account - {currency}",
        }

        try:
            response = requests.post(url, json=payload, headers=self.headers)
            response.raise_for_status()
            funding_source = response.json()
            logger.info(f"Created funding source: {funding_source.get('id')}")
            return funding_source
        except requests.exceptions.RequestException as e:
            logger.error(f"Sudo funding source API error: {str(e)}")
            if hasattr(e.response, "text"):
                logger.error(f"Error response: {e.response.text}")
            raise Exception("Failed to create funding source with Sudo")

    def get_or_create_funding_source(
        self, customer_id: str, currency: str = "NGN"
    ) -> dict:
        """Get existing funding source or create new one"""
        try:
            # Try to get existing funding sources
            url = f"{self.base_url}/accounts"
            params = {"customerId": customer_id, "currency": currency}

            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()

            accounts = response.json().get("data", [])
            if accounts:
                logger.info(f"Found existing funding source: {accounts[0].get('id')}")
                return accounts[0]

            # Create new funding source if none exists
            return self.create_funding_source(customer_id, currency)

        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting funding sources: {str(e)}")
            # Fallback to creating new funding source
            return self.create_funding_source(customer_id, currency)

    def create_card(
        self, customer_id: str, funding_source_id: str, card_data: dict
    ) -> dict:
        """Create a virtual card via Sudo API"""
        url = f"{self.base_url}/cards"

        currency = card_data.get("currency")

        # Default spending limits based on currency
        default_limits = [
            {"amount": 50000, "interval": "daily"},  # 50k NGN daily
            {"amount": 200000, "interval": "monthly"},  # 200k NGN monthly
        ]

        if currency == "USD":
            default_limits = [
                {"amount": 100, "interval": "daily"},  # $100 daily
                {"amount": 500, "interval": "monthly"},  # $500 monthly
            ]

        payload = {
            "customerId": customer_id,
            "fundingSourceId": funding_source_id,
            "type": "virtual",
            "brand": "Verve",  # Default to Verve for NGN
            "currency": currency,
            "issuerCountry": "NGA",
            "status": "active",
            "metadata": json.dumps(card_data.get("metadata", {})),
            "spendingControls": {
                "allowedCategories": [],
                "blockedCategories": [],
                "channels": {
                    "atm": False,  # Virtual cards don't support ATM
                    "pos": False,  # Virtual cards don't support POS
                    "web": True,
                    "mobile": True,
                },
                "spendingLimits": card_data.get("spending_limits", default_limits),
            },
        }

        try:
            response = requests.post(url, json=payload, headers=self.headers)
            response.raise_for_status()
            card_response = response.json()
            logger.info(f"Created card: {card_response.get('id')}")
            return card_response
        except requests.exceptions.RequestException as e:
            logger.error(f"Sudo card API error: {str(e)}")
            if hasattr(e.response, "text"):
                logger.error(f"Error response: {e.response.text}")
            raise Exception("Failed to create card with Sudo")

    def get_card_details(self, card_id: str) -> dict:
        """Get card details including PAN and CVV"""
        url = f"{self.base_url}/cards/{card_id}"

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Sudo card details API error: {str(e)}")
            raise Exception("Failed to fetch card details")


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

        currency = body["currency"].upper()

        # Validate supported currencies for Sudo
        supported_currencies = ["NGN", "USD", "GBP"]  # Add more as supported by Sudo
        if currency not in supported_currencies:
            return make_response(
                400,
                {
                    "error": True,
                    "success": False,
                    "message": f"Unsupported currency: {currency}. Supported: {', '.join(supported_currencies)}",
                    "data": None,
                },
            )

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

        # Create Sudo client
        sudo = SudoClient()

        # Create/get customer in Sudo
        customer_response = sudo.create_or_get_customer(
            {
                "first_name": claims.get("given_name"),
                "last_name": claims.get("family_name"),
                "email": claims.get("email"),
                "phone": body.get("phone_number"),
                "date_of_birth": body.get("birthdate"),
                "address": body.get("address"),
                "city": body.get("city", "Lagos"),
                "state": body.get("state", "Lagos"),
                "postal_code": body.get("postal_code"),
            }
        )

        customer_id = customer_response["id"]

        # Get or create funding source
        funding_source = sudo.get_or_create_funding_source(customer_id, currency)
        funding_source_id = funding_source["id"]

        # Create the card
        card_response = sudo.create_card(
            customer_id=customer_id,
            funding_source_id=funding_source_id,
            card_data={
                "currency": currency,
                "metadata": {
                    "user_id": user_id,
                    "created_via": "lambda",
                    "environment": sudo.environment,
                },
                "spending_limits": body.get("spending_limits"),  # Allow custom limits
            },
        )

        # Extract card details
        card_number = card_response.get("number")  # Full PAN
        cvv = card_response.get("cvv")
        last_four = card_number[-4:] if card_number else "****"

        # Encrypt sensitive data
        try:
            encrypted_pan = None
            encrypted_cvv = None

            if card_number:
                encrypted_pan = kms.encrypt(
                    KeyId="alias/many-cards-data-key",
                    Plaintext=card_number.encode(),
                )["CiphertextBlob"]

            if cvv:
                encrypted_cvv = kms.encrypt(
                    KeyId="alias/many-cards-data-key",
                    Plaintext=cvv.encode(),
                )["CiphertextBlob"]

        except Exception as e:
            logger.error(f"Failed to encrypt PAN/CVV: {str(e)}")
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
            "sudo_card_id": card_response["id"],
            "sudo_customer_id": customer_id,
            "sudo_funding_source_id": funding_source_id,
            "is_active": True,
            "created_at": datetime.datetime.now().isoformat(),
            "balance": Decimal("0.00"),
            "currency": currency,
            "encrypted_pan": encrypted_pan,
            "encrypted_cvv": encrypted_cvv,
            "card_type": "virtual",
            "expiry": card_response.get("expirationDate", ""),
            "last_four": last_four,
            "card_status": card_response.get("status", "active"),
            "brand": card_response.get("brand", "Verve"),
            "issuer_country": card_response.get("issuerCountry", "NGA"),
        }

        table.put_item(Item=card_item)

        # Prepare success response (don't return sensitive data)
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
                    "masked_number": f"****{last_four}",
                    "expiry": card_response.get("expirationDate", ""),
                    "brand": card_response.get("brand", "Verve"),
                    "is_active": True,
                    "created_at": card_item["created_at"],
                    "balance": float(card_item["balance"]),
                    "card_status": card_response.get("status", "active"),
                    "sudo_card_id": card_response["id"],
                    "issuer_country": card_response.get("issuerCountry", "NGA"),
                    "spending_limits": card_response.get("spendingControls", {}).get(
                        "spendingLimits", []
                    ),
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
                "data": {"error_details": str(e)},
            },
        )


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
