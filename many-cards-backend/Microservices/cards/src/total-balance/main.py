import json
import boto3
import requests
from boto3.dynamodb.conditions import Key
from decimal import Decimal
from typing import Dict, List
from os import getenv
from aws_lambda_powertools.utilities import parameters
from utils import handle_exceptions, logger, make_response

# Environment variables
STAGE = getenv("STAGE")
APP_NAME = getenv("APP_NAME")

# Get API key from parameter store
EXCHANGE_API_KEY = parameters.get_parameter(
    f"/{APP_NAME}/{STAGE}/EXCHANGE_API_KEY", decrypt=True
)

# AWS clients
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("many-cards-prod-main-table")


# Supported currencies
SUPPORTED_CURRENCIES = {
    "USD": "US Dollar",
    "GBP": "British Pound",
    "NGN": "Nigerian Naira",
}


class CurrencyConverter:
    """Currency conversion utility class"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://v6.exchangerate-api.com/v6"

    def get_exchange_rates(self, base_currency: str) -> Dict:
        """Get exchange rates for a base currency"""
        try:
            url = f"{self.base_url}/{self.api_key}/latest/{base_currency.upper()}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            data = response.json()

            if data.get("result") != "success":
                raise Exception(f"API Error: {data.get('error-type', 'Unknown error')}")

            return data

        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            raise Exception("Failed to fetch exchange rates")
        except Exception as e:
            logger.error(f"Exchange rate API error: {str(e)}")
            raise

    def convert_currency(
        self, amount: float, from_currency: str, to_currency: str
    ) -> Dict:
        """Convert amount from one currency to another"""
        try:
            from_currency = from_currency.upper()
            to_currency = to_currency.upper()

            # Validate currencies
            if from_currency not in SUPPORTED_CURRENCIES:
                raise ValueError(f"Unsupported source currency: {from_currency}")
            if to_currency not in SUPPORTED_CURRENCIES:
                raise ValueError(f"Unsupported target currency: {to_currency}")

            # If same currency, return original amount
            if from_currency == to_currency:
                return {
                    "original_amount": amount,
                    "converted_amount": amount,
                    "from_currency": from_currency,
                    "to_currency": to_currency,
                    "exchange_rate": 1.0,
                }

            # Get exchange rates using source currency as base
            rates_data = self.get_exchange_rates(from_currency)
            rates = rates_data["conversion_rates"]

            if to_currency not in rates:
                raise ValueError(f"Exchange rate not available for {to_currency}")

            exchange_rate = rates[to_currency]
            converted_amount = amount * exchange_rate

            return {
                "original_amount": amount,
                "converted_amount": round(converted_amount, 2),
                "from_currency": from_currency,
                "to_currency": to_currency,
                "exchange_rate": exchange_rate,
                "timestamp": rates_data.get("time_last_update_utc"),
            }

        except Exception as e:
            logger.error(f"Currency conversion failed: {str(e)}")
            raise


def get_user_main_cards(user_id: str) -> List[Dict]:
    """Get all main cards for a user"""
    try:
        response = table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
            ExpressionAttributeValues={
                ":pk": f"USER#{user_id}",
                ":sk_prefix": "CARD#",
            },
        )

        return response.get("Items", [])

    except Exception as e:
        logger.error(f"Failed to fetch main cards for user {user_id}: {str(e)}")
        raise


def calculate_total_balance(cards: List[Dict], target_currency: str = "USD") -> dict:
    """Calculate total balance of all cards in specified currency"""
    try:
        converter = CurrencyConverter(EXCHANGE_API_KEY)
        total_balance = 0.0
        card_balances = []

        for card in cards:
            card_balance = float(card.get("balance", Decimal("0.00")))
            card_currency = card.get("currency", "USD").upper()

            # Convert to target currency
            if card_balance > 0:
                conversion_result = converter.convert_currency(
                    card_balance, card_currency, target_currency
                )
                converted_balance = conversion_result["converted_amount"]
            else:
                converted_balance = 0.0

            total_balance += converted_balance

            card_balances.append(
                {
                    "card_id": card.get("sk"),
                    "original_balance": card_balance,
                    "original_currency": card_currency,
                    "converted_balance": converted_balance,
                    "target_currency": target_currency,
                }
            )

        return {
            "total_balance": round(total_balance, 2),
            "target_currency": target_currency,
            "card_count": len(cards),
            "card_balances": card_balances,
        }

    except Exception as e:
        logger.error(f"Failed to calculate total balance: {str(e)}")
        raise


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context=None):
    """Lambda handler for getting user's total balance"""
    try:
        # Extract user authentication
        request_context = event.get("requestContext", {})
        authorizer = request_context.get("authorizer", {})
        claims = authorizer.get("claims", {}) or authorizer or {}

        if not isinstance(claims, dict) or not claims:
            return make_response(
                401,
                {
                    "error": True,
                    "message": "Unauthorized - No claims found",
                    "data": None,
                },
            )

        # Extract user_id
        user_id = claims.get("sub") or claims.get("cognito:username")
        if not user_id:
            return make_response(
                401,
                {
                    "error": True,
                    "message": "Unauthorized - No user identifier",
                    "data": None,
                },
            )

        # Parse request parameters
        query_params = event.get("queryStringParameters") or {}
        target_currency = query_params.get("currency", "NGN").upper()

        # Validate target currency
        if target_currency not in SUPPORTED_CURRENCIES:
            return make_response(
                400,
                {
                    "error": True,
                    "message": f"Unsupported currency: {target_currency}. Supported: {', '.join(SUPPORTED_CURRENCIES.keys())}",
                    "data": None,
                },
            )

        # Get user's main cards
        main_cards = get_user_main_cards(user_id)

        if not main_cards:
            return make_response(
                200,
                {
                    "error": False,
                    "success": True,
                    "message": "No main cards found for user",
                    "data": {
                        "total_balance": 0.0,
                        "target_currency": target_currency,
                        "card_count": 0,
                        "card_balances": [],
                    },
                },
            )

        # Calculate total balance
        balance_result = calculate_total_balance(main_cards, target_currency)

        return make_response(
            200,
            {
                "error": False,
                "success": True,
                "message": f"Total balance calculated successfully in {target_currency}",
                "data": balance_result,
            },
        )

    except Exception as e:
        logger.error(f"User balance calculation error: {str(e)}")
        return make_response(
            500, {"error": True, "message": "Internal server error", "data": None}
        )


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    """Handler specifically for user balance calculation"""
    return main(event, context)
