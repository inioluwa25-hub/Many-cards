import json
import boto3
import requests
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

    def get_exchange_rates(self, base_currency: str) -> dict:
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
    ) -> dict:
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


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context=None):
    """Lambda handler for currency conversion"""
    try:
        # Parse request body
        try:
            body = json.loads(event.get("body", "{}") or "{}")
        except json.JSONDecodeError:
            return make_response(
                400,
                {
                    "error": True,
                    "message": "Invalid JSON in request body",
                    "data": None,
                },
            )

        # Extract parameters
        amount = body.get("amount")
        from_currency = body.get("from_currency")
        to_currency = body.get("to_currency")

        # Validate required parameters
        if amount is None:
            return make_response(
                400,
                {
                    "error": True,
                    "message": "Missing required parameter: amount",
                    "data": None,
                },
            )

        if not from_currency:
            return make_response(
                400,
                {
                    "error": True,
                    "message": "Missing required parameter: from_currency",
                    "data": None,
                },
            )

        if not to_currency:
            return make_response(
                400,
                {
                    "error": True,
                    "message": "Missing required parameter: to_currency",
                    "data": None,
                },
            )

        # Validate amount
        try:
            amount = float(amount)
            if amount < 0:
                raise ValueError("Amount must be positive")
        except ValueError:
            return make_response(
                400,
                {
                    "error": True,
                    "message": "Invalid amount. Must be a positive number",
                    "data": None,
                },
            )

        # Perform conversion
        converter = CurrencyConverter(EXCHANGE_API_KEY)
        result = converter.convert_currency(amount, from_currency, to_currency)

        return make_response(
            200,
            {
                "error": False,
                "success": True,
                "message": "Currency conversion successful",
                "data": result,
            },
        )

    except ValueError as e:
        return make_response(400, {"error": True, "message": str(e), "data": None})
    except Exception as e:
        logger.error(f"Currency conversion error: {str(e)}")
        return make_response(
            500, {"error": True, "message": "Internal server error", "data": None}
        )


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    """Handler specifically for currency conversion"""
    return main(event, context)
