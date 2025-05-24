from uuid import uuid4
from utils import make_response, handle_exceptions, logger
import random
import datetime
from dataclasses import dataclass
import json
import boto3
from decimal import Decimal  # Add this import
from dataclasses import asdict
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("many-cards-prod-main-table")
kms = boto3.client("kms")


@dataclass
class CardDetails:
    number: str
    cvv: str
    expiry: str
    card_type: str
    network: str


class CardGenerator:
    # BIN ranges for different card types and currencies
    BIN_RANGES = {
        "naira": {
            "visa": ["4", "47"],
            "mastercard": ["51", "52", "53", "54", "55", "2221", "2222", "2223"],
        },
        "dollar": {
            "visa": ["4"],
            "mastercard": ["51", "52", "53", "54", "55", "2221", "2222", "2223"],
        },
        "pound": {
            "visa": ["4"],
            "mastercard": ["51", "52", "53", "54", "55", "2221", "2222", "2223"],
        },
    }

    @staticmethod
    def generate_card(currency: str, card_network: str = "visa") -> CardDetails:
        """Generate valid payment card details"""
        # Validate inputs
        if currency not in CardGenerator.BIN_RANGES:
            raise ValueError(
                f"Invalid currency. Must be one of: {list(CardGenerator.BIN_RANGES.keys())}"
            )

        if card_network not in CardGenerator.BIN_RANGES[currency]:
            raise ValueError(
                f"Invalid network for {currency}. Must be one of: {list(CardGenerator.BIN_RANGES[currency].keys())}"
            )

        # Generate card number
        bin_prefix = random.choice(CardGenerator.BIN_RANGES[currency][card_network])
        card_number = CardGenerator._generate_card_number(bin_prefix)

        # Generate other details
        cvv = CardGenerator._generate_cvv()
        expiry = CardGenerator._generate_expiry_date()

        return CardDetails(
            number=card_number,
            cvv=cvv,
            expiry=expiry,
            card_type="virtual",
            network=card_network,
        )

    @staticmethod
    def _generate_card_number(bin_prefix: str, length: int = 16) -> str:
        """Generate valid card number using Luhn algorithm"""
        # Generate the base number
        number = bin_prefix
        remaining_length = length - len(number) - 1  # -1 for check digit

        # Add random digits
        number += "".join([str(random.randint(0, 9)) for _ in range(remaining_length)])

        # Calculate check digit
        check_digit = CardGenerator._calculate_luhn_check_digit(number)
        return number + str(check_digit)

    @staticmethod
    def _calculate_luhn_check_digit(partial_number: str) -> int:
        """Calculate the Luhn check digit"""
        total = 0
        for i, digit in enumerate(partial_number[::-1]):
            n = int(digit)
            if i % 2 == 0:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return (10 - (total % 10)) % 10

    @staticmethod
    def _generate_cvv(length: int = 3) -> str:
        """Generate random CVV"""
        return "".join([str(random.randint(0, 9)) for _ in range(length)])

    @staticmethod
    def _generate_expiry_date(years_valid: int = 3) -> str:
        """Generate future expiry date (MM/YY format)"""
        today = datetime.datetime.now()
        expiry = today + datetime.timedelta(days=365 * years_valid)
        return expiry.strftime("%m/%y")


def _encrypt_card_details(card: CardDetails) -> dict:
    """Encrypt sensitive card details using KMS"""
    try:
        return {
            "number": kms.encrypt(
                KeyId="alias/many-cards-data-key", Plaintext=card.number.encode()
            )["CiphertextBlob"],
            "cvv": kms.encrypt(
                KeyId="alias/many-cards-data-key", Plaintext=card.cvv.encode()
            )["CiphertextBlob"],
        }
    except ClientError as e:
        raise Exception(f"Encryption failed: {str(e)}")


def _mask_card_number(number: str) -> str:
    """Mask card number for display (first 4 and last 4 visible)"""
    return number[:4] + "*" * (len(number) - 8) + number[-4:]


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
            logger.info(f"Full event structure: {json.dumps(event, indent=2)}")
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

        # Generate card details
        currency = body["currency"].lower()
        network = body.get("card_network", "visa").lower()

        card = CardGenerator.generate_card(currency, network)

        # Encrypt sensitive data
        encrypted_card = _encrypt_card_details(card)

        # Store in DynamoDB
        # In your main function, modify the card_item creation:
        card_item = {
            "pk": f"USER#{user_id}",  # Partition key
            "sk": f"CARD#{str(uuid4())[:8]}",  # Sort key
            "user_id": user_id,
            **asdict(card),
            "encrypted_card_number": encrypted_card["number"],
            "encrypted_cvv": encrypted_card["cvv"],
            "is_active": True,
            "created_at": datetime.datetime.now().isoformat(),
            "balance": Decimal("0.00"),
            "currency": currency,
            "card_type": card.card_type,
            "network": card.network,
            "expiry": card.expiry,
            "masked_number": _mask_card_number(card.number),
        }

        table.put_item(Item=card_item)

        # Prepare success response
        return make_response(
            201,
            {
                "error": False,
                "success": True,
                "message": "Card generated successfully",
                "data": {
                    "card_id": card_item["sk"],
                    "user_id": user_id,
                    "currency": currency,
                    "card_type": card.card_type,
                    "network": card.network,
                    "masked_number": _mask_card_number(card.number),
                    "expiry": card.expiry,
                    "is_active": True,
                    "created_at": card_item["created_at"],
                    "balance": float(
                        card_item["balance"]
                    ),  # Convert back to float for JSON
                },
            },
        )

    except ValueError as e:
        return make_response(
            400, {"error": True, "success": False, "message": str(e), "data": None}
        )
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return make_response(
            500,
            {
                "error": True,
                "success": False,
                "message": "Internal server error",
                "data": None,
            },
        )


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
