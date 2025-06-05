from decimal import Decimal
from utils import make_response, handle_exceptions, logger
import json
import boto3
from botocore.exceptions import ClientError
from os import getenv

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("many-cards-prod-main-table")
kms = boto3.client("kms")

# Environment variables
STAGE = getenv("STAGE")
APP_NAME = getenv("APP_NAME")


def _decrypt_kms_data(encrypted_data):
    try:
        response = kms.decrypt(CiphertextBlob=encrypted_data)
        return response["Plaintext"].decode("utf-8")
    except ClientError as e:
        logger.error(f"KMS decryption failed: {str(e)}")
        raise Exception("Decryption failed")


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context=None):
    try:
        # Initialize with proper null checks
        request_context = event.get("requestContext", {}) or {}
        authorizer = request_context.get("authorizer", {}) or {}

        # Parse request body
        try:
            body = json.loads(event.get("body", "{}") or "{}")
        except json.JSONDecodeError:
            body = {}

        # Get claims from authorizer
        claims = authorizer.get("claims", {}) or authorizer or {}

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

        # Get card_id from path parameters or body
        card_id = body.get("card_id")
        if not card_id:
            logger.error("Missing card_id in request")
            return make_response(
                400,
                {
                    "error": True,
                    "success": False,
                    "message": "Missing required field: card_id",
                    "data": None,
                },
            )

        # Get card from DynamoDB
        try:
            response = table.get_item(
                Key={
                    "pk": f"USER#{user_id}",
                    "sk": card_id,  # Match your create_card format
                }
            )
        except ClientError as e:
            logger.error(f"DynamoDB error: {str(e)}")
            return make_response(
                500,
                {
                    "error": True,
                    "success": False,
                    "message": "Database error",
                    "data": None,
                },
            )

        if "Item" not in response:
            logger.error(f"Card not found for user {user_id}, card {card_id}")
            return make_response(
                404,
                {
                    "error": True,
                    "success": False,
                    "message": "Card not found",
                    "data": None,
                },
            )

        card_item = response["Item"]

        # Verify card ownership
        if card_item.get("user_id") != user_id:
            logger.error(
                f"User {user_id} attempted to access unauthorized card {card_id}"
            )
            return make_response(
                403,
                {
                    "error": True,
                    "success": False,
                    "message": "Forbidden - Card does not belong to user",
                    "data": None,
                },
            )

        # Prepare response data
        response_data = {
            "card_id": card_id,
            "user_id": user_id,
            "sudo_card_id": card_item.get("sudo_card_id"),
            "sudo_account_id": card_item.get("sudo_account_id"),
            "currency": card_item.get("currency"),
            "card_type": card_item.get("card_type"),
            "expiry": card_item.get("expiry"),
            "is_active": card_item.get("is_active", False),
            "created_at": card_item.get("created_at"),
            "balance": float(card_item.get("balance", Decimal("0.00"))),
            "card_status": card_item.get("card_status"),
            "last_four": card_item.get("last_four"),
            "brand": card_item.get("brand"),
            "is_test_card": card_item.get("is_test_card", False),
            "issuer_country": card_item.get("issuer_country"),
        }

        # Handle sensitive data based on card type
        try:
            is_test_card = card_item.get("is_test_card", False)

            if is_test_card and card_item.get("test_card_data"):
                # For test cards, get data from test_card_data
                test_data = card_item["test_card_data"].get("data", {})
                if test_data:
                    response_data["full_number"] = test_data.get("number")
                    response_data["cvv"] = test_data.get("cvv2")

                    # Handle expiry date formatting
                    expiry_month = test_data.get("expiryMonth")
                    expiry_year = test_data.get("expiryYear")
                    if expiry_month and expiry_year:
                        # Format as MM/YY
                        expiry_year_short = (
                            str(expiry_year)[-2:]
                            if len(str(expiry_year)) == 4
                            else str(expiry_year)
                        )
                        response_data["expiry"] = f"{expiry_month}/{expiry_year_short}"
            else:
                # For production cards, decrypt encrypted data
                if card_item.get("encrypted_pan"):
                    response_data["full_number"] = _decrypt_kms_data(
                        card_item["encrypted_pan"]
                    )
                if card_item.get("encrypted_cvv"):
                    response_data["cvv"] = _decrypt_kms_data(card_item["encrypted_cvv"])

        except Exception as e:
            logger.warning(f"Partial data retrieval failure: {str(e)}")
            # Continue without sensitive data rather than failing

        return make_response(
            200,
            {
                "error": False,
                "success": True,
                "message": "Card details retrieved successfully",
                "data": response_data,
            },
        )

    except Exception as e:
        logger.error(f"Unexpected error in get_card: {str(e)}")
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
