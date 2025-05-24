from decimal import Decimal
from utils import make_response, handle_exceptions, logger
import json
import boto3
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("many-cards-prod-main-table")
kms = boto3.client("kms")


def _decrypt_card_details(encrypted_card_number: bytes, encrypted_cvv: bytes) -> dict:
    """Decrypt sensitive card details using KMS"""
    try:
        # Ensure we have bytes objects
        if not isinstance(encrypted_card_number, bytes):
            encrypted_card_number = bytes(encrypted_card_number)
        if not isinstance(encrypted_cvv, bytes):
            encrypted_cvv = bytes(encrypted_cvv)

        # Decrypt card number
        try:
            decrypted_number_response = kms.decrypt(
                CiphertextBlob=encrypted_card_number
            )
            decrypted_number = decrypted_number_response["Plaintext"]

            # Handle both bytes and string responses
            if isinstance(decrypted_number, bytes):
                decrypted_number = decrypted_number.decode("utf-8")
        except ClientError as e:
            logger.error(
                f"Failed to decrypt card number: {e.response['Error']['Code']} - {e.response['Error']['Message']}"
            )
            raise Exception("Failed to decrypt card number")
        except UnicodeDecodeError as e:
            logger.error(f"Failed to decode decrypted card number: {str(e)}")
            raise Exception("Failed to decode decrypted card number")

        # Decrypt CVV
        try:
            decrypted_cvv_response = kms.decrypt(CiphertextBlob=encrypted_cvv)
            decrypted_cvv = decrypted_cvv_response["Plaintext"]

            # Handle both bytes and string responses
            if isinstance(decrypted_cvv, bytes):
                decrypted_cvv = decrypted_cvv.decode("utf-8")
        except ClientError as e:
            logger.error(
                f"Failed to decrypt CVV: {e.response['Error']['Code']} - {e.response['Error']['Message']}"
            )
            raise Exception("Failed to decrypt CVV")
        except UnicodeDecodeError as e:
            logger.error(f"Failed to decode decrypted CVV: {str(e)}")
            raise Exception("Failed to decode decrypted CVV")

        return {"number": decrypted_number, "cvv": decrypted_cvv}

    except Exception as e:
        # Safely handle the error without exposing sensitive data
        error_msg = str(e) if hasattr(e, "__str__") else "Decryption failed"
        logger.error(f"Decryption error: {error_msg}")
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

        # Get card_id from request body
        card_id = body.get("card_id")
        if not card_id:
            logger.error("Missing card_id in request body")
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
            response = table.get_item(Key={"pk": f"USER#{user_id}", "sk": card_id})
        except ClientError as e:
            logger.error(
                f"DynamoDB error: {e.response['Error']['Code']} - {e.response['Error']['Message']}"
            )
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

        # Validate encrypted data exists
        encrypted_card_number = card_item.get("encrypted_card_number")
        encrypted_cvv = card_item.get("encrypted_cvv")

        if not encrypted_card_number or not encrypted_cvv:
            logger.error(f"Missing encrypted data for card {card_id}")
            return make_response(
                500,
                {
                    "error": True,
                    "success": False,
                    "message": "Card data incomplete",
                    "data": None,
                },
            )

        # Decrypt card details
        try:
            decrypted_details = _decrypt_card_details(
                encrypted_card_number, encrypted_cvv
            )
        except Exception as e:
            logger.error(f"Decryption failed for card {card_id}: {str(e)}")
            return make_response(
                500,
                {
                    "error": True,
                    "success": False,
                    "message": "Failed to decrypt card details",
                    "data": None,
                },
            )

        # Prepare response data
        response_data = {
            "card_id": card_item.get("sk"),
            "user_id": user_id,
            "currency": card_item.get("currency"),
            "card_type": card_item.get("card_type"),
            "network": card_item.get("network"),
            "expiry": card_item.get("expiry"),
            "is_active": card_item.get("is_active", False),
            "created_at": card_item.get("created_at"),
            "balance": float(card_item.get("balance", Decimal("0.00"))),
            "full_number": decrypted_details.get("number"),
            "cvv": decrypted_details.get("cvv"),
        }

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
        logger.error(f"Unexpected error in get_card_details: {str(e)}")
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
