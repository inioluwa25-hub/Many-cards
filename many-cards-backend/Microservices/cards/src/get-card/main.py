from decimal import Decimal
from uuid import uuid4
from utils import make_response, handle_exceptions, logger
import datetime
from dataclasses import asdict
import json
import boto3
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("many-cards-prod-main-table")
kms = boto3.client("kms")


def _decrypt_card_details(encrypted_card_number: bytes, encrypted_cvv: bytes) -> dict:
    """Decrypt sensitive card details using KMS"""
    try:
        decrypted_number = kms.decrypt(CiphertextBlob=encrypted_card_number)[
            "Plaintext"
        ].decode()

        decrypted_cvv = kms.decrypt(CiphertextBlob=encrypted_cvv)["Plaintext"].decode()

        return {"number": decrypted_number, "cvv": decrypted_cvv}
    except ClientError as e:
        raise Exception(f"Decryption failed: {str(e)}")


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context=None):
    try:
        request_context = event.get("requestContext", {})
        authorizer = request_context.get("authorizer") or {}

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

        # Get card_id from path parameters
        card_id = event.get("pathParameters", {}).get("card_id")
        if not card_id:
            return make_response(
                400,
                {
                    "error": True,
                    "success": False,
                    "message": "Missing card_id in path parameters",
                    "data": None,
                },
            )

        # Get card from DynamoDB
        response = table.get_item(
            Key={"pk": f"USER#{user_id}", "sk": f"CARD#{card_id}"}
        )

        if "Item" not in response:
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

        # Verify the card belongs to the requesting user
        if card_item.get("user_id") != user_id:
            return make_response(
                403,
                {
                    "error": True,
                    "success": False,
                    "message": "Forbidden - Card does not belong to user",
                    "data": None,
                },
            )

        # Decrypt sensitive data
        decrypted_details = _decrypt_card_details(
            card_item["encrypted_card_number"], card_item["encrypted_cvv"]
        )

        # Prepare response
        return make_response(
            200,
            {
                "error": False,
                "success": True,
                "message": "Card details retrieved successfully",
                "data": {
                    "card_id": card_item["card_id"],
                    "user_id": user_id,
                    "currency": card_item.get("currency"),
                    "card_type": card_item.get("card_type"),
                    "network": card_item.get("network"),
                    "full_number": decrypted_details["number"],
                    "expiry": card_item.get("expiry"),
                    "cvv": decrypted_details["cvv"],
                    "is_active": card_item.get("is_active", False),
                    "created_at": card_item.get("created_at"),
                    "balance": float(card_item.get("balance", Decimal("0.00"))),
                    "masked_number": card_item.get("masked_number"),
                },
            },
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
