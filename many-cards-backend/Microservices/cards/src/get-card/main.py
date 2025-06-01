from decimal import Decimal
from utils import make_response, handle_exceptions, logger
import json
import boto3
import requests
from requests.auth import HTTPBasicAuth
from botocore.exceptions import ClientError
from os import getenv
from aws_lambda_powertools.utilities import parameters

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


class MarqetaClient:
    def __init__(self):
        self.base_url = "https://sandbox-api.marqeta.com/v3"
        self.app_token = MARQETA_APP_TOKEN
        self.access_token = MARQETA_ACCESS_TOKEN

    def get_card_details(self, card_token: str) -> dict:
        """Get full card details including PAN and CVV from Marqeta API"""
        url = f"{self.base_url}/cards/{card_token}/showpan"
        headers = {"Content-Type": "application/json"}
        auth = HTTPBasicAuth(self.app_token, self.access_token)

        try:
            response = requests.get(url, headers=headers, auth=auth)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Marqeta card details API error: {str(e)}")
            raise Exception("Failed to get card details from Marqeta")


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

        # Get full card details from Marqeta
        marqeta = MarqetaClient()
        try:
            card_details = marqeta.get_card_details(card_item["marqeta_card_token"])
        except Exception as e:
            logger.error(f"Failed to get card details from Marqeta: {str(e)}")
            return make_response(
                500,
                {
                    "error": True,
                    "success": False,
                    "message": "Failed to retrieve card details",
                    "data": None,
                },
            )

        # Decrypt PAN/CVV
        try:
            pan = _decrypt_kms_data(card_item["encrypted_pan"])
            cvv = _decrypt_kms_data(card_item["encrypted_cvv"])
        except Exception as e:
            logger.error(f"Failed to decrypt card data: {str(e)}")
            return make_response(500, {"error": "Card data decryption failed"})

        # Prepare response data
        response_data = {
            "card_id": card_id,
            "user_id": user_id,
            "currency": card_item.get("currency"),
            "card_type": card_item.get("card_type"),
            "full_number": pan,
            "cvv": cvv,
            "expiry": card_item.get("expiry"),
            "is_active": card_item.get("is_active", False),
            "created_at": card_item.get("created_at"),
            "balance": float(card_item.get("balance", Decimal("0.00"))),
            "card_status": card_item.get("card_status"),
            "last_four": card_item.get("last_four"),
            "marqeta_card_token": card_item.get("marqeta_card_token"),
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
