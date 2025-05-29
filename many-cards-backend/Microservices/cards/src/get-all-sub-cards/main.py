import json
import boto3
from boto3.dynamodb.conditions import Key
from decimal import Decimal
from typing import Dict, List
from os import getenv
from utils import handle_exceptions, logger, make_response

# Environment variables
STAGE = getenv("STAGE")
APP_NAME = getenv("APP_NAME")

# AWS clients
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("many-cards-prod-main-table")


def get_main_card(user_id: str, card_id: str) -> Dict:
    """Get a specific main card to verify ownership"""
    try:
        response = table.get_item(Key={"pk": f"USER#{user_id}", "sk": card_id})

        return response.get("Item")

    except Exception as e:
        logger.error(
            f"Failed to fetch main card {card_id} for user {user_id}: {str(e)}"
        )
        raise


def get_sub_cards(user_id: str, main_card_id: str) -> List[Dict]:
    """Get all sub cards for a specific main card"""
    try:
        response = table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
            ExpressionAttributeValues={
                ":pk": f"USER#{user_id}",
                ":sk_prefix": "SUB#",
            },
        )

        return response.get("Items", [])

    except Exception as e:
        logger.error(
            f"Failed to fetch sub cards for main card {main_card_id}: {str(e)}"
        )
        raise


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context=None):
    """Lambda handler for getting sub cards of a main card"""
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
        main_card_id = body.get("main_card_id")

        if not main_card_id:
            return make_response(
                400,
                {
                    "error": True,
                    "message": "Missing main_card_id in path parameters",
                    "data": None,
                },
            )

        # Verify that the main card exists and belongs to the user
        main_card = get_main_card(user_id, main_card_id)
        if not main_card:
            return make_response(
                404,
                {
                    "error": True,
                    "message": "Main card not found or access denied",
                    "data": None,
                },
            )

        # Get sub cards for the main card
        sub_cards = get_sub_cards(user_id, main_card_id)

        if not sub_cards:
            return make_response(
                200,
                {
                    "error": False,
                    "success": True,
                    "message": "No sub cards found for this main card",
                    "data": sub_cards,
                },
            )

        return make_response(
            200,
            {
                "error": False,
                "success": True,
                "message": f"Found {len(sub_cards)} sub cards for main card",
                "data": sub_cards,
            },
        )

    except Exception as e:
        logger.error(f"Get sub cards error: {str(e)}")
        return make_response(
            500, {"error": True, "message": "Internal server error", "data": None}
        )


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    """Handler specifically for getting sub cards"""
    return main(event, context)
