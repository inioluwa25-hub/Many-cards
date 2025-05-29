from os import getenv
import json
import boto3
from boto3.dynamodb.conditions import Key
from pydantic import BaseModel
from aws_lambda_powertools.utilities import parameters
from typing import Dict, Optional
from utils import (
    make_response,
    handle_exceptions,
    logger,
)

# AWS client
client = boto3.client("cognito-idp")
db = boto3.resource("dynamodb")
table = db.Table("many-cards-prod-main-table")


class SubCardSchema(BaseModel):
    sub_card_id: str


def get_sub_card_by_id(user_id: str, sub_card_id: str) -> Optional[Dict]:
    """
    Retrieves a sub card from the database by ID

    Args:
        sub_card_id (str): The ID of the sub card to retrieve (used as sort key in DB)

    Returns:
        Dict or None: The product data or None if not found
    """
    try:
        # Execute the query
        response = table.query(
            KeyConditionExpression=Key("pk").eq(f"USER#{user_id}")
            & Key("sk").eq(sub_card_id),
        )

        # Return the first item found (or None if none found)
        items = response.get("Items", [])
        return items[0] if items else None

    except Exception as e:
        print(f"Error retrieving sub card: {str(e)}")
        return None


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context=None):
    status_code = 400
    response = {
        "error": True,
        "success": False,
        "message": "Server error",
        "data": None,
    }

    try:
        # Enhanced claims extraction
        request_context = event.get("requestContext", {})
        authorizer = request_context.get("authorizer") or {}

        try:
            body = json.loads(event.get("body", "{}") or "{}")
        except json.JSONDecodeError:
            body = {}
        try:
            payload = SubCardSchema(**body)
            logger.info(f"payload - {payload}")
        except Exception as e:
            logger.error(f"Invalid payload: {str(e)}")
            return make_response(
                400, {"error": True, "success": False, "message": str(e), "data": None}
            )

        claims = authorizer.get("claims") or authorizer

        if not isinstance(claims, dict) or not claims:
            logger.error("No valid claims found in event")
            logger.info(f"Full event structure: {json.dumps(event, indent=2)}")
            status_code = 401
            response["message"] = "Unauthorized - No claims found"
            return make_response(status_code, response)

        # Extract user_id from claims
        user_id = claims.get("sub") or claims.get("cognito:username")
        if not user_id:
            logger.error("No user identifier found in claims")
            status_code = 401
            response["message"] = "Unauthorized - No user identifier"
            return make_response(status_code, response)

        sub_card = get_sub_card_by_id(user_id, payload.sub_card_id)
        if sub_card:
            status_code = 200
            response["message"] = "success"
            response["error"], response["success"] = False, True
            response["data"] = sub_card
        else:
            status_code = 404
            response["message"] = "Sub card not found"

    except client.exceptions.NotAuthorizedException as e:
        logger.error(f"Not authorized: {str(e)}")
        status_code = 403
        response["message"] = "Access denied"
    except Exception as e:
        logger.error(f"Unexpected error: {type(e).__name__}: {str(e)}")
        status_code = 500
        response["message"] = "Internal server error"

    return make_response(status_code, response)


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
