from utils import make_response, handle_exceptions, logger
import json
from boto3.dynamodb.conditions import Key
import boto3

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("many-cards-prod-main-table")
kms = boto3.client("kms")


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context=None):
    try:
        request_context = event.get("requestContext", {})
        authorizer = request_context.get("authorizer") or {}

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

        response = table.query(
            KeyConditionExpression=Key("pk").eq(f"USER#{user_id}")
            & Key("sk").begins_with("CARD#"),
            Limit=10,  # Adjust as needed
        )

        cards = response.get("Items", [])

        if cards:
            return make_response(
                200,
                {
                    "error": False,
                    "success": True,
                    "message": "CArds retrieved successfully",
                    "data": cards,  # Returns all found cards
                },
            )
        else:
            return make_response(
                404,
                {
                    "error": True,
                    "success": False,
                    "message": "No cards found for this user",
                    "data": None,
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
