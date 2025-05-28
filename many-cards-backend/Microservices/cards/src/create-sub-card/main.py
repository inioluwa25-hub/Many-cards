import json
from os import getenv
from time import time
from uuid import uuid4
from datetime import datetime, timedelta
from decimal import Decimal

import boto3
from aws_lambda_powertools.utilities import parameters
from pydantic import BaseModel, validator
from utils import handle_exceptions, logger, make_response

# Environment variables
STAGE = getenv("STAGE")
APP_NAME = getenv("APP_NAME")

# Fix the parameter store path to match SAM template
POOL_ID = parameters.get_parameter(f"/many-cards/{STAGE}/POOL_ID")
CLIENT_ID = parameters.get_parameter(f"/{APP_NAME}/{STAGE}/CLIENT_ID")
CLIENT_SECRET = parameters.get_parameter(
    f"/{APP_NAME}/{STAGE}/CLIENT_SECRET", decrypt=True
)

# AWS client
client = boto3.client("cognito-idp")
db = boto3.resource("dynamodb")
table = db.Table("many-cards-prod-main-table")


class SubCardPayload(BaseModel):
    main_card_id: str
    color: str
    merchant_id: str
    name: str
    start_date: str | None = None
    duration_days: int | None = None
    spending_limit: int
    resume: bool

    @validator("start_date")
    def validate_start_date(cls, v):
        if v:
            try:
                datetime.fromisoformat(v)
            except ValueError:
                raise ValueError("Invalid date format. Use YYYY-MM-DD")
        return v

    @validator("duration_days")
    def validate_duration(cls, v):
        if v is not None and v <= 0:
            raise ValueError("Duration must be positive")
        return v


def validate_hex_color(color: str) -> bool:
    """Validate hex color code format"""
    if color.startswith("#"):
        color = color[1:]
    return len(color) == 6 and all(c in "0123456789ABCDEFabcdef" for c in color)


def convert_floats_to_decimals(obj):
    """Recursively convert float values to Decimal in a dictionary"""
    if isinstance(obj, dict):
        return {k: convert_floats_to_decimals(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [convert_floats_to_decimals(v) for v in obj]
    elif isinstance(obj, float):
        return Decimal(str(obj))
    return obj


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
            payload = SubCardPayload(**body)
            logger.info(f"payload - {payload}")
        except Exception as e:
            logger.error(f"Invalid payload: {str(e)}")
            return make_response(
                400,
                {
                    "error": True,
                    "success": False,
                    "message": str(e),
                    "data": None,
                },
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

        # Validate color format
        if not validate_hex_color(payload.color):
            return make_response(
                400,
                {
                    "error": True,
                    "message": "Invalid color format. Use hex color code (e.g., #FF5733)",
                },
            )

        # Check if main card exists and belongs to user
        main_card = table.get_item(
            Key={"pk": f"USER#{user_id}", "sk": payload.main_card_id}
        ).get("Item")
        if not main_card:
            return make_response(
                404, {"error": True, "message": "Parent card not found"}
            )

        current_time = datetime.now()
        expiration_date = None

        if payload.duration_days:
            if payload.start_date:
                start_date = datetime.fromisoformat(payload.start_date)
            else:
                start_date = current_time

            expiration_date = (
                start_date + timedelta(days=payload.duration_days)
            ).isoformat()

        # Create sub-card
        sub_card_id = f"SUB#{str(uuid4())[:8]}"

        sub_card = {
            "pk": f"USER#{user_id}",
            "sk": sub_card_id,
            "type": "SUB_CARD",
            "name": payload.name,
            "color": payload.color,
            "merchant_id": payload.merchant_id,
            "spending_limit": Decimal(str(payload.spending_limit)),
            "current_spend": Decimal("0.00"),
            "status": payload.resume,
            "created_at": int(time()),
            "updated_at": int(time()),
            "duration_days": payload.duration_days,
            "start_date": payload.start_date or current_time.isoformat(),
            "expiration_date": expiration_date,
            "main_card_id": payload.main_card_id,
            "GSI1PK": payload.main_card_id,  # For querying by parent card
            "GSI1SK": f"SUB#{sub_card_id}",
        }

        # Convert all floats to decimals before saving to DynamoDB
        sub_card = convert_floats_to_decimals(sub_card)

        # Save to DynamoDB
        table.put_item(Item=sub_card)

        return make_response(
            201,
            {
                "error": False,
                "message": "Sub-card created successfully",
                "data": {
                    "sub_card_id": sub_card_id,
                    "name": sub_card["name"],
                    "color": sub_card["color"],
                    "merchant_id": sub_card["merchant_id"],
                    "duration_days": sub_card["duration_days"],
                    "start_date": sub_card["start_date"],
                    "expiration_date": sub_card["expiration_date"],
                    "spending_limit": float(sub_card["spending_limit"]),
                    "current_spend": float(sub_card["current_spend"]),
                    "status": sub_card["status"],
                    "parent_card_id": sub_card["main_card_id"],
                    "created_at": sub_card["created_at"],
                },
            },
        )

    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return make_response(
            404, {"error": True, "success": False, "message": str(e), "data": None}
        )
    except Exception as e:
        logger.error(f"Unexpected error: {type(e).__name__}: {str(e)}")
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
