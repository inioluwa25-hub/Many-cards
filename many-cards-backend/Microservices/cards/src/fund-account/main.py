import json
import boto3
from decimal import Decimal
from datetime import datetime
from pydantic import BaseModel, validator
from utils import logger, handle_exceptions, make_response
from botocore.exceptions import ClientError

# Initialize AWS services
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("many-cards-prod-main-table")


class FundCardRequest(BaseModel):
    card_id: str
    amount: float
    currency: str = "NGN"  # Default currency

    @validator("amount")
    def validate_amount(cls, value):
        if value <= 0:
            raise ValueError("Amount must be positive")
        if value > 1000000:  # 1M max funding
            raise ValueError("Maximum funding amount exceeded")
        return value


def update_card_balance(user_id: str, card_id: str, amount: Decimal) -> dict:
    """Atomic update of card balance in DynamoDB with proper error handling

    Args:
        user_id: Cognito user ID (e.g., "usr-123")
        card_id: Full SK value (e.g., "CARD#abc123")
        amount: Decimal amount to add (negative for debits)

    Returns:
        Dictionary with updated attributes if successful

    Raises:
        ValueError: Invalid amount
        ClientError: DynamoDB operation failed
    """
    try:
        # Validate amount before DB operation
        if not isinstance(amount, Decimal):
            raise ValueError("Amount must be Decimal type")

        if amount <= Decimal("0"):
            raise ValueError("Amount must be positive")

        response = table.update_item(
            Key={
                "pk": f"USER#{user_id}",
                "sk": card_id,  # Ensures consistent format
            },
            UpdateExpression="SET balance = if_not_exists(balance, :zero) + :amt, last_updated = :now",
            ExpressionAttributeValues={
                ":amt": amount,
                ":zero": Decimal("0"),  # Handles new cards
                ":now": datetime.utcnow().isoformat(),
            },
            ConditionExpression="attribute_exists(pk)",
            ReturnValues="UPDATED_NEW",
        )
        return response.get("Attributes", {})

    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.error(f"Card not found: user={user_id}, card={card_id}")
            raise ValueError("Card does not exist") from e
        logger.error(f"DynamoDB error: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context):
    try:
        # Extract user info from event
        request_context = event.get("requestContext", {})
        authorizer = request_context.get("authorizer") or {}
        claims = authorizer.get("claims") or authorizer

        if not isinstance(claims, dict) or not claims:
            return make_response(
                401, {"error": True, "message": "Unauthorized - No claims found"}
            )

        user_id = claims.get("sub") or claims.get("cognito:username")

        if not user_id:
            return make_response(
                401, {"error": True, "message": "Unauthorized - No user"}
            )
        # Parse and validate request
        request = FundCardRequest(**json.loads(event["body"]))

        # Convert to Decimal for precise money handling
        amount = Decimal(str(request.amount))

        # Update card balance
        updated = update_card_balance(user_id, request.card_id, amount)

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "success": True,
                    "new_balance": float(updated["balance"]),
                    "currency": request.currency,
                }
            ),
        }

    except ValueError as e:
        return {"statusCode": 400, "body": json.dumps({"error": str(e)})}
    except Exception as e:
        logger.error(f"Funding error: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Internal server error"}),
        }


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
