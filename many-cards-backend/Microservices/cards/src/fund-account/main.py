import requests
import boto3
from os import getenv
from decimal import Decimal
from aws_lambda_powertools.utilities import parameters
from utils import logger, make_response

# Environment variables
STAGE = getenv("STAGE")
APP_NAME = getenv("APP_NAME")

dynamodb = boto3.resource("dynamodb")
kms = boto3.resource("kms")
table = dynamodb.Table("many-cards-prod-main-table")

# Load Paystack test secret key from AWS Parameter Store or environment
PAYSTACK_SECRET_KEY = parameters.get_parameter(
    f"/{APP_NAME}/{STAGE}/PAYSTACK_SECRET_KEY", decrypt=True
)
SUDO_API_KEY = parameters.get_parameter(f"/{APP_NAME}/{STAGE}/SUDO_SECRET_KEY")


class PaymentProcessor:
    def __init__(self):
        self.paystack_headers = {
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json",
        }
        self.sudo_headers = {
            "Authorization": f"Bearer {SUDO_API_KEY}",
            "Content-Type": "application/json",
        }

    def simulate_paystack_payment(
        self, card_pan: str, amount: float, email: str, currency: str
    ) -> dict:
        """Simulate a Paystack payment to the card"""
        url = "https://api.paystack.co/transaction/charge_authorization"

        payload = {
            "authorization_code": "AUTH_test123",  # Test mode code
            "email": email,
            "amount": int(amount * 100),  # Paystack uses kobo
            "currency": currency,
            "metadata": {
                "card_pan": card_pan[-4:],  # Last 4 digits
                "purpose": "sudo_card_funding",
            },
        }

        try:
            response = requests.post(
                url, json=payload, headers=self.paystack_headers, timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Paystack simulation failed: {str(e)}")
            raise

    def settle_to_sudo_account(self, sudo_account_id: str, amount: float) -> dict:
        """Credit the Sudo account using sandbox endpoint"""
        url = f"https://api.sandbox.sudo.cards/simulator/accounts/{sudo_account_id}/credit"

        payload = {
            "amount": amount,
            "currency": "NGN",
            "description": "Paystack funding settlement",
        }

        try:
            response = requests.post(
                url, json=payload, headers=self.sudo_headers, timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Sudo settlement failed: {str(e)}")
            raise


# Example Usage
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
                401, {"error": True, "message": "Unauthorized - No user identifier"}
            )

        email = claims.get("email")
        if not email:
            return make_response(
                401, {"error": True, "message": "Unauthorized - No email identifier"}
            )
        # Extract parameters from event
        body = event.get("body", {})
        card_id = body.get("card_id")
        amount = float(body.get("amount", 0))

        card_data = table.get_item(Key={"pk": f"USER#{user_id}", "sk": card_id})["Item"]

        if not card_data:
            return {"statusCode": 404, "body": "Card not found"}

        currency = card_data["currency"]

        # 2. Decrypt PAN (if encrypted)
        pan = card_data["test_card_data"]["data"]["number"]

        # 3. Process payment
        processor = PaymentProcessor()

        # Step 1: Simulate Paystack payment
        paystack_result = processor.simulate_paystack_payment(
            card_pan=pan, amount=amount, email=email, currency=currency
        )

        # Step 2: Settle to Sudo account
        sudo_result = processor.settle_to_sudo_account(
            sudo_account_id=card_data["sudo_account_id"], amount=amount
        )

        # 4. Update DynamoDB
        new_balance = Decimal(str(card_data["balance"])) + Decimal(str(amount))
        table.update_item(
            Key={"pk": f"USER#{user_id}", "sk": card_id},
            UpdateExpression="SET balance = :balance",
            ExpressionAttributeValues={":balance": new_balance},
        )

        return {
            "statusCode": 200,
            "body": {
                "paystack_reference": paystack_result["data"]["reference"],
                "sudo_transaction_id": sudo_result["id"],
                "new_balance": float(new_balance),
            },
        }

    except Exception as e:
        logger.error(str(e))
        return {"statusCode": 500, "body": str(e)}


def handler(event, context):
    return main(event, context)
