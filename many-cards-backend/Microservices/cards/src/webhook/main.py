import json
import boto3
from botocore.exceptions import ClientError
from utils import logger, handle_exceptions

kms = boto3.client("kms")
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("many-cards-prod-main-table")


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context):
    try:
        # Verify webhook payload
        body = json.loads(event["body"])
        event_type = body.get("type")

        if event_type != "card_transition":
            return {"statusCode": 200, "body": "Ignored - Not a card transition event"}

        card_data = body.get("data", {})
        if card_data.get("new_state") != "ACTIVE":
            return {"statusCode": 200, "body": "Ignored - Card not yet active"}

        # Extract card details
        pan = card_data.get("pan")
        cvv = card_data.get("cvv_number")
        card_token = card_data.get("token")

        if not pan or not cvv:
            logger.error("Missing PAN/CVV in webhook")
            return {"statusCode": 400, "body": "Missing card details"}

        # Encrypt PAN/CVV with AWS KMS
        try:
            encrypted_pan = kms.encrypt(
                KeyId="alias/many-cards-data-key",  # Replace with your KMS key
                Plaintext=pan.encode(),
            )["CiphertextBlob"]

            encrypted_cvv = kms.encrypt(
                KeyId="alias/many-cards-data-key", Plaintext=cvv.encode()
            )["CiphertextBlob"]
        except ClientError as e:
            logger.error(f"KMS encryption failed: {str(e)}")
            return {"statusCode": 500, "body": "Encryption failed"}

        # Update DynamoDB
        try:
            table.update_item(
                Key={"pk": f"CARD#{card_token}", "sk": "METADATA"},
                UpdateExpression="SET encrypted_pan = :pan, encrypted_cvv = :cvv",
                ExpressionAttributeValues={
                    ":pan": encrypted_pan,
                    ":cvv": encrypted_cvv,
                },
            )
        except ClientError as e:
            logger.error(f"DynamoDB update failed: {str(e)}")
            return {"statusCode": 500, "body": "Database update failed"}

        return {"statusCode": 200, "body": "Webhook processed successfully"}

    except Exception as e:
        logger.error(f"Webhook error: {str(e)}")
        return {"statusCode": 500, "body": "Internal server error"}


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def hanlder(event, context):
    return main(event, context)
