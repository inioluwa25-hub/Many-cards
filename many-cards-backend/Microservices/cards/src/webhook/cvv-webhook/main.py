import boto3
import json
from utils import logger, handle_exceptions

kms = boto3.client("kms")
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("many-cards-prod-main-table")


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context):
    try:
        body = json.loads(event["body"])
        if body.get("type") == "card_transition":
            data = body.get("data", {})

            # Only process ACTIVE state transitions
            if data.get("new_state") == "ACTIVE":
                card_token = data.get("token")
                cvv = data.get("cvv_number")

                if card_token and cvv:
                    encrypted_cvv = kms.encrypt(
                        KeyId="alias/many-cards-data-key", Plaintext=cvv.encode()
                    )["CiphertextBlob"]

                    table.update_item(
                        Key={"marqeta_card_token": card_token},
                        UpdateExpression="SET encrypted_cvv = :cvv",
                        ExpressionAttributeValues={":cvv": encrypted_cvv},
                    )

        return {"statusCode": 200}
    except Exception as e:
        print(f"Webhook error: {str(e)}")
        return {"statusCode": 500}


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
