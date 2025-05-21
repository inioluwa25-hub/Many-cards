import base64
import hashlib
import hmac
import json
from os import getenv

import boto3
from aws_lambda_powertools.utilities import parameters

from pydantic import BaseModel, EmailStr, validator
from utils import logger, make_response, handle_exceptions


# Environment variables
STAGE = getenv("STAGE")
APP_NAME = getenv("APP_NAME")

POOL_ID = parameters.get_parameter(f"/{APP_NAME}/{STAGE}/POOL_ID")
CLIENT_ID = parameters.get_parameter(f"/{APP_NAME}/{STAGE}/CLIENT_ID")
CLIENT_SECRET = parameters.get_parameter(
    f"/{APP_NAME}/{STAGE}/CLIENT_SECRET", decrypt=True
)

client = boto3.client("cognito-idp")


class PasswordSchema(BaseModel):
    email: EmailStr
    code: str
    password: str

    @validator("password")
    def validate_password(cls, password):
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not any(c.isupper() for c in password):
            raise ValueError("Password must contain at least one capital letter.")
        if not any(c.isdigit() for c in password):
            raise ValueError("Password must contain at least one digit.")
        if not any(c in "@$!%*?&-.,.#`~^()" for c in password):
            raise ValueError("Password must contain at least one special character.")
        return password


def get_secret_hash_individual(username):
    msg = username + CLIENT_ID
    dig = hmac.new(
        str(CLIENT_SECRET).encode("utf-8"),
        msg=str(msg).encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()
    d2 = base64.b64encode(dig).decode()
    return d2


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def main(event, context=None):
    status_code = 400
    logger.info(event)
    response = {
        "error": True,
        "success": False,
        "message": "server error",
        "data": None,
    }
    try:
        body = json.loads(event["body"])
        payload = PasswordSchema(**body)
        logger.info(f"payload - {payload}")
        secret_hash = get_secret_hash_individual(payload.email)
        client.confirm_forgot_password(
            ClientId=CLIENT_ID,
            SecretHash=secret_hash,
            Username=payload.email,
            ConfirmationCode=payload.code,
            Password=payload.password,
        )
        status_code = 200
        response["error"] = False
        response["success"] = True
        response["message"] = "password reset successful"
    except ValueError as e:
        logger.error(e)
        response["message"] = e.messages
    except client.exceptions.NotAuthorizedException as e:
        logger.error(e)
        response_string = str(e)
        response["message"] = response_string.split(":", 1)[-1].strip()
    except client.exceptions.UserNotConfirmedException as e:
        logger.error(e)
        response_string = str(e)
        response["message"] = response_string.split(":", 1)[-1].strip()
    except client.exceptions.UserNotFoundException as e:
        logger.error(e)
        response["message"] = "User not found"
    except Exception as e:
        status_code = 500
        logger.error(e)
        response["message"] = str(e)
    return make_response(status_code, response)


@logger.inject_lambda_context(log_event=True)
@handle_exceptions
def handler(event, context):
    return main(event, context)
