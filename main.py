from datetime import datetime, timedelta, timezone
from typing import Annotated

import os
import jwt
import random
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jwt.exceptions import InvalidTokenError
from bcrypt import hashpw, gensalt, checkpw
from pydantic import BaseModel, EmailStr

import boto3
from dotenv import load_dotenv

load_dotenv()

AWS_REGION = os.getenv('AWS_REGION')
AWS_ACCESS_ID = os.getenv('AWS_ACCESS_ID')
AWS_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY')
TABLE_1 = os.getenv('TABLE_1')
TABLE_2 = os.getenv('TABLE_2')

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: EmailStr | None = None
    full_name: str | None = None
    disabled: bool = False


class UserInDB(User):
    password: str


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

def verify_password(plain_password, hashed_password):
    return checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


def get_password_hash(password):
    salt = gensalt(12)
    r = hashpw(password.encode('utf-8'), salt).decode('utf-8')
    return r


def get_user(username: str):
    # Initialize a DynamoDB resource
    dynamodb = boto3.resource(
        'dynamodb',
        region_name = AWS_REGION,
        aws_access_key_id = AWS_ACCESS_ID,
        aws_secret_access_key = AWS_ACCESS_KEY
    )

    table = dynamodb.Table(TABLE_1)

    # Specify the primary key of the item you want to check
    primary_key = {
        'username': username,
    }
    response = table.get_item(Key=primary_key)
    dynamodb = None
    if 'Item' in response:
        """print(f"{username} found in our database.")"""
        return UserInDB(**response['Item'])


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def check_user(user: Annotated[UserInDB, Depends(get_user)]):
    if user:
        return False
    else:
        return True


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

origins = [
    "http://localhost.tiangolo.com",
    "https://localhost.tiangolo.com",
    "http://localhost",
    "http://localhost:8080",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    """
    Gets jwt login token.
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

@app.get("/check/")
async def check_user_name(check: Annotated[bool, Depends(check_user)]):
    """
    Checks if a username exists in database.
    Accepts a string and gives a boolean response.
    True means user with given name exists, False means username does not exist.
    """
    return not check

@app.post("/createuser/")
async def create_new_user(user: UserInDB):
    """
    Adds new user to database.
    Takes in user data and creates a new user.
    """
    if not get_user(user.username):
        # Initialize a DynamoDB resource
        dynamodb = boto3.resource(
            'dynamodb',
            region_name = AWS_REGION,
            aws_access_key_id = AWS_ACCESS_ID,
            aws_secret_access_key = AWS_ACCESS_KEY
        )

        table = dynamodb.Table(TABLE_1)
        table2 = dynamodb.Table(TABLE_2)
        password = get_password_hash(user.password)

        table.put_item(
            Item={
                'username': user.username,
                'email': user.email,
                'password': password,
                'full_name': user.full_name,
                'disabled': user.disabled
            }
        )
        table2.put_item(
            Item={
                'username': user.username,
                'streak': 0,
                'longest_streak': 0
            }
        )
        return {"detail": f"{user.username} added. Login to continue."}
    else:
        return {"detail": "User already exists."}

@app.post("/changepassword/")
async def change_user_password(
    current_user: Annotated[UserInDB, Depends(get_current_user)],
    new_password: str,
):
    """Changes password of the active user.
    Requires user to be logged in to change their password.
    """
    dynamodb = boto3.resource(
        'dynamodb',
        region_name = AWS_REGION,
        aws_access_key_id = AWS_ACCESS_ID,
        aws_secret_access_key = AWS_ACCESS_KEY
    )

    table = dynamodb.Table(TABLE_1)

    # Specify the primary key of the item you want to check
    primary_key = {
        'username': current_user.username,
    }
    password = get_password_hash(new_password)
    if(verify_password(new_password, table.get_item(Key=primary_key)['Item']['password'])):
        return {"detail" : "Old and new password can't be same."}
    response = table.update_item(
        Key=primary_key,
        UpdateExpression="SET #attr = :val",
        ExpressionAttributeNames={
            '#attr': 'password'
        },
        ExpressionAttributeValues={
            ':val': password
        }
                                 )
    dynamodb = None
    return {"detail" : "password changed successfully!"}


@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    """
    Returns the current logged in username
    Returns null if no user is logged in.
    """
    return current_user
