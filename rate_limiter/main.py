import time
import secrets
import hashlib
import logging
import sqlalchemy
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from connection import connect_db, disconnect_db, get_db, databases

# logging configuration
logging.basicConfig(level=logging.INFO)

metadata = sqlalchemy.MetaData()

# User Table
users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String(255), unique=True),
    sqlalchemy.Column("hashed_password", sqlalchemy.String(255)),
    sqlalchemy.Column("api_key", sqlalchemy.String(255), unique=True),
)

# Rate Limit Table
rate_limits = sqlalchemy.Table(
    "rate_limit",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("api_key", sqlalchemy.String(255), unique=True),
    sqlalchemy.Column("last_request", sqlalchemy.Float),
    sqlalchemy.Column("request_count", sqlalchemy.Integer),
)

app = FastAPI()
security = HTTPBearer()

# Rate Limit Configuration
REQUEST_LIMIT = 5  # Number of requests allowed
TIME_WINDOW = 25  # Time window in seconds


def hash_password(password: str):
    """Hashes a password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()


async def authenticate_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: databases.Database = Depends(get_db),
):
    """Authenticates a user based on the API key provided in the Authorization header."""
    api_key = credentials.credentials
    query = users.select().where(users.c.api_key == api_key)
    user = await db.fetch_one(query)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return user


async def rate_limit(api_key: str, db: databases.Database = Depends(get_db)):
    """Applies rate limiting to requests based on the API key."""
    current_time = time.time() % 60  # get time in seconds
    query = rate_limits.select().where(rate_limits.c.api_key == api_key)
    result = await db.fetch_one(query)

    if result:
        last_request = result["last_request"]
        request_count = result["request_count"]
        logging.info(f"Current Time - {str(current_time)}")
        logging.info(f"Last Requested Time - {str(last_request)}")
        logging.info(f"Elapsed Time - {str(abs(current_time - last_request))}")

        if abs(current_time - last_request) > TIME_WINDOW:
            await db.execute(
                rate_limits.update()
                .where(rate_limits.c.api_key == api_key)
                .values(last_request=current_time, request_count=1)
            )
            return

        if request_count >= REQUEST_LIMIT:
            raise HTTPException(status_code=429, detail="Too Many Requests")

        await db.execute(
            rate_limits.update()
            .where(rate_limits.c.api_key == api_key)
            .values(last_request=current_time, request_count=request_count + 1)
        )
    else:
        await db.execute(
            rate_limits.insert().values(
                api_key=api_key, last_request=current_time, request_count=1
            )
        )


class UserRegistration(BaseModel):
    """Pydantic model for user registration data."""

    username: str
    password: str


@app.post("/register")
async def register(user: UserRegistration, db: databases.Database = Depends(get_db)):
    """Registers a new user and generates an API key."""
    hashed_password = hash_password(user.password)
    api_key = secrets.token_hex(32)
    query = users.insert().values(
        username=user.username,
        hashed_password=hashed_password,
        api_key=api_key)
    await db.execute(query)
    return {"message": "User registered", "api_key": api_key}


@app.get("/api/data")
async def get_data(
    user: dict = Depends(authenticate_user), db: databases.Database = Depends(get_db)
):
    """Retrieves data after authenticating and rate limiting."""
    await rate_limit(user["api_key"], db)
    return {"message": "Data retrieved successfully"}


@app.on_event("startup")
async def startup():
    """Connects to the database on application startup."""
    connect_db()


@app.on_event("shutdown")
async def shutdown():
    """Disconnects from the database on application shutdown."""
    disconnect_db()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
