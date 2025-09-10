from fastapi import APIRouter, Request, Depends, HTTPException, Form
from fastapi.responses import RedirectResponse

from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.templates import templates
import re
import secrets
import json
import requests
import hashlib
import base64
import jwt
from dotenv import load_dotenv
import logging
from sqlalchemy import select

load_dotenv()
logger = logging.getLogger(__name__)

from app.database import get_db
from app.utils.app_config import AppConfig

router = APIRouter(prefix="/users", tags=["users"])
import asyncio
# asyncio.run(AppConfig.get_configuration())

@router.get("/register", response_class=templates.TemplateResponse)
async def create_user_form(request: Request):
    async with get_db() as db:
        existing_usernames_result = await db.execute(select(User.username))
        existing_usernames = existing_usernames_result.scalars().all()
        existing_emails_result = await db.execute(select(User.email))
        existing_emails = existing_emails_result.scalars().all()
        existing_usernames = [username for username in existing_usernames]
        existing_emails = [email for email in existing_emails]
        
        return templates.TemplateResponse(
            "user/create_user_form.html",
            {
                "request": request,
                "user": None,
                "existing_username": existing_usernames,
                "existing_email": existing_emails,
            },
        )


def validate_email(email: str):
    """Validate the email format."""
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not re.match(email_regex, email):
        raise HTTPException(status_code=400, detail="Invalid email format")


def validate_password(password: str):
    """Validate the password strength."""
    # Password rules: at least 8 characters, one uppercase, one lowercase, one number, one special character
    if len(password) < 8:
        raise HTTPException(
            status_code=400, detail="Password must be at least 8 characters long"
        )
    if not any(char.isupper() for char in password):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one uppercase letter",
        )
    if not any(char.islower() for char in password):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one lowercase letter",
        )
    if not any(char.isdigit() for char in password):
        raise HTTPException(
            status_code=400, detail="Password must contain at least one digit"
        )
    if not any(char in "!@#$%^&*()-_=+[]{}|;:',.<>?/`~" for char in password):
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least one special character",
        )


# Add the validation function for email and username in the database
async def check_existing_user(db: Session, username: str, email: str):
    existing_user_result = await db.execute(select(User).filter((User.username == username) | (User.email == email)))
    existing_user = existing_user_result.scalars().first()
    if existing_user:
        if existing_user.username == username:
            raise HTTPException(status_code=400, detail="Username is already taken")
        if existing_user.email == email:
            raise HTTPException(status_code=400, detail="Email is already registered")


@router.post("/create")
async def create_user(
    request: Request,
    first_name: str = Form(...),
    last_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    gender: str = Form(...),
):
    # Validate email and password and check Existing user_email and username
    async with get_db() as db:
        validate_email(email)
        validate_password(password)
        check_existing_user(db, email, email)

        payload = json.dumps(
            {
                "username": email,
                "profile": {
                    "givenName": first_name,
                    "familyName": last_name,
                    "nickName": email,
                    "displayName": f"{first_name}",
                    "preferredLanguage": "en",
                    "gender": gender,
                },
                "email": {"email": email, "isVerified": True},
                "password": {"password": password, "changeRequired": False},
                "idpLinks": [],
            }
        )

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {AppConfig._config.zitadel_client_secret}",
        }

        url = f"{AppConfig._config.zitadel_issuer}/v2/users/human"
        response = requests.post(url, headers=headers, data=payload)
        if response.status_code == 201:
            response_data = response.json()
            user_id = response_data.get("userId")
            if not user_id:
                raise HTTPException(
                    status_code=400,
                    detail="Failed to retrieve userId from external service",
                )

            try:
                # Hash the password before saving to the database
                new_user = User(
                    username=email,
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    gender=gender,
                    zitadel_user_id=user_id,
                )
                db.add(new_user)
                await db.commit()
                await db.refresh(new_user)
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

            return RedirectResponse(url="/", status_code=303)
        elif response.status_code == 409:
            raise HTTPException(status_code=400, detail="User is already exists")
        else:
            raise HTTPException(
                status_code=response.status_code,
                detail="Error while creating user in external service",
            )


def generate_pkce_codes():
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = (
        base64.urlsafe_b64encode(code_challenge).decode("utf-8").rstrip("=")
    )
    return code_verifier, code_challenge


@router.get("/login")
async def login(request: Request):
    code_verifier, code_challenge = generate_pkce_codes()
    request.session["code_verifier"] = code_verifier

    auth_url = (
        f"{AppConfig._config.zitadel_issuer}/oauth/v2/authorize"
        f"?client_id={AppConfig._config.zitadel_client_id}"
        f"&redirect_uri={request.url_for('auth')}"
        f"&response_type=code"
        f"&scope=openid%20profile%20email"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
    )
    return RedirectResponse(auth_url)


@router.get("/user_login", response_class=templates.TemplateResponse)
async def login_form(request: Request):
    return templates.TemplateResponse(
        "user/login.html", {"request": request, "user": None}
    )


@router.get("/auth")
async def auth(request: Request):
    
    auth_code = request.query_params.get("code")

    if not auth_code:
        return RedirectResponse(url="/users/login")

    code_verifier = request.session.get("code_verifier")
    if not code_verifier:
        return RedirectResponse(url="/users/login")

    token_url = f"{AppConfig._config.zitadel_issuer}/oauth/v2/token"
    try:
        response = requests.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "client_id": AppConfig._config.zitadel_client_id,
                "redirect_uri": request.url_for("auth"),
                "code_verifier": code_verifier,
                # "scope": "openid email profile",
                "scope": "urn:iam:org:project:roles",
            },
        )
        response.raise_for_status()
        tokens = response.json()

        user_info = jwt.decode(
            tokens["id_token"],
            options={"verify_signature": False},
            algorithms=["RS256"],
        )
        roles = user_info.get("urn:zitadel:iam:org:project:roles", {})
        if roles:
            (
                request.session["user"],
                request.session["id_token"],
                request.session["user_role"],
            ) = (user_info, tokens["id_token"], next(iter(roles), None))
            return RedirectResponse(url="/")
        else:
            request.session.clear()
            return RedirectResponse(url="/users/login")

    except requests.RequestException as e:
        logger.exception(f"Token Exchange Error: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to exchange authorization code for tokens."
        )


@router.get("/logout")
async def logout(request: Request):
    # URL for logging out of the external service 
    id_token = request.session.get("id_token")
    logout_url = f"{AppConfig._config.zitadel_issuer}/oidc/v1/end_session?id_token_hint={id_token}&post_logout_redirect_uri={AppConfig._config.logout_redirect_uri}&state=random_string"
    request.session.clear()

    return RedirectResponse(logout_url)
