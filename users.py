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
        return False
    return True


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


def verify_id_token(id_token: str) -> dict | None:
    """
    Verify ID token using Zitadel JWKS.
    Automatically fetches JWKS if not cached.
    """
    try:
        jwks_url = f"{AppConfig._config.zitadel_issuer.rstrip('/')}/oauth/v2/keys"
        jwk_client = jwt.PyJWKClient(jwks_url)

        signing_key = jwk_client.get_signing_key_from_jwt(id_token).key

        claims = jwt.decode(
            id_token,
            signing_key,
            algorithms=["RS256"],
            audience=AppConfig._config.zitadel_client_id,
            issuer=AppConfig._config.zitadel_issuer.rstrip("/"),
        )
        return claims

    except Exception as e:
        print(f"ID Token verification failed: {e}")
        return None
        
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
