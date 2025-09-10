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
