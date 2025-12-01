DB_PASSWORD=supersecret
def abc():
  print("Result: ")
  print("add Prams:")



def set_github_webhook(
    request: Request,
    webhook_for:str,
    github_owner: str,
    github_repo: str,
    github_token: str,
    workflow_id: int = None,
    data_source_id: int = None,
):
    """Add or update a GitHub webhook for PR events (opened, closed, reopened, synchronize)."""

    missing = []
    if not github_owner:
        missing.append("github_owner")
    if not github_repo:
        missing.append("github_repo")
    if not github_token:
        missing.append("github_token")

    if missing:
        return False, f"Missing GitHub configuration: {', '.join(missing)}. Please update project settings."

    # Scope webhook URL to specific workflow and data source if provided
    if workflow_id and data_source_id:
        # webhook_target_url = f"{str(request.base_url)}settings/github-webhook/{workflow_id}/{data_source_id}"
        webhook_target_url = f"https://48fb29d8beb0.ngrok-free.app/settings/github-webhook/{workflow_id}/{data_source_id}"
    else:
        # Fallback to generic webhook (for backward compatibility)
        webhook_target_url = f"https://48fb29d8beb0.ngrok-free.app/settings/github-webhook"
        # webhook_target_url = f"{str(request.base_url)}settings/github-webhook"

    headers = {
        "Authorization": f"token Demo12458polvbhgydwwdmedlmelfmeflmefefefefefefefyhyh",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json"
    }

