async def verify_review_access(
    project_id: int,
    review_id: int,
    current_user: Dict[str, Any],
    db,
    required_permission: str = "read"  # "read", "write", "delete", "admin"
):
    """
    Helper function to verify review exists and user has specific permission
    
    Args:
        project_id: ID of the project
        review_id: ID of the review
        current_user: JWT payload from API key
        db: Database session
        required_permission: Required permission level ("read", "write", "delete", "admin")
    """
    
    # Check if review exists and belongs to the project
    review_result = await db.execute(
        select(Review).where(
            Review.id == review_id,
            Review.project_id == project_id
        )
    )
    review = review_result.scalars().first()
    
    if not review:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Review not found"
        )
    
    # Get user info from API key
    user_role = current_user.get("role")
    user_project_id = current_user.get("project_id")
    
    if not user_role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key: missing role information"
        )
    
    # Define permission matrix
    role_permissions = {
        "super_admin": ["read", "write", "delete", "admin"],
        "project_admin": ["read", "write", "delete", "admin"],
        "project_user": ["read"]
    }
    
    # Check if role exists and has required permission
    if user_role not in role_permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: Invalid role '{user_role}'"
        )
    
    if required_permission not in role_permissions[user_role]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: Role '{user_role}' does not have '{required_permission}' permission"
        )
    
    # Super admin can access all projects
    if user_role == "super_admin":
        return review
    
    # Project-specific roles must match the project
    if user_role in ["project_admin", "project_user"]:
        if int(user_project_id) != project_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: API key is restricted to project {user_project_id}, cannot access project {project_id}"
            )
    
    return review

async def verify_project_access(
    project_id: int,
    current_user: Dict[str, Any],
    db,
    required_permission: str = "read"  # "read", "write", "delete", "admin"
):
    """
    Helper function to verify project exists and user has specific permission
    
    Args:
        project_id: ID of the project
        current_user: JWT payload from API key
        db: Database session
        required_permission: Required permission level ("read", "write", "delete", "admin")
    """
    
    # Check if project exists
    project_result = await db.execute(
        select(Project).where(Project.id == project_id)
    )
    project = project_result.scalars().first()
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    # Get user info from API key
    user_role = current_user.get("role")
    user_project_id = current_user.get("project_id")
    
    if not user_role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key: missing role information"
        )
    
    # Define permission matrix
    role_permissions = {
        "super_admin": ["read", "write", "delete", "admin"],
        "project_admin": ["read", "write", "delete", "admin"],
        "project_user": ["read"]
    }
    
    # Check if role exists and has required permission
    if user_role not in role_permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: Invalid role '{user_role}'"
        )
    
    if required_permission not in role_permissions[user_role]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: Role '{user_role}' does not have '{required_permission}' permission"
        )
    
    # Super admin can access all projects
    if user_role == "super_admin":
        return project
    
    # Project-specific roles must match the project
    if user_role in ["project_admin", "project_user"]:
        if int(user_project_id) != project_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: API key is restricted to project {user_project_id}, cannot access project {project_id}"
            )
    
    return project
