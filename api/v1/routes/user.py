from datetime import datetime, timedelta
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from decouple import config

from api.core.dependencies.email_sending_service import send_email
from api.core.dependencies.flash_messages import MessageCategory, flash
from api.db.database import get_db
from api.utils import paginator
from api.utils.payload_builder import build_payload
from api.utils.responses import success_response
from api.utils.settings import settings
from api.v1.models.user import User
from api.v1.services.auth import AuthService
from api.v1.services.user import UserService
from api.v1.schemas import user as user_schemas
from api.utils.loggers import create_logger
from api.utils.telex_notification import TelexNotification


user_router = APIRouter(prefix='/users', tags=['User'])
logger = create_logger(__name__)

@user_router.get('/me', status_code=200, response_model=success_response)
async def get_current_user(db: Session=Depends(get_db), user: User=Depends(AuthService.get_current_user)):
    """Endpoint to get the current user

    Args:
        db (Session, optional): Database session. Defaults to Depends(get_db).
        user (User, optional): Current user. Defaults to Depends(AuthService.get_current_user).
    """
    
    return success_response(
        status_code=200,
        message='User fetched successfully',
        data=user.to_dict()
    )

@user_router.post('/me/edit', status_code=200, response_model=success_response)
async def update_user_details(
    payload: user_schemas.UpdateUser,
    db: Session=Depends(get_db), 
    user: User=Depends(AuthService.get_current_user)
):
    """Endpoint to a user to update their details"""
    
    if payload.password and payload.old_password:
        payload.password = UserService.verify_password_change(
            db, 
            email=payload.email,
            old_password=payload.old_password,
            new_password=payload.password
        ) 
    
    if payload.email and payload.email != user.email:
        user = User.fetch_one_by_field(db, throw_error=False, email=payload.email)
        if user:
            raise HTTPException(400, 'Email already in use')
    
    user = User.update(
        db,
        id=user.id,
        **payload.model_dump(exclude_unset=True)
    )
            
    return success_response(
        status_code=200,
        message='Details updated successfully',
        data=user.to_dict()
    )
    

@user_router.post('/{id}/edit')
async def edit_user(
    id: str,
    request: Request,
    db: Session=Depends(get_db), 
):
    """Endpoint to a user to update their details"""
    
    try:
        current_user = request.state.current_user
        AuthService.is_user_admin(db, current_user.id)
        user = User.fetch_by_id(db, id, 'User does not exist')
        
        payload = await build_payload(request, boolean_fields=['is_active', 'is_approved', 'is_admin'])
        
        if payload.get('email') and payload.get('email') != user.email:
            existing_user = User.fetch_one_by_field(db, throw_error=False, email=payload.get('email'))
            if existing_user:
                raise HTTPException(400, 'Email already in use')

        user = User.update(
            db,
            id=id,
            **payload
        )
                
    except HTTPException as e:
        # Preserve form data on error
        flash(request, e.detail, MessageCategory.ERROR)

    return RedirectResponse(url='/dashboard/users', status_code=303)


@user_router.post('/{id}/delete')
async def delete_user(
    id: str,
    request: Request,
    db: Session=Depends(get_db), 
):
    """Endpoint to a user to update their details"""
    
    current_user = request.state.current_user
    AuthService.is_user_admin(db, current_user.id)
    user = User.fetch_by_id(db, id, 'User does not exist')
    
    user = User.delete(
        db,
        id=id,
    )
            
    return RedirectResponse(url='/dashboard/users', status_code=303)
