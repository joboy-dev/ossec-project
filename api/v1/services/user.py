from datetime import datetime
from fastapi import BackgroundTasks, HTTPException, Request
from fastapi.datastructures import FormData
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from decouple import config

from api.core.dependencies.email_sending_service import send_email
from api.core.dependencies.flash_messages import MessageCategory, flash
from api.utils.loggers import create_logger
from api.utils.telex_notification import TelexNotification
from api.v1.models.token import TokenType
from api.v1.models.user import User
# from api.v1.models.user_profile import UserProfile
from api.v1.schemas.auth import CreateUser
from api.v1.schemas.user import UpdateUser
from api.v1.services.auth import AuthService
from api.v1.services.token import TokenService


logger = create_logger(__name__)

class UserService:
    @classmethod
    def create(
        cls, 
        # request: Request, 
        db: Session, 
        payload: FormData, 
        bg_tasks: BackgroundTasks,
        is_active: bool = False,
        is_admin: bool = False,
        create_token: bool = True
    ):
        """Creates a new user"""
        
        _, _, count = User.fetch_by_field(db=db, paginate=False)
        if count > 0:
            raise HTTPException(400, 'An account already exists for this server')
        
        email = payload.get('email').lower().strip()
        user_with_email_exists = User.fetch_one_by_field(db, throw_error=False, email=email)
        if user_with_email_exists:
            raise HTTPException(400, 'User with email already exist')
        
        password = payload.get('password')
        confirm_password = payload.get('confirm_password')
        if password != confirm_password:
            raise HTTPException(400, 'Passwords do not match')
        
        password = AuthService.hash_secret(password)
        
        new_user = User.create(
            db=db,
            email=email,
            username=email.split('@')[0],
            password=password,
            is_active=is_active,
            is_admin=is_admin
        )
        
        if create_token:
            access_token = AuthService.create_access_token(db, new_user.id)
            refresh_token = AuthService.create_refresh_token(db, new_user.id)
        else:
            access_token = None
            refresh_token = None
        
        user_dict = new_user.__dict__.copy()
        
        # TODO: Update the url
        # bg_tasks.add_task(
        #     send_email,
        #     recipients=[new_user.email],
        #     template_name='welcome.html',
        #     subject='Welcome to Wren',
        #     template_data={
        #         'user': user_dict,
        #         'dashboard_url': f"{config('APP_URL')}/dashboard"
        #     }
        # )
        
        return new_user, access_token, refresh_token
    
    @classmethod
    def verify_password_change(cls, db: Session, email: str, old_password: str, new_password: str):
        """Fucntion to change user password"""
        
        user, _, _ = AuthService.authenticate(
            db, 
            email=email, 
            password=old_password, 
            create_token=False
        )
        
        if new_password == old_password:
            raise HTTPException(400, 'New and old password cannot be the same')
        
        password_hash = AuthService.hash_secret(new_password)
        
        return password_hash
    
    @classmethod
    def change_email(cls, db: Session, payload: UpdateUser, user_id: str):
        user = User.fetch_one_by_field(db, throw_error=False, email=payload.email)
        if user:
            raise HTTPException(400, 'Email already in use')
        
        user = User.update(db, user_id, email=payload.email)
        return user

    @classmethod
    async def send_account_reactivation_token(cls, db: Session, email: str, bg_tasks: BackgroundTasks):
        """Function to send account reactivation token to user"""
        
        user = User.fetch_one_by_field(db=db, email=email)
        
        # Generate a account reactivation token
        expiry_minutes = 1440  # 24 hours
        account_reactivation_token = TokenService.create_token(
            db=db, 
            token_type=TokenType.ACCOUNT_REACTIVATION.value,
            expiry_in_minutes=expiry_minutes,
            user_id=user.id,
        )
        
        # TODO: Update the url
        # bg_tasks.add_task(
        #     send_email,
        #     recipients=[user.email],
        #     template_name='account-reactivate-request.html',
        #     subject='Reactivate your account',
        #     template_data={
        #         'user': user,
        #         'reactivation_url': f"{config('APP_URL')}/users/reactivate-account",
        #         'token': account_reactivation_token,
        #         'expiry_hours': expiry_minutes/60
        #     }
        # )
        
        return account_reactivation_token

    @classmethod
    def verify_account_reactivation_token(cls, db: Session, token: str):
        """Function to verify the account reactivation token"""
        
        credentials_exception = HTTPException(
            status_code=401, detail="Invalid token"
        )
        
        user_id = AuthService.verify_token(
            db=db,
            token=token,
            expected_token_type=TokenType.ACCOUNT_REACTIVATION.value,
            credentials_exception=credentials_exception
        )
        
        TokenService.revoke_token(db, token, user_id)
        
        return user_id  
