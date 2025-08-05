# from fastapi import Depends, HTTPException, Request
# from fastapi.responses import RedirectResponse
# from starlette.middleware.base import BaseHTTPMiddleware
# from sqlalchemy.orm import Session

# from api.db.database import get_db, get_db_with_ctx_manager
# from api.v1.models.user import User
# from api.v1.services.auth import AuthService
# from api.core.dependencies.flash_messages import flash, MessageCategory


# class AuthMiddleware(BaseHTTPMiddleware):
#     async def dispatch(self, request: Request, call_next):
#         with get_db_with_ctx_manager() as db:
#             credentials_exception = HTTPException(
#                 status_code=401,
#                 detail="Could not validate credentials",
#                 headers={"WWW-Authenticate": "Bearer"},
#             )
            
#             # Define route access logic
#             unauthenticated_only_routes = [
#                 "/", "/auth/login", 
#                 "/auth/register", "/auth/request-access"
#             ]
#             protected_routes = [
#                 "/dashboard"
#             ]  # Define more as needed

#             # Check access token in cookies
#             access_token = request.cookies.get("access_token")
#             refresh_token = request.cookies.get("refresh_token")
            
#             # If route is protected, ensure user is authenticated
#             if request.url.path in protected_routes:
#                 if not access_token:
#                     flash(request, 'Please login to access this page.', MessageCategory.ERROR)
#                     return RedirectResponse(url="/auth/login", status_code=303)

#                 # Verify token
#                 try:
#                     token = AuthService.verify_access_token(
#                         db=db, 
#                         access_token=access_token, 
#                         credentials_exception=credentials_exception
#                     )
#                     user = User.fetch_by_id(
#                         db=db, 
#                         id=token.user_id, 
#                         error_message='Session expired. Please login again.'
#                     )
                    
#                 except HTTPException as e:
#                     # Try to refresh access token with refresh token
#                     try:
#                         access, refresh = AuthService.refresh_access_token(refresh_token)
        
#                         # Update access token in cookies
#                         response = RedirectResponse(url=request.url.path, status_code=303)
#                         response.set_cookie("access_token", access)
#                         response.set_cookie("refresh_token", refresh)
                        
#                         return response
                    
#                     except HTTPException as e:
#                         # If refresh token is expired, redirect to login page
#                         flash(request, e.detail, MessageCategory.ERROR)
#                         return RedirectResponse(url="/auth/login", status_code=303)
                
#                 # Attach user to request state for access in route
#                 request.state.current_user = user

#             # If route is for unauthenticated users only, redirect authenticated users
#             elif request.url.path in unauthenticated_only_routes:
#                 try:
#                     if access_token:
#                         token = AuthService.verify_access_token(
#                             db=db, 
#                             access_token=access_token, 
#                             credentials_exception=credentials_exception
#                         )
#                         user = User.fetch_by_id(
#                             db=db, 
#                             id=token.user_id, 
#                             error_message='Session expired. Please login again.'
#                         )
                        
#                         if user:
#                             return RedirectResponse(url="/dashboard", status_code=303)
                        
#                 except HTTPException as e:
#                     flash(request, e.detail, MessageCategory.ERROR)
#                     return RedirectResponse(url="/auth/login", status_code=303)
            
#             # If route is not protected or unauthenticated, proceed with request
#             # Works for both authenticated and unauthenticated users
#             else:
#                 user = None
                
#                 if access_token:
#                     token = AuthService.verify_access_token(
#                         db=db, 
#                         access_token=access_token, 
#                         credentials_exception=credentials_exception
#                     )
#                     user = User.fetch_by_id(
#                         db=db, 
#                         id=token.user_id, 
#                         error_message='Session expired. Please login again.'
#                     )
                
#                 # Attach user to request state for access in route
#                 request.state.current_user = user
                
#             # Proceed with request if no redirection is needed
#             response = await call_next(request)
#             return response


from fastapi import Request, HTTPException
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import Session

from api.db.database import get_db_with_ctx_manager
from api.v1.models.user import User
from api.v1.services.auth import AuthService
from api.core.dependencies.flash_messages import flash, MessageCategory


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)

        # Define route access
        self.unauthenticated_routes = [
            "/", "/auth/login", 
            "/auth/register", "/auth/request-access",
            # "/dashboard"
        ]
        self.protected_routes = [
            "/dashboard"
        ]

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Always open DB session
        with get_db_with_ctx_manager() as db:
            access_token = request.cookies.get("access_token")
            refresh_token = request.cookies.get("refresh_token")

            # 1️⃣ If user tries to access a protected page
            if path in self.protected_routes:
                if not access_token:
                    flash(request, "Please login to access this page.", MessageCategory.ERROR)
                    return RedirectResponse(url="/auth/login", status_code=303)
                
                user = await self._get_user_from_token(db, access_token, refresh_token, request)
                if not user:
                    flash(request, "Please login to access this page.", MessageCategory.ERROR)
                    return RedirectResponse(url="/auth/login", status_code=303)
                request.state.current_user = user
                return await call_next(request)

            # 2️⃣ If user is already logged in but visits login/register → redirect to dashboard
            if path in self.unauthenticated_routes and access_token:
                user = await self._get_user_from_token(db, access_token, refresh_token, request)
                if user:
                    return RedirectResponse(url="/dashboard", status_code=303)

            # 3️⃣ For any other route (public pages, APIs)
            if access_token:
                user = await self._get_user_from_token(db, access_token, refresh_token, request)
                request.state.current_user = user

            return await call_next(request)

    async def _get_user_from_token(
        self, 
        db: Session, 
        access_token: str, 
        refresh_token: str, 
        request: Request,
    ):
        if not access_token:
            return None
        
        credentials_exception = HTTPException(
            status_code=401,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
        try:
            token = AuthService.verify_access_token(db, access_token, credentials_exception)
            return User.fetch_by_id(db=db, id=token.user_id)
        except HTTPException as e:
            flash(request, e.detail, MessageCategory.ERROR)
            return None
            # Try refreshing the token
            # try:
            #     access, refresh = AuthService.refresh_access_token(db, refresh_token)
            #     response = RedirectResponse(url=request.url.path, status_code=303)
            #     response.set_cookie("access_token", access, httponly=True)
            #     response.set_cookie("refresh_token", refresh, httponly=True)
            #     return None  # Let user reload with new cookies
            # except HTTPException:
            #     return None
