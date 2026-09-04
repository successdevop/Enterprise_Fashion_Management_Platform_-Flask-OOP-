from typing import Annotated

from fastapi import APIRouter, status, Depends
from fastapi.security import OAuth2PasswordRequestForm

from app.dependencies.auth_service import AuthServiceDep
from app.dependencies.user_dep import CurrentAuthDep
from app.schemas.identity.user import UserCreate, UserRead, TokenResponse
from app.security.schema.auth import AuthSessionRead

auth_router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)


@auth_router.post("/sign_up", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def user_registration_account(auth_service: AuthServiceDep, user_data: UserCreate):
    return await auth_service.register_user(user_data=user_data)


@auth_router.post("/sign_in", response_model=TokenResponse, status_code=status.HTTP_200_OK)
async def sign_in_user(auth_service: AuthServiceDep, login_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    return await auth_service.login_user(email=login_data.username, password=login_data.password)


@auth_router.post("/refresh", response_model=TokenResponse, status_code=status.HTTP_200_OK)
async def refresh_token(auth_service: AuthServiceDep, token: str):
    return await auth_service.refresh_token_generation(refresh_token=token)


@auth_router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(auth_service: AuthServiceDep, current_auth: CurrentAuthDep):
    return await auth_service.logout(user_id=current_auth.user_id, session_id=current_auth.session_id)


@auth_router.post("/logout_all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(auth_service: AuthServiceDep, current_auth: CurrentAuthDep):
    return await auth_service.logout_of_all_sessions(user_id=current_auth.user_id)


@auth_router.get("/sessions", response_model=AuthSessionRead, status_code=status.HTTP_200_OK)
async def get_sessions(auth_service: AuthServiceDep, current_auth: CurrentAuthDep):
    return await auth_service.get_all_sessions(user_id=current_auth.user_id)


@auth_router.get("/me")
async def get_me(current_auth: CurrentAuthDep):
    return current_auth