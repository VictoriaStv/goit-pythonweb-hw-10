from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Request
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from slowapi.decorator import limiter
from fastapi import File, UploadFile

from src.services.cloudinary_service import upload_avatar

from src.database.models import User
from src.schemas.auth import UserCreate, UserResponse, Token
from src.services.auth import (
    get_db,
    get_password_hash,
    verify_password,
    create_access_token,
    get_current_user,
    create_email_verification_token,
    decode_email_verification_token,
    send_verification_email,
)

router = APIRouter()


@router.post("/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def signup(user: UserCreate, background_tasks: BackgroundTasks, request: Request, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user.password)
    new_user = User(
        username=user.username,
        email=user.email,
        password=hashed_password,
        confirmed=False
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = create_email_verification_token(new_user.email)
    background_tasks.add_task(send_verification_email, new_user.email, new_user.username, token, str(request.base_url))

    return new_user


@router.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    try:
        email = decode_email_verification_token(token)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.confirmed:
        raise HTTPException(status_code=400, detail="Email already verified")

    user.confirmed = True
    db.commit()
    return {"message": "Email verified successfully"}


@router.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.confirmed:
        raise HTTPException(status_code=403, detail="Email not verified")

    token = create_access_token(data={"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}


@router.get("/me", response_model=UserResponse)
@limiter.limit("5/minute")
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.patch("/avatar", response_model=UserResponse)
def update_avatar(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    avatar_url = upload_avatar(file.file, public_id=f"avatars/{current_user.email}")
    current_user.avatar = avatar_url
    db.commit()
    db.refresh(current_user)
    return current_user   
