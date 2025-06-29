from fastapi import FastAPI, Depends, HTTPException, status, Path, Body , Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from database import engine, get_db
import models, schemas, auth
from fastapi.middleware.cors import CORSMiddleware
from mail import sendmail

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

origins = [
    "http://localhost",
    "http://localhost:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.post("/users/signup", response_model=schemas.User)
def signup_user(user: schemas.SignupRequest, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = auth.get_password_hash(user.password)
    new_user = models.User(name=user.name, email=user.email, hashed_password=hashed_password, role= "customer")
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/users/login", response_model=schemas.LoginResponseWithToken)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = auth.create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer", "user": user}

@app.post("/users/reset-password")
def reset_password(request: Request,resetpass : schemas.ResetPasswordRequest,db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == resetpass.email).first()
    access_token = auth.create_access_token(data={"sub":user.email})
    base_url = str(request.base_url)
    reset_link = f"{base_url}reset-password?token={access_token}"
    print(reset_link)
    sendmail(user.email,reset_link)
    # emailing it to be implemented later for now I'm printing



async def get_current_user(token: schemas.Token, db: Session = Depends(get_db)):
    username = auth.verify_token(token.access_token)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.query(models.User).filter(models.User.email == username).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.post("/users/me",response_model=schemas.User)
async def read_users_me(current_user: models.User = Depends(get_current_user)):
    return current_user


@app.put("/users/{userId}",response_model=schemas.User)
def updateUserInfo(userId: int =Path(...),updateInfo: schemas.UpdateUserRequest = Body(...), db: Session = Depends(get_db),current_user : models.User = Depends(get_current_user)):
    if current_user.id != userId and current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized to update this user"
        )
    user = db.query(models.User).filter(models.User.id == current_user.id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    user.name= updateInfo.name
    user.phone = updateInfo.phone
    user.addresses.clear()
    for addr in updateInfo.addresses:
        user.addresses.append(
            models.Address(id=userId,street=addr.street, city=addr.city, zip=addr.zip)
        )
    user.cart_items.clear()
    for carti in updateInfo.cart:
        user.cart_items.append(
            models.CartItem(id=userId,product_id=carti.product_id,quantity=carti.quantity)
        )
    db.commit()
    db.refresh(user)
    return user
@app.put("/users/{userId}/reset-password")
def changePassword(userId: int =Path(...),newPassword: schemas.changePassword = ..., db: Session = Depends(get_db),current_user : models.User = Depends(get_current_user)):
    if current_user.id != userId and current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized to update this user"
        )
    user = db.query(models.User).filter(models.User.id == current_user.id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    user.hashed_password = auth.get_password_hash(newPassword.password)
    db.commit()
    db.refresh(user)

@app.get("/users/{userId}/role",response_model=schemas.UserRole)
async def getUserRole(current_user_role: models.User = Depends(get_current_user)):
    return current_user_role

@app.get("/reset-password")
async def reset_password_form(token: str):
    email = auth.verify_token(token)
    if not email:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    return {"msg": "Token valid. Show reset password form"}

def mock_get_current_user_for_pact():
    """A mock dependency that returns a predefined user."""
    return models.User(id=1, name='Test User', email='user@example.com', role='customer')
                       
@app.post("/pact-states")
def provider_states(state: schemas.ProviderState, db: Session = Depends(get_db)):
    print(f"Received provider state: {state.state} ({state.action})")
    
    state_mapping = {
        "An authenticated user with a valid token exists for user_id 1": setup_authenticated_user,
    }

    if state.state in state_mapping:
        state_mapping[state.state](action=state.action)
    
    return {"result": f"State '{state.state}' processed."}
def setup_authenticated_user(action: str):
    """Sets up the dependency override for an authenticated user."""
    if action == "setup":
        app.dependency_overrides[get_current_user] = mock_get_current_user_for_pact
    elif action == "teardown":
        app.dependency_overrides = {}
'''
@app.post("/_pact/provider_states")
async def provider_states(provider_state: schemas.ProviderState = Body(...)):
    print(f"Setting up provider state: {provider_state.state} for consumer: {provider_state.consumer}")
    if provider_state.state == "User an_existing_user exists":
        # Logic to ensure a user exists for the test
        # e.g., mock your get_db dependency or add a user to a test DB
        # This is highly dependent on your app's architecture
        # For your app, you might mock `db.query(models.User).filter(...).first()`
        # to return a specific user when this state is active.
        pass
    elif provider_state.state == "User a_non_existing_user does not exist":
        # Logic to ensure a user does NOT exist
        pass
    # Add more states as needed by your consumer contracts
    return {"result": f"State '{provider_state.state}' set up."}'''