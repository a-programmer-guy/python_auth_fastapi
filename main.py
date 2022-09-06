# Import JWT
import jwt
# Depends class will make is so depending on the
# result of the RequestForm, will determine what happens next
from enum import unique
from fastapi import FastAPI, Depends, HTTPException, status
# Import bcrypt for hashing passwords
from passlib.hash import bcrypt



# To secure the API, Authentication done with OAuth2PasswordBearer
# Request form with OAuthPasswordRequestForm
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# Tortoise ORM will be used for db management
from tortoise import fields
from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise.models import Model
from tortoise.contrib.fastapi import register_tortoise

# Instantiate application
app = FastAPI()

# JSON Web Token Secret
JWT_SECRET = "MyJwtSecret"

# Define user model attributes - whats going on in the db
class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(30, unique=True)
    email = fields.CharField(50, unique=True)
    password_hash = fields.CharField(128)

    def verify_password(self, password):
      return bcrypt.verify(password, self.password_hash)

# Pydantic represents whats going on with the user models when we run the app
# Create the User model defined above with tortoise ORM
User_Pydantic = pydantic_model_creator(User, name='User')
# Exclude read only - If user passes in data needed to update db
UserIn_Pydantic = pydantic_model_creator(User, name='UserIn', exclude_readonly=True)

# Oauth2 for authentication - pass in tokenURL
oauth2_scheme = OAuth2PasswordBearer(tokenUrl = 'token')

# Helper method to get current user
# Since get current user Depends on oath2_scheme it will return that lock on the users/me route beacuse
# its in the OAuth dependency chain: /users/me Depends on get_current_user which Depends on oauth2_scheme
async def get_current_user(token: str = Depends(oauth2_scheme)):
  try:
    # Decode the jwt token, get the value of id from the decoded token
    payload = jwt.decode(token, JWT_SECRET, algorithms='HS256')
    user = await User.get(id=payload.get('id'))
  except:
    raise HTTPException(
      status_code= status.HTTP_401_UNAUTHORIZED,
      detail='Invalid username or password'
    )
  # User_Pydantic is being used to pass the token, Users themselves are not passing the token
  return await User_Pydantic.from_tortoise_orm(user)

# Helper method to Authenticate the user
# Get the user from the db, verify they exist and password is valid - return user if valid
async def authenticate_user(username: str, password: str):
  user = await User.get(username=username)
  if not user:
    return False
  if not user.verify_password(password):
    return False
  return user

# POST endpoint to generate a token if the username exists and password is correct
@app.post('/token')
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
  # Authenticate the user with authenticate_user method, use form data sent in post req
  user = await authenticate_user(form_data.username, form_data.password)

  if not user:
    return {'error' : 'Invalid credentials'}

  # Convert tortoise_orm user to user pydantic obj
  user_obj = await User_Pydantic.from_tortoise_orm(user)

  # Convert user object into dictionary because this is the payload for the JWT
  token = jwt.encode(user_obj.dict(), JWT_SECRET)

  # Retrun the access token with the value of the encoded jwt token, set type to bearer
  return {'access_token' : token, 'token_type' : 'bearer'}

# POST Enpoint to add users. UserIn is for user input, User is output
@app.post('/users', response_model=User_Pydantic)
async def create_user(user: UserIn_Pydantic):
  # User object will get the username and password(hashed with bcrypt here) passed into it
  user_obj = User(username=user.username, password_hash=bcrypt.hash(user.password_hash))
  await user_obj.save()
  # Convert the user object from tortoise orm to a User_Pydantic object (response type)
  return await User_Pydantic.from_tortoise_orm(user_obj)

# GET endpoint to Get current user
# Using Pydanctic object because it Depends on the current user (will run first)
@app.get('/users/me', response_model=User_Pydantic)
async def get_user(user: User_Pydantic = Depends(get_current_user)):
  return user

# Create db with tortoise orm - pass in the app, db location, the modules containing models,
# generate schema, create table if it doesnt exist, allow handling of exceptions
register_tortoise(
  app,
  db_url='sqlite://db.registration',
  modules={'modules' : ['main']},
  generate_schemas=True,
  add_exception_handlers=True
)
