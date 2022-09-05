# Depends class will make is so depending on the
# result of the RequestForm, will determine what happens next
from enum import unique
from fastapi import FastAPI, Depends

# To secure the API, Authentication done with OAuth2PasswordBearer
# Request form with OAuthPasswordRequestForm
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# Tortoise ORM will be used for db management
from tortoise import fields
from tortoise.models import Model
from tortoise.contrib.fastapi import register_tortoise

# Create use model
class User(model):
    id = fields.IntField(pk=True)
    username = fields.CharField(30, unique=True)
    password_hash = fields.CharField(128)
    #Helper funtions to get username and verify the hashed password
    @classmethod
    async def get_user(cls, username):
      return cls.get(username=username)

    def verify_password(self, password):
      return True

# Create database - pass in the app, db location, the modules containing models,
# generate schema, will make the table if it doesnt exist, allow handling of exceptions
register_tortoise(
  app,
  db_url='sqlite://db.register'
  modules={'modules' : ['main']},
  generate_schema=True
  add_exception_handler=True
)

# Instantiate application
app = FastAPI()

# Oauth2 for authentication - pass in tokenURL - we create the endpoint
oauth2_scheme = OAuth2PasswordBearer(tokenUrl = 'token')

# Create a endpoint for post request that generates a token
@app.post('/token')
async def token(form_data: OAuth2PasswordRequestForm = Depends()):
  return{'access_token' : form_data.username + 'token'}

# Calls oath2_scheme to see if there is a token available,if so pass it into token
@app.get('/')
async def index(token: str = Depends(oauth2_scheme)):
  return { 'the_token' : token }


