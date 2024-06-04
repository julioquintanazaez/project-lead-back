from fastapi import Depends, FastAPI, HTTPException, status, Response, Security, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from functools import lru_cache
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.sql import func
from sqlalchemy.sql.expression import case
from sqlalchemy import desc, asc
from uuid import uuid4
from pathlib import Path
from typing import Union
from datetime import datetime, timedelta
#---Imported for JWT example-----------
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, ValidationError
from typing_extensions import Annotated
import models
import schemas
from database import SessionLocal, engine 
import init_db
import config
from fpdf import FPDF
from fpdf_table import PDFTable, Align, add_image_local
import asyncio
import concurrent.futures

models.Base.metadata.create_all(bind=engine)

#Create resources for JWT flow
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(
	tokenUrl="token",
	scopes={"admin": "Add, edit and delete information.", "manager": "Create and read information.", "user": "Read information."}
)
#----------------------
#Create our main app
app = FastAPI()

#----SETUP MIDDLEWARES--------------------
# Allow these origins to access the API
origins = [	
	"https://projects-maneger.onrender.com",
	"https://projects-maneger.onrender.com",		
	"http://localhost",
	"http://localhost:8080",
	"https://localhost:8080",
	"http://localhost:5000",
	"https://localhost:5000",
	"http://localhost:3000",
	"https://localhost:3000",
	"http://localhost:8000",
	"https://localhost:8000",
]

# Allow these methods to be used
methods = ["GET", "POST", "PUT", "DELETE"]

# Only these headers are allowed
headers = ["Content-Type", "Authorization"]

app.add_middleware(
	CORSMiddleware,
	allow_origins=origins,
	allow_credentials=True,
	allow_methods=methods,
	allow_headers=headers,
	expose_headers=["*"]
)

ALGORITHM = config.ALGORITHM	
SECRET_KEY = config.SECRET_KEY
APP_NAME = config.APP_NAME
ACCESS_TOKEN_EXPIRE_MINUTES = config.ACCESS_TOKEN_EXPIRE_MINUTES
ADMIN_USER = config.ADMIN_USER
ADMIN_NAME = config.ADMIN_NAME
ADMIN_EMAIL = config.ADMIN_EMAIL
ADMIN_PASS = config.ADMIN_PASS

# Dependency
def get_db():
	db = SessionLocal()
	try:
		yield db
	finally:
		db.close()


#------CODE FOR THE JWT EXAMPLE----------
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db: Session, username: str):
	db_user = db.query(models.User).filter(models.User.username == username).first()	
	if db_user is not None:
		return db_user 

#This function is used by "login_for_access_token"
def authenticate_user(username: str, password: str,  db: Session = Depends(get_db)):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password): #secret
        return False
    return user
	
#This function is used by "login_for_access_token"
def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=30) #Si no se pasa un valor por usuario
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
	
#This function is used by "get currecnt active user" dependency security authentication
async def get_current_user(
			security_scopes: SecurityScopes, 
			token: Annotated[str, Depends(oauth2_scheme)],
			db: Session = Depends(get_db)):
	if security_scopes.scopes:
		authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
	else:
		authenticate_value = "Bearer"
		
	credentials_exception = HTTPException(
		status_code=status.HTTP_401_UNAUTHORIZED,
		detail="Could not validate credentials",
		headers={"WWW-Authenticate": "Bearer"},
	)
	try:
		payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
		username: str = payload.get("sub")
		if username is None:
			raise credentials_exception			
		token_scopes = payload.get("scopes", [])
		token_data = schemas.TokenData(scopes=token_scopes, username=username)
		
	except (JWTError, ValidationError):
		raise credentials_exception
			
		token_data = schemas.TokenData(username=username)
	except JWTError:
		raise credentials_exception
		
	user = get_user(db, username=token_data.username)
	if user is None:
		raise credentials_exception
		
	for user_scope in security_scopes.scopes:
		if user_scope not in token_data.scopes:
			raise HTTPException(
				status_code=status.HTTP_401_UNAUTHORIZED,
				detail="Not enough permissions",
				headers={"WWW-Authenticate": authenticate_value},
			)
			
	return user
	
async def get_current_active_user(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["admin"])]):  
	if current_user.disable:
		print({"USER AUTENTICATED" : current_user.disable})
		print({"USER ROLES" : current_user.role})
		raise HTTPException(status_code=400, detail="Disable user")
	return current_user

#------------------------------------
@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db)):
	user = authenticate_user(form_data.username, form_data.password, db)
	if not user:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Incorrect username or password",
			headers={"WWW-Authenticate": "Bearer"},
		)
	access_token_expires = timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
	print(form_data.scopes)
	print(user.role)
	access_token = create_access_token(
		data={"sub": user.username, "scopes": user.role},   #form_data.scopes
		expires_delta=access_token_expires
	)
	return {"detail": "Ok", "access_token": access_token, "token_type": "Bearer"}
	
@app.get("/")
def index():
	return {"Application": "Hello from developers"}
	
@app.get("/users/me", response_model=schemas.User)
async def read_users_me(current_user: Annotated[schemas.User, Depends(get_current_user)]):
	return current_user
	
@app.get("/get_restricted_user")
async def get_restricted_user(current_user: Annotated[schemas.User, Depends(get_current_active_user)]):
    return current_user
	
@app.get("/get_authenticated_admin_resources", response_model=schemas.User)
async def get_authenticated_admin_resources(current_user: Annotated[schemas.User, Security(get_current_active_user, scopes=["manager"])]):
    return current_user
	
@app.get("/get_authenticated_edition_resources", response_model=schemas.User)
async def get_authenticated_edition_resources(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["user"])]):
    return current_user


#########################
###   USERS ADMIN  ######
#########################
@app.post("/create_owner", status_code=status.HTTP_201_CREATED)  
async def create_owner(db: Session = Depends(get_db)): #Por el momento no tiene restricciones
	if db.query(models.User).filter(models.User.username == config.ADMIN_USER).first():
		db_user = db.query(models.User).filter(models.User.username == config.ADMIN_USER).first()
		if db_user is None:
			raise HTTPException(status_code=404, detail="User not found")	
		db.delete(db_user)	
		db.commit()
		
	db_user = models.User(
		username=config.ADMIN_USER, 
		full_name=config.ADMIN_NAME,
		email=config.ADMIN_EMAIL,
		role=["admin","manager","user"],
		disable=False,
		hashed_password=pwd_context.hash(config.ADMIN_PASS)		
	)
	db.add(db_user)
	db.commit()
	db.refresh(db_user)	
	return {f"User:": "Succesfully created"}
	
@app.post("/create_user/", status_code=status.HTTP_201_CREATED)  
async def create_user(current_user: Annotated[schemas.User, Depends(get_current_active_user)],
				user: schemas.User, db: Session = Depends(get_db)): 
	if db.query(models.User).filter(models.User.username == user.username).first() :
		raise HTTPException( 
			status_code=400,
			detail="The user with this email already exists in the system",
		)	
	db_user = models.User(
		username=user.username, 
		full_name=user.full_name,
		email=user.email,
		role=user.role,
		disable=False,
		hashed_password=pwd_context.hash(user.hashed_password)
	)
	db.add(db_user)
	db.commit()
	db.refresh(db_user)	
	return {f"User: {db_user.username}": "Succesfully created"}
	
@app.get("/read_users/", status_code=status.HTTP_201_CREATED) 
async def read_users(current_user: Annotated[schemas.User, Depends(get_current_active_user)],
		skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    	
	db_users = db.query(models.User).offset(skip).limit(limit).all()    
	return db_users

@app.put("/update_user/{user_id}", status_code=status.HTTP_201_CREATED) 
async def update_user(current_user: Annotated[schemas.User, Depends(get_current_active_user)], 
				user_id: str, new_user: schemas.UserUPD, db: Session = Depends(get_db)):
	db_user = db.query(models.User).filter(models.User.user_id == user_id).first()
	if db_user is None:
		raise HTTPException(status_code=404, detail="User not found")
	db_user.username=new_user.username
	db_user.full_name=new_user.full_name
	db_user.email=new_user.email	
	db_user.role=new_user.role
	db.commit()
	db.refresh(db_user)	
	return db_user	
	
@app.put("/activate_user/{user_id}", status_code=status.HTTP_201_CREATED) 
async def activate_user(current_user: Annotated[schemas.User, Depends(get_current_active_user)],
				user_id: str, new_user: schemas.UserActivate, db: Session = Depends(get_db)):
	db_user = db.query(models.User).filter(models.User.user_id == user_id).first()
	if db_user is None:
		raise HTTPException(status_code=404, detail="User not found")
	if username != "_admin" and username != current_user.username:
		db_user.disable=new_user.disable		
		db.commit()
		db.refresh(db_user)	
	return db_user	
	
@app.delete("/delete_user/{user_id}", status_code=status.HTTP_201_CREATED) 
async def delete_user(current_user: Annotated[schemas.User, Depends(get_current_active_user)],
				user_id: str, db: Session = Depends(get_db)):
	db_user = db.query(models.User).filter(models.User.user_id == user_id).first()
	if db_user is None:
		raise HTTPException(status_code=404, detail="User not found")	
	if username != "_admin" and username != current_user.username:
		db.delete(db_user)	
		db.commit()
	return {"Deleted": "Delete user successfuly"}
	
@app.put("/reset_password/{user_id}", status_code=status.HTTP_201_CREATED) 
async def reset_password(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
				user_id: str, password: schemas.UserPassword, db: Session = Depends(get_db)):
	db_user = db.query(models.User).filter(models.User.user_id == user_id).first()
	if db_user is None:
		raise HTTPException(status_code=404, detail="User not found")	
	db_user.hashed_password=pwd_context.hash(password.hashed_password)
	db.commit()
	db.refresh(db_user)	
	return {"Result": "Password updated successfuly"}
	
@app.put("/reset_password_by_user/{user_id}", status_code=status.HTTP_201_CREATED) 
async def reset_password_by_user(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
				user_id: str, password: schemas.UserResetPassword, db: Session = Depends(get_db)):
				
	if not verify_password(password.actualpassword, current_user.hashed_password): 
		return HTTPException(status_code=700, detail="Actual password doesn't match")
		
	db_user = db.query(models.User).filter(models.User.user_id == user_id).first()	
	if db_user is None:
		raise HTTPException(status_code=404, detail="User not found")	
	db_user.hashed_password=pwd_context.hash(password.newpassword)
	db.commit()
	db.refresh(db_user)	
	return {"response": "Password updated successfuly"}
		
#######################
#CRUD for PROJECTS here
#######################

@app.post("/create_project/", status_code=status.HTTP_201_CREATED)  #, response_model=schemas.Project
async def create_project(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					project: schemas.Project, db: Session = Depends(get_db)):	
	
	db_project = db.query(models.Project).filter(models.Project.project_name == project.project_name).first()
	
	if db_project is None:
		try:		
			db_project = models.Project(
				project_name=project.project_name, 
				project_type=project.project_type,
				project_date=func.now(),
				user_project_id=project.user_project_id
			)
			db.add(db_project)
			db.commit()
			db.refresh(db_project)				
			return db_project
			
		except IntegrityError as e:
			raise HTTPException(status_code=500, detail="Integrity error")
		except SQLAlchemyError as e: 
			raise HTTPException(status_code=405, detail="Unexpected error when creating project")	
	else:
		raise HTTPException(status_code=700, detail="This project alredy exist in the database")
		
@app.get("/read_projects/", status_code=status.HTTP_201_CREATED) 
async def read_projects(current_user: Annotated[schemas.User, Depends(get_current_active_user)],
		skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    	
	db_projects = db.query(models.Project).offset(skip).limit(limit).all()    
	return db_projects

@app.put("/update_project/{project_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
async def update_project(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					project_id: str, project: schemas.ProjectUPD, db: Session = Depends(get_db)):
	
	db_project = db.query(models.Project).filter(models.Project.project_id == project_id).first()
	
	if db_project is None:
		raise HTTPException(status_code=404, detail="Project not found in database")
	
	db_project.project_name = project.project_name
	db_project.project_type = project.project_type
	db_project.project_date = func.now()
	db.commit()
	db.refresh(db_project)	
	
	return db_project
	
@app.delete("/delete_project/{project_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
async def delete_project(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					project_id: str, db: Session = Depends(get_db)):
	
	db_project = db.query(models.Project).filter(models.Project.project_id == project_id).first()
	
	if db_project is None:
		raise HTTPException(status_code=404, detail="Project not found in database")	
	
	db.delete(db_project)	
	db.commit()
	
	return {"Deleted": "Project deleted successfuly"}
	
@app.get("/read_all_projects_with_totals/", status_code=status.HTTP_201_CREATED)
async def read_all_projects_with_totals(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
								skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	#Read tasks							
	sub_task = db.query(
		models.Task.labor_task_id,		
		func.sum(models.Task.task_price).label("task_amount")
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	sub_equipment = db.query(
		models.Equipment.labor_equipment_id,		
		func.sum(models.Equipment.equipment_amount).label("equipment_amount"),
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	labor_query = db.query(
		models.Labor.project_labor_id,	
		func.sum(
			case([(sub_task.c.task_amount == None, 0)], else_= sub_task.c.task_amount) +
			case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount)
		).label('labor_amount')
	).select_from(
		models.Labor
	).outerjoin(
		sub_equipment, models.Labor.labor_id == sub_equipment.c.labor_equipment_id
	).outerjoin(
		sub_task, models.Labor.labor_id == sub_task.c.labor_task_id
	).group_by(
		models.Labor.labor_id
	).subquery()
	
	sub_material = db.query(
		models.Material.project_material_id,
		func.sum(models.Material.material_amount).label("material_amount"),
	).group_by(
		models.Material.project_material_id, models.Material.material_type
	).subquery()

	project_query = db.query(
		models.Project.project_id,
		models.Project.project_name,
		models.Project.project_type,
		models.Project.project_date,	
		func.sum(case([(labor_query.c.labor_amount == None, 0)], else_= labor_query.c.labor_amount) +
				case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)
				).label('project_amount'),		
	).select_from(
		models.Project
	).outerjoin(
		labor_query, models.Project.project_id == labor_query.c.project_labor_id
	).outerjoin(
		sub_material, models.Project.project_id == sub_material.c.project_material_id
	).group_by(
		models.Project.project_id
	).all()
		
	return project_query

@app.get("/read_project_items_totals/", status_code=status.HTTP_201_CREATED)
async def read_project_items_totals(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
							skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	#Read tasks							
	sub_task = db.query(
		models.Task.labor_task_id,	
		models.Task.task_price,
		func.sum(models.Task.task_price).label("task_amount"),
		func.count(models.Task.task_id).label("task_number"),
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	sub_equipment = db.query(
		models.Equipment.labor_equipment_id,		
		func.sum(models.Equipment.equipment_amount).label("equipment_amount"),
		func.count(models.Equipment.equipment_id).label("equipment_number"),
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	labor_query = db.query(
		models.Labor.project_labor_id,	
		sub_task.c.task_amount.label('labor_task_amount'),
		sub_equipment.c.equipment_amount.label('labor_equipment_amount'),
		func.count(models.Labor.labor_id).label("labors_number"),
	).select_from(
		models.Labor
	).outerjoin(
		sub_equipment, models.Labor.labor_id == sub_equipment.c.labor_equipment_id
	).outerjoin(
		sub_task, models.Labor.labor_id == sub_task.c.labor_task_id
	).group_by(
		models.Labor.project_labor_id,
	).subquery()
	
	sub_material = db.query(
		models.Material.project_material_id,
		func.sum(models.Material.material_amount).label('material_amount'),
		func.count(models.Material.material_id).label("materials_number"),
	).group_by(
		models.Material.project_material_id
	).subquery()	
	
	project_query = db.query(
		models.Project.project_id,
		sub_material.c.material_amount.label("material_amount"),
		labor_query.c.labor_task_amount.label("labor_task_amount"),
		labor_query.c.labor_equipment_amount.label("labor_equipment_amount"),
		func.sum(case([(labor_query.c.labor_task_amount == None, 0)], else_= labor_query.c.labor_task_amount) +
				 case([(labor_query.c.labor_equipment_amount == None, 0)], else_= labor_query.c.labor_equipment_amount) +
				 case([(sub_material.c.material_amount == None, 0)], else_= sub_material.c.material_amount)				 
				 ).label('project_amount'),		
	).select_from(
		models.Project
	).outerjoin(
		labor_query, models.Project.project_id == labor_query.c.project_labor_id
	).outerjoin(
		sub_material, models.Project.project_id == sub_material.c.project_material_id
	).group_by(
		models.Project.project_id
	).all()
		
	return project_query
	
@app.get("/read_project_items_total_by_project_id/{project_id}", status_code=status.HTTP_201_CREATED)
async def read_project_items_total_by_project_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
							project_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	project_labor_task_query = db.query(
		models.Labor.project_labor_id,
		func.sum(models.Task.task_price).label("task_amount"),
		func.count(models.Task.task_id).label("task_number"),
	).select_from(
		models.Labor
	).outerjoin(
		models.Task, models.Labor.labor_id == models.Task.labor_task_id
	).group_by(
		models.Labor.project_labor_id
	).where(
		models.Labor.project_labor_id == project_id,
	).subquery()
	
	project_labor_equipment_query = db.query(
		models.Labor.project_labor_id,
		func.sum(models.Equipment.equipment_amount).label("equipment_amount"),
		func.count(models.Equipment.equipment_id).label("equipment_number"),
	).select_from(
		models.Labor
	).outerjoin(
		models.Equipment, models.Labor.labor_id == models.Equipment.labor_equipment_id
	).group_by(
		models.Labor.project_labor_id
	).where(
		models.Labor.project_labor_id == project_id,
	).subquery()
	
	project_material = db.query(
		models.Material.project_material_id,
		func.sum(models.Material.material_amount).label('material_amount'),
		func.count(models.Material.material_id).label("materials_number"),
	).group_by(
		models.Material.project_material_id
	).subquery()		
	
	project_query = db.query(
		project_labor_task_query.c.task_amount,
		project_labor_task_query.c.task_number,
		project_labor_equipment_query.c.equipment_amount,
		project_labor_equipment_query.c.equipment_number,
		project_material.c.material_amount,
		project_material.c.materials_number,			
	).select_from(
		models.Project
	).outerjoin(
		project_labor_task_query, models.Project.project_id == project_labor_task_query.c.project_labor_id
	).outerjoin(
		project_labor_equipment_query, models.Project.project_id == project_labor_equipment_query.c.project_labor_id
	).outerjoin(
		project_material, models.Project.project_id == project_material.c.project_material_id
	).filter(
		models.Project.project_id == project_id
	).all()	
		
	return project_query
		
@app.get("/read_project_materials_total_by_id/{project_id}", status_code=status.HTTP_201_CREATED)
async def read_project_materials_total_by_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
							project_id: str,	skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	
	sub_material = db.query(
		models.Material.project_material_id,
		models.Material.material_type,
		func.sum(models.Material.material_amount).label('material_amount'),
	).group_by(
		models.Material.project_material_id, models.Material.material_type
	).subquery()	
	
	project_materials_query = db.query(
		models.Project.project_id,
		models.Project.project_name,
		models.Project.project_type,
		models.Project.project_date,
		sub_material.c.material_type,
		sub_material.c.material_amount
	).select_from(
		models.Project
	).outerjoin(
		sub_material, models.Project.project_id == sub_material.c.project_material_id
	).filter(
		models.Project.project_id == project_id
	).group_by(
		sub_material.c.material_type
	).all()
		
	return project_materials_query
	
@app.get("/read_project_labors_total_by_id/{project_id}", status_code=status.HTTP_201_CREATED)
async def read_project_labors_total_by_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
							project_id: str,	skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	#Read tasks							
	sub_task = db.query(
		models.Task.labor_task_id,		
		func.sum(models.Task.task_price).label("task_price"),
	).group_by(
		models.Task.labor_task_id
	).subquery()
	
	sub_equipment = db.query(
		models.Equipment.labor_equipment_id,		
		func.sum(models.Equipment.equipment_amount).label("equipment_amount"),
	).group_by(
		models.Equipment.labor_equipment_id
	).subquery()
	
	project_labors_query = db.query(
		models.Labor.labor_id,
		models.Labor.labor_type,
		sub_task.c.task_price.label('labor_task_price'),
		sub_equipment.c.equipment_amount.label('labor_equipment_amount'),
		func.sum(
			case([(sub_task.c.task_price == None, 0)], else_= sub_task.c.task_price) +
			case([(sub_equipment.c.equipment_amount == None, 0)], else_= sub_equipment.c.equipment_amount)
		).label('labor_amount')
	).select_from(
		models.Labor
	).outerjoin(
		sub_equipment, models.Labor.labor_id == sub_equipment.c.labor_equipment_id
	).outerjoin(
		sub_task, models.Labor.labor_id == sub_task.c.labor_task_id
	).group_by(
		models.Labor.labor_type
	).filter(
		models.Labor.project_labor_id == project_id
	).all()
		
	return project_labors_query
	
##########################
#CRUD for MATERIALS here
##########################

@app.post("/create_material/", status_code=status.HTTP_201_CREATED)  #, response_model=schemas.Project
async def create_material(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					material: schemas.Material, db: Session = Depends(get_db)):		
	
	db_parent_project = db.query(models.Project).filter(models.Project.project_id == material.project_material_id).first()
		
	if 	db_parent_project is not None:	
	
		try:			
			db_material = models.Material(
				material_name=material.material_name,
				material_type=material.material_type,
				material_quantity=material.material_quantity,
				material_price=material.material_price,
				material_amount=(material.material_quantity * material.material_price),
				project_material_id=material.project_material_id, 
			)				
			db.add(db_material)   	
			db.commit()
			db.refresh(db_material)			
			return db_material
			
		except SQLAlchemyError as e: 
			raise HTTPException(status_code=405, detail="Unexpected error when creating material")
			
	else:
		raise HTTPException(status_code=700, detail="Project for the material dosent exists in the database")

@app.get("/read_materials/", status_code=status.HTTP_201_CREATED) 
async def read_materials(current_user: Annotated[schemas.User, Depends(get_current_active_user)],
		skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    	
	db_materials = db.query(models.Material).offset(skip).limit(limit).all()    
	return db_materials
	
@app.get("/read_project_materials_project_by_id/{project_id}", status_code=status.HTTP_201_CREATED)
async def read_project_materials_project_by_id(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
							project_id: str,	skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    
	
	sub_material = db.query(
		models.Material.project_material_id,
		models.Material.material_id.label("material_id"),
		models.Material.material_type.label("material_type"),
		models.Material.material_name.label("material_name"),
		models.Material.material_quantity.label("material_quantity"),
		models.Material.material_price.label("material_price"),
		models.Material.material_amount.label("material_amount")		
	).subquery()	
	
	project_materials_query = db.query(
		models.Project.project_id,
		sub_material.c.material_id,
		sub_material.c.material_type,
		sub_material.c.material_name,
		sub_material.c.material_quantity,
		sub_material.c.material_price,
		sub_material.c.material_amount,
	).select_from(
		models.Project
	).outerjoin(
		sub_material, models.Project.project_id == sub_material.c.project_material_id
	).filter(
		models.Project.project_id == project_id
	).order_by(
		sub_material.c.material_type
	).all()
		
	return project_materials_query
	
@app.put("/update_material/{material_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
async def update_material(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					material_id: str, material: schemas.MaterialUPD, db: Session = Depends(get_db)):
	
	db_material = db.query(models.Material).filter(models.Material.material_id == material_id).first()
	if db_material is None:
		raise HTTPException(status_code=404, detail="Material not found")
	db_material.material_quantity=material.material_quantity
	db_material.material_price=material.material_price
	db_material.material_amount=(material.material_quantity * material.material_price)
	db.commit()
	db.refresh(db_material)	
	return db_material
	
@app.delete("/delete_material/{material_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
async def delete_material(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					material_id: str, db: Session = Depends(get_db)):
	
	db_material = db.query(models.Material).filter(models.Material.material_id == material_id).first()
	
	if db_material is None:
		raise HTTPException(status_code=404, detail="Material not found in database")	
	
	db.delete(db_material)	
	db.commit()
	
	return {"Deleted": "Material deleted successfuly"}
	
#####################
#CRUD for LABORS here
#####################

@app.post("/create_labor/", status_code=status.HTTP_201_CREATED)  #, response_model=schemas.Project
async def create_labor(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					labor: schemas.Labor, db: Session = Depends(get_db)):		
	
	db_parent_project = db.query(models.Project).filter(models.Project.project_id == labor.project_labor_id).first()
		
	if 	db_parent_project is not None:	
	
		try:			
			db_labor = models.Labor(
				labor_type=labor.labor_type,
				project_labor_id=labor.project_labor_id, 
			)				
			db.add(db_labor)   	
			db.commit()
			db.refresh(db_labor)			
			return db_labor
			
		except SQLAlchemyError as e: 
			raise HTTPException(status_code=405, detail="Unexpected error when creating labor")
			
	else:
		raise HTTPException(status_code=700, detail="Project for the labor dosent exists in the database")
		
@app.get("/read_labors/", status_code=status.HTTP_201_CREATED) 
async def read_labors(current_user: Annotated[schemas.User, Depends(get_current_active_user)],
		skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):    	
	db_labors = db.query(models.Labor).offset(skip).limit(limit).all()    
	return db_labors
	
@app.get("/read_labors_by_project_id/{project_id}", status_code=status.HTTP_201_CREATED) 
async def read_labors_by_project_id(current_user: Annotated[schemas.User, Depends(get_current_active_user)],
		project_id: str, db: Session = Depends(get_db)):    	
	
	db_labors = db.query(models.Labor).filter(models.Labor.project_labor_id == project_id).all()  
	
	return db_labors
	
@app.put("/update_labor/{labor_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
async def update_labor(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					labor_id: str, labor: schemas.LaborUPD, db: Session = Depends(get_db)):
	
	db_labor = db.query(models.Labor).filter(models.Labor.labor_id == labor_id).first()
	if db_labor is None:
		raise HTTPException(status_code=404, detail="Labor not found")
	db_labor.labor_type=labor.labor_type
	db.commit()
	db.refresh(db_labor)	
	return db_labor
	
@app.delete("/delete_labor/{labor_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
async def delete_labor(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					labor_id: str, db: Session = Depends(get_db)):
	
	db_labor = db.query(models.Labor).filter(models.Labor.labor_id == labor_id).first()	
	if db_labor is None:
		raise HTTPException(status_code=404, detail="Labor not found in database")		
	db.delete(db_labor)	
	db.commit()	
	return {"Deleted": "Labor deleted successfuly"}
	
#########################	
#  CRUD for TASK here 
#########################

@app.post("/create_task/", status_code=status.HTTP_201_CREATED) 
async def create_task(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
				task: schemas.Task, db: Session = Depends(get_db)):		
	
	db_parent_labor = db.query(models.Labor).filter(models.Labor.labor_id == task.labor_task_id).first()
		
	if 	db_parent_labor is not None:	
	
		try:	
			db_task = models.Task(
				task_description=task.task_description,	
				task_mechanicals=task.task_mechanicals,
				task_hour=task.task_hour,  
				task_price=task.task_price,
				task_hour_men=(task.task_hour * task.task_mechanicals),
				labor_task_id=task.labor_task_id,
			)			
			db.add(db_task)   	
			db.commit()
			db.refresh(db_task)			
			return db_task
			
		except IntegrityError as e:
			raise HTTPException(status_code=500, detail="Integrity error")
		except SQLAlchemyError as e: 
			raise HTTPException(status_code=405, detail="Unexpected error when creating task")	
			
	else:
		raise HTTPException(status_code=700, detail="Labor for the task dosent exists in the database")

@app.get("/read_tasks_by_labor_id/{labor_id}", status_code=status.HTTP_201_CREATED) 
async def read_tasks_by_labor_id(current_user: Annotated[schemas.User, Depends(get_current_active_user)],
		labor_id: str, db: Session = Depends(get_db)):    	
	
	db_tasks = db.query(models.Task).filter(models.Task.labor_task_id == labor_id).all()  
	
	return db_tasks
	
@app.put("/update_task/{task_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
async def update_task(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					task_id: str, task: schemas.TaskUPD, db: Session = Depends(get_db)):
	
	db_task = db.query(models.Task).filter(models.Task.task_id == task_id).first()
	if db_task is None:
		raise HTTPException(status_code=404, detail="Task not found")
	db_task.task_description = task.task_description
	db_task.task_mechanicals = task.task_mechanicals
	db_task.task_hour = task.task_hour
	db_task.task_price = task.task_price
	db_task.task_hour_men=(task.task_hour * task.task_price)
	db.commit()
	db.refresh(db_task)	
	return db_task
	
@app.delete("/delete_task/{task_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
async def delete_task(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					task_id: str, db: Session = Depends(get_db)):
	
	db_task = db.query(models.Task).filter(models.Task.task_id == task_id).first()	
	if db_task is None:
		raise HTTPException(status_code=404, detail="Task not found in database")		
	db.delete(db_task)	
	db.commit()	
	return {"Deleted": "Labor deleted successfuly"}
	
#########################
# CRUD for EQUIPMENT here  
#########################		

@app.post("/create_equipment/", status_code=status.HTTP_201_CREATED) 
async def create_equipment(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
				equipment: schemas.Equipment, db: Session = Depends(get_db)):		
	
	db_parent_labor = db.query(models.Labor).filter(models.Labor.labor_id == equipment.labor_equipment_id).first()
		
	if 	db_parent_labor is not None:	
	
		try:	
			db_equipment = models.Equipment(
				equipment_name = equipment.equipment_name,	
				equipment_quantity = equipment.equipment_quantity,
				equipment_unit_price = equipment.equipment_unit_price,  
				equipment_amount = (equipment.equipment_unit_price * equipment.equipment_quantity), 
				labor_equipment_id = equipment.labor_equipment_id,
			)			
			db.add(db_equipment)   	
			db.commit()
			db.refresh(db_equipment)			
			return db_equipment
			
		except IntegrityError as e:
			raise HTTPException(status_code=500, detail="Integrity error")
		except SQLAlchemyError as e: 
			raise HTTPException(status_code=405, detail="Unexpected error when creating task")	
			
	else:
		raise HTTPException(status_code=700, detail="Labor for the equipment dosent exists in the database")	
	
@app.get("/read_equipments_by_labor_id/{labor_id}", status_code=status.HTTP_201_CREATED) 
async def read_equipments_by_labor_id(current_user: Annotated[schemas.User, Depends(get_current_active_user)],
		labor_id: str, db: Session = Depends(get_db)):    	
	
	db_equipment = db.query(models.Equipment).filter(models.Equipment.labor_equipment_id == labor_id).all()  
	
	return db_equipment
	
@app.put("/update_equipment/{equipment_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
async def update_equipment(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					equipment_id: str, equipment: schemas.EquipmentUPD, db: Session = Depends(get_db)):
	
	db_equipment = db.query(models.Equipment).filter(models.Equipment.equipment_id == equipment_id).first()
	if db_equipment is None:
		raise HTTPException(status_code=404, detail="Equipment not found")
	db_equipment.equipment_name = equipment.equipment_name
	db_equipment.equipment_quantity = equipment.equipment_quantity
	db_equipment.equipment_unit_price = equipment.equipment_unit_price
	db_equipment.equipment_amount = (equipment.equipment_unit_price * equipment.equipment_quantity)
	db.commit()
	db.refresh(db_equipment)	
	return db_equipment
	
@app.delete("/delete_equipment/{equipment_id}", status_code=status.HTTP_201_CREATED) #response_model=schemas.User
async def delete_equipment(current_user: Annotated[schemas.User, Security(get_current_user, scopes=["manager"])],
					equipment_id: str, db: Session = Depends(get_db)):
	
	db_equipment = db.query(models.Equipment).filter(models.Equipment.equipment_id == equipment_id).first()	
	if db_equipment is None:
		raise HTTPException(status_code=404, detail="Equipment not found in database")		
	db.delete(db_equipment)	
	db.commit()	
	return {"Deleted": "Labor deleted successfuly"}