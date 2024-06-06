from typing import Union, Optional, List
from datetime import date
from pydantic import BaseModel, EmailStr 

class UserUPD(BaseModel):	
	username: str
	email: Union[EmailStr, None] = None
	full_name: Union[str, None] = None
	role: List[str] = []
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
		
class UserActivate(BaseModel):	
	disable: Union[bool, None] = None
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
	
class User(BaseModel):	
	username: str
	email: EmailStr
	full_name: Union[str, None] = None
	role: List[str] = []	
	disable: Union[bool, None] = None
	hashed_password: str
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	

class UserInDB(User):
	user_id: str	
	
class UserPassword(BaseModel):
    hashed_password: str
	
class UserResetPassword(BaseModel):
	actualpassword: str
	newpassword: str
	
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
	username: Union[str, None] = None
	scopes: List[str] = []	
#-------------------------
#-------PROJECT-------------
#-------------------------
class ProjectUPD(BaseModel):
	project_name : str
	project_type: str
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True
		
class Project(BaseModel):
	project_name : str
	project_type : str
	user_project_id: str
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True
		
class ProjectInDB(Project):
	project_id : str 
	project_date: date

#-------------------------
#-------MATERIAL-------------
#-------------------------
class MaterialUPD(BaseModel):
	material_name: str
	material_quantity : int
	material_price : float
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True
		
class Material(BaseModel):
	material_name: str
	material_type: str
	material_quantity : int
	material_price : float	
	project_material_id : str 
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	

class MaterialInDB(Material):
	material_id: str	
	material_amount : float
	
#-------------------------
#-------LABOR-------------
#-------------------------	
class LaborUPD(BaseModel):
	labor_type : str
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True
		
class Labor(BaseModel):
	labor_type : str	
	project_labor_id : str
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True
		
class LaborInDB(Labor):
	labor_id: str

#-------------------------
#-------TASK-------------
#-------------------------
class TaskUPD(BaseModel):
	task_description : str
	task_mechanicals : int
	task_hour : int
	task_price : float
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	

class Task(BaseModel):
	task_description : str
	task_mechanicals : int
	task_hour : int
	task_price : float
	labor_task_id : str 
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True		
		
class TaskInDB(Task):
	task_id: str
	task_hour_men : int
	

#-------------------------
#-------EQUIPMENT-------------
#-------------------------

class EquipmentUPD(BaseModel):
	equipment_name: str
	equipment_quantity : int
	equipment_unit_price : float
	
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
		
class Equipment(BaseModel):
	equipment_name: str
	equipment_quantity : int
	equipment_unit_price : float
	labor_equipment_id : str 
			
	class Config:
		orm_mode = True
		allow_population_by_field_name = True
		arbitrary_types_allowed = True	
		
class EquipmentInDB(Equipment):
	equipment_id: str
	equipment_amount : float	
	

#----------------------------------	
	
	
