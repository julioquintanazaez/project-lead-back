from database import Base
import datetime
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, Float, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from fastapi_utils.guid_type import GUID, GUID_DEFAULT_SQLITE
from sqlalchemy.types import TypeDecorator, String
import json

from uuid import UUID, uuid4  

class JSONEncodeDict(TypeDecorator):
	impl = String
	
	def process_bind_param(self, value, dialect):
		if value is not None:
			value = json.dumps(value)
		return value

	def process_result_value(self, value, dialect):
		if value is not None:
			value = json.loads(value)
		return value
		
class User(Base):
	__tablename__ = "user"
	
	user_id = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE)
	username = Column(String(30), primary_key=True, unique=True, index=True) 
	full_name = Column(String(50), nullable=True, index=True) 
	email = Column(String(30), nullable=False, index=True) 
	#role = Column(String(15), nullable=False, index=True)#List[] #Scopes
	role = Column(JSONEncodeDict)
	disable = Column(Boolean, nullable=True, default=False)	
	hashed_password = Column(String(100), nullable=True, default=False)	
	#Relations with its child "Labor"
	users = relationship("Project", back_populates="user", cascade="all, delete")

class Project(Base):  
	__tablename__ = "project"
	
	project_id = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE)
	project_name = Column(String(50), nullable=False, unique=True, index=True)
	project_type = Column(String(50), nullable=False, index=True)
	project_date = Column(DateTime, nullable=False, server_default=func.now())
	#Relation with its father "Labor"
	user_project_id = Column(GUID, ForeignKey("user.user_id"))
	user = relationship("User", back_populates="users")
	#Relations with its child "Material"
	materials = relationship("Material", back_populates="project", cascade="all, delete")
	#Relations with its child "Labor"
	labors = relationship("Labor", back_populates="project", cascade="all, delete")
	
class Material(Base):  
	__tablename__ = 'material'
	
	material_id = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE)
	material_name = Column(String(100), nullable=True, default=None, index=True) 
	material_type = Column(String(100), nullable=True, default=None, index=True) 
	material_quantity = Column(Integer, nullable=True, default=1)
	material_price = Column(Float, nullable=True, default=1.0) 
	material_amount = Column(Float, nullable=True, default=1.0)	
	#Relation with its father "Labor"
	project_material_id = Column(GUID, ForeignKey("project.project_id"))
	project = relationship("Project", back_populates="materials")
	
class Labor(Base): 
	__tablename__ = "labor"	
	
	labor_id = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE)
	labor_type = Column(String(100), nullable=False, index=True)
	#Relation with its father "Project"
	project_labor_id = Column(GUID, ForeignKey("project.project_id"))
	project = relationship("Project", back_populates="labors")
	#Relations with its childs "Task, Equipment & Material"
	tasks = relationship("Task", back_populates="labor_tasks", cascade="all, delete")
	equipments = relationship("Equipment", back_populates="labor_equipments", cascade="all, delete")
	
class Task(Base):
	__tablename__ = "task"

	task_id = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE)
	task_description = Column(String(100), nullable=True, default=None, index=True) 
	task_mechanicals = Column(Integer, nullable=True, default=1)
	task_hour = Column(Integer, nullable=True, default=1)
	task_hour_men = Column(Integer, nullable=True, default=1)
	task_price = Column(Float, nullable=True, default=1.0)
	#Relation with its father "Labor"
	labor_task_id = Column(GUID, ForeignKey("labor.labor_id"))	
	labor_tasks = relationship("Labor", back_populates="tasks")
	
class Equipment(Base):
	__tablename__ = "equipment"

	equipment_id = Column(GUID, primary_key=True, default=GUID_DEFAULT_SQLITE)
	equipment_name = Column(String(100), nullable=True, default=None, index=True) 
	equipment_quantity = Column(Integer, nullable=True, default=1)
	equipment_unit_price = Column(Float, nullable=True, default=1.0)
	equipment_amount = Column(Float, nullable=True, default=1.0)
	#Relation with its father "Labor"
	labor_equipment_id = Column(GUID, ForeignKey("labor.labor_id"))	
	labor_equipments = relationship("Labor", back_populates="equipments")

