from django.db import models
from enum import Enum
import uuid
import bcrypt





# Create your models here.
class User(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False)
    firstName = models.CharField(max_length=50,blank=True)
    lastName = models.CharField(max_length=50,blank=True)
    email = models.EmailField(max_length=50,unique=True)
    password = models.CharField(max_length=128,null=True)
    image_url = models.URLField(max_length=100,null=True,blank=True)
    isActive = models.BooleanField(default=True)
    isEmailVerified = models.BooleanField(default=False)
    is_authenticated_with_email = models.BooleanField(default=False)
    is_authenticated_with_google = models.BooleanField(default=False)
    
    def __str__(self):
        return f'{self.firstName} {self.lastName}'
    
    def set_password(self,raw_password):
        self.password = bcrypt.hashpw(raw_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
    def check_password(self,raw_password):
        return bcrypt.checkpw(raw_password.encode('utf-8'), self.password.encode('utf-8'))