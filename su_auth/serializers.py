from rest_framework import serializers
from .models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'
        
    
    
    def create(self,validate_data):
        password = validate_data.pop('password',None)
        user = User(**validate_data)
        if password:
            user.set_password(password)
        user.save()
        return user
    
    def update(self,instance,validated_data):
        password = validated_data.pop('password',None)
        for attr, value in validated_data.items():
            setattr(instance,attr,value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance