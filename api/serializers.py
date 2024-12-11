"""
    Serializers converts python models into JSON format and vise-versa
    views.py functions will call these functions to format the data
"""

from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from .models import *

class CreateUserSerializer(serializers.ModelSerializer): 
    """Serializer for new user registering"""
    phone = serializers.CharField(write_only=True) # deserialize the phone field

    class Meta:
        """Deserialize the user model fields below"""
        model = User
        fields = ['email', 'username', 'password', 'first_name', 'last_name', 'phone']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        """Creates the user and account"""
        phone = validated_data.pop('phone')
        
        # user object created and data set
        user = User(
            email = validated_data['email'],
            username = validated_data['username'],
            first_name = validated_data['first_name'],
            last_name = validated_data['last_name']
        )

        # set_password() and save() are built-in functions
        user.set_password(validated_data['password']) # hashes the password- security measure
        user.save() # saves user object to database
    
        # account object created and data set
        account = Account(
            user = user,
            phone = phone,
        )

        account.save() # saves account object to database
        return user # returns user object to views.py function call

class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""
    class Meta:
        """Serialize the user model fields below"""
        model = User
        fields = ['email', 'username', 'first_name', 'last_name']

class LoginAccountSerializer(serializers.Serializer):
    """Serializer to handle login"""
    username = serializers.CharField(required=True) # deserialize username field
    password = serializers.CharField(required=True, write_only=True) # deserialize password field

    def validate(self, attrs):
        """Authenticate the user credentials"""
        username = attrs.get('username')
        password = attrs.get('password')

        # built-in function to search for matching credentials in database, returns User object
        user = authenticate(username=username, password=password) 

        # credentials match not found, user is null
        if user is None:
            raise serializers.ValidationError("Invalid credentials.")
        
        # find the user's account
        try:
            account = Account.objects.get(user=user)
        except Account.DoesNotExist:
            raise serializers.ValidationError("Account not found.")

        # return both user and account to views.py function call
        return {
            'user': user,
            'account': account
        }

class AccountSerializer(serializers.ModelSerializer):
    """Serializer for Account model"""
    class Meta:
        """Serialize the account model fields below"""
        model = Account
        fields = ['id', 'user', 'phone', 'isVerified', 'courses']
        extra_kwargs = {"user": {"read_only": True}}

class CourseSerializer(serializers.ModelSerializer):
    """Serializer for Course model"""
    class Meta:
        """Serialize the course model fields below"""
        model = Course
        fields = ['id', 'title', 'overview', 'description', 'lessons', 'price', 'cover_image']

class LessonPreviewSerializer(serializers.ModelSerializer):
    """Serializer for Lesson model"""
    class Meta:
        """Serialize the lesson model preview fields below"""
        model = Lesson
        fields = ['id', 'title', 'overview']

class LessonSerializer(serializers.ModelSerializer):
    """Serializer for Lesson model"""
    class Meta:
        """Serialize the lesson model fields below"""
        model = Lesson
        fields = ['id', 'title', 'overview', 'description', 'video', 'image']

class VerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Verification
        fields = ['code', 'email']
