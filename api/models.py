"""
    Models are stored in the database
    When an object of a model is created, a table is created in the database

    Django also includes a predefined model for User from import below
    Stores username, password, firstname, lastname, email

    Each model automatically creates an "id" field
"""

from django.db import models
from django.contrib.auth.models import User

# Uses meta data to modify default User model to make emails unique
User._meta.get_field('email')._unique = True 

class Lesson(models.Model):
    """Model representing an individual lesson"""
    title = models.CharField(max_length=50)
    overview = models.TextField()
    description = models.TextField()
    video = models.FileField(upload_to='api/upload_videos/', blank=True, null=True)
    image = models.ImageField(upload_to='api/upload_images/', blank=True, null=True)

    def __str__(self):
        """defines string representation of Lesson object"""
        return self.title

class Course(models.Model):
    """Model representing a course"""
    title = models.CharField(max_length=50)
    overview = models.TextField()
    description = models.TextField()
    lessons = models.ManyToManyField(Lesson, blank=True) # each course can hold multiple lessons 
    price = models.DecimalField(max_digits=6, decimal_places=2)
    cover_image = models.ImageField(upload_to='api/upload_images', blank=True, null=True)

    def __str__(self):
        """defines string representation of Course object"""
        return self.title

class Account(models.Model):
    """Model representing an account"""
    user = models.OneToOneField(User, on_delete=models.CASCADE) # each account is linked to a user
    phone = models.TextField(blank=True, null=True)
    isVerified = models.BooleanField(default=False)
    courses = models.ManyToManyField(Course, blank=True, related_name='accounts') # each account can hold multiple courses

    def __str__(self):
        """defines string representation of Account object"""
        return self.user.username
    
class Verification(models.Model):
    '''Model for the verification function'''
    email = models.TextField(blank=False, null=False)
    code = models.CharField(max_length=6, blank=False, null=False)

    def __str__(self):
        return self.email