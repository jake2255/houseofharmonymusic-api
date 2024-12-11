from django.contrib import admin
from .models import Account, Lesson, Course, Verification
# Register your models here.

admin.site.register(Account)
admin.site.register(Course)
admin.site.register(Lesson)
admin.site.register(Verification)