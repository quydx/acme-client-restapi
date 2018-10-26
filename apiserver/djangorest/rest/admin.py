from django.contrib import admin

# Register your models here.
from .models import Customer, Certificate

# Register your models here.

admin.site.register(Customer)
admin.site.register(Certificate)