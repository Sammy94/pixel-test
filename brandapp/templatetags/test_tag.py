from django import template
from brandapp.models import *

from django.contrib.auth.models import User
register = template.Library()


@register.filter
def check_temp(val):
	try:
		temp=emailTemplate.objects.get(category=val)
		print("False")
		return False
	except Exception as e:
		print("True")
		return True