from django.db import models
from markdownx.models import MarkdownxField
from markdownx.utils import markdownify
from django.contrib.auth.models import User
# Create your models here.

class userinfo(models.Model):
	 user = models.ForeignKey(User, on_delete=models.CASCADE)
	 company= models.TextField(max_length=500, blank=True)
	 is_previously_loggedin=models.BooleanField(default=False)

class activate(models.Model):
	email = models.EmailField()
	timestamp = models.DateTimeField(auto_now_add=True,auto_now=False) 
	ip_addr = models.CharField(max_length=200,blank=True)
	hashed=models.CharField(max_length=100,blank=False)
	expired=models.BooleanField()
	def __unicode__(self):
		return self.email
	 
class domains(models.Model):
	 member = models.ForeignKey(User, on_delete=models.CASCADE)
	 domain=models.TextField(max_length=500,blank=True)

class Keywords(models.Model):
	user=models.ForeignKey(User, on_delete=models.CASCADE)
	keyword=models.TextField(max_length=1000,blank=True)

class combination(models.Model):
	original_domain = models.ForeignKey(domains,on_delete=models.CASCADE)
	domain_name=models.TextField(max_length=500,blank=True)
	fuzzer=models.TextField(max_length=500,blank=True)

# class notifications(models.Model):
# 	user=models.ForeignKey(User, on_delete=models.CASCADE)
# 	domain_name=models.TextField(max_length=1000,blank=True)
# 	message=models.TextField(max_length=1000,blank=True)
# 	created_date=models.TextField(max_length=1000,blank=True)
# 	detected_type=models.TextField(max_length=100,default='domain')
# 	action_taken=models.BooleanField(default=False)
# 	timestamp = models.DateTimeField(auto_now_add=True,auto_now=False)

class critical_alerts(models.Model):
	user=models.ForeignKey(User, on_delete=models.CASCADE)
	count=models.TextField(max_length=1000,blank=True)

class info_alerts(models.Model):
	user=models.ForeignKey(User, on_delete=models.CASCADE)
	count=models.TextField(max_length=1000,blank=True)

class Detection(models.Model):
	user=models.ForeignKey(User,on_delete=models.CASCADE)
	domain_detected=models.TextField(max_length=1000,blank=True)
	registrant_email=models.TextField(max_length=1000,blank=True)
	registrant_name=models.TextField(max_length=1000,blank=True)
	registrant_organization=models.TextField(max_length=1000,blank=True)
	registrant_telephone=models.TextField(max_length=1000,blank=True)
	whoisServer=models.TextField(max_length=1000,blank=True)
	createdDate=models.TextField(max_length=1000,blank=True)
	registrant_country=models.TextField(max_length=500,blank=True)
	registrant_state=models.TextField(max_length=500,blank=True)
	detection_type=models.TextField(max_length=10,default="domain")
	action_taken=models.BooleanField(default=False)
	ticket_id=models.TextField(default=None,blank=True)
	timestamp = models.DateTimeField(auto_now_add=True,auto_now=False)
	original_domain=models.TextField(max_length=1000,blank=True)
	
class category(models.Model):
	category_name=models.TextField(max_length=1000,blank=True)

class emailTemplate(models.Model):
	content=models.TextField(max_length=5000,blank=True)
	category=models.ForeignKey(category,on_delete=models.CASCADE)
	filenames=models.CharField(max_length=1000,blank=True)
	subject=models.TextField(max_length=1000,blank=True)


class ticketsetting(models.Model):
	user=models.ForeignKey(User,on_delete=models.CASCADE)
	category=models.TextField(max_length=1000)
	title=models.TextField(max_length=1000)
	description=MarkdownxField()
	status=models.TextField(max_length=1000,blank=True,default="null")
	summary=models.TextField(max_length=5000)
	priority=models.TextField(max_length=1000)
	incident_id=models.TextField(max_length=1000,blank=True)
	incident_details=models.TextField(max_length=1000,blank=True)
	recom_action=models.TextField(max_length=5000,blank=True)
	impact=models.TextField(max_length=5000,blank=True)
	url=models.TextField(max_length=1000,blank=True)
	domain=models.TextField(max_length=1000,blank=True)
	pimage=models.CharField(max_length=600,blank=True)
	request_takedown=models.BooleanField(default=False)
	takedown_initiated=models.BooleanField(default=False)
	email_sent=models.BooleanField(default=False)
	is_delivered=models.BooleanField(default=False)
	is_read=models.BooleanField(default=False)
	timestamp = models.DateTimeField(auto_now_add=True,auto_now=False)

	@property
	def formatted_markdown(self):
		return markdownify(self.description)


class notification(models.Model):
	ticketid=models.ForeignKey(ticketsetting,on_delete=models.CASCADE)
	userid=models.TextField(max_length=5000,blank=True)
	msg=models.TextField(max_length=5000,blank=True)


class whoisinfo(models.Model):
	ticketid=models.ForeignKey(ticketsetting,on_delete=models.CASCADE)
	domain_detected=models.TextField(max_length=1000,blank=True)
	registrant_email=models.TextField(max_length=1000,blank=True)
	registrant_name=models.TextField(max_length=1000,blank=True)
	registrant_organization=models.TextField(max_length=1000,blank=True)
	registrant_telephone=models.TextField(max_length=1000,blank=True)
	whoisServer=models.TextField(max_length=1000,blank=True)
	createdDate=models.TextField(max_length=1000,blank=True)
	registrant_country=models.TextField(max_length=500,blank=True)
	registrant_state=models.TextField(max_length=500,blank=True)
	detection_type=models.TextField(max_length=10,default="domain")
	action_taken=models.BooleanField(default=False)
	ticket_id=models.TextField(default=None,blank=True)
	timestamp = models.DateTimeField(auto_now_add=True,auto_now=False)
	original_domain=models.TextField(max_length=1000,blank=True)


class Commments(models.Model):
	username = models.CharField(max_length=20, unique=False)
	ticketid = models.IntegerField(blank=False)
	filenames = models.CharField(max_length=600,blank=True)
	is_internal = models.BooleanField(default=False)
	timestamp = models.DateTimeField(auto_now_add=True,auto_now=False)
	#comments = models.TextField(max_length=600,blank=False)
	comments = models.TextField(max_length=1000,blank=True)


class temp_data(models.Model):
	domainName=models.TextField(max_length=1000,blank=True)
	registrarName= models.TextField(max_length=1000,blank=True)
	contactEmail=models.TextField(max_length=1000,blank=True)
	whoisServer=models.TextField(max_length=500,blank=True)
	nameServers=models.TextField(max_length=500,blank=True)
	createdDate=models.TextField(max_length=500,blank=True)
	updatedDate=models.TextField(max_length=500,blank=True)
	expiresDate=models.TextField(max_length=500,blank=True)
	standardRegCreatedDate=models.TextField(max_length=1000,blank=True)
	standardRegUpdatedDate=models.TextField(max_length=1000,blank=True)
	standardRegExpiresDate=models.TextField(max_length=1000,blank=True)
	status=models.TextField(max_length=1000,blank=True)
	Audit_auditUpdatedDate=models.TextField(max_length=1000,blank=True)
	registrant_email=models.TextField(max_length=1000,blank=True)
	registrant_name=models.TextField(max_length=1000,blank=True)
	registrant_organization=models.TextField(max_length=1000,blank=True)
	registrant_country=models.TextField(max_length=500,blank=True)
	registrant_telephone=models.TextField(max_length=1000,blank=True)
	registrant_street1=models.TextField(max_length=1000,blank=True)
	registrant_street2=models.TextField(max_length=1000,blank=True)
	registrant_street3=models.TextField(max_length=1000,blank=True)
	registrant_street4=models.TextField(max_length=1000,blank=True)
	registrant_city=models.TextField(max_length=1000,blank=True)
	registrant_state=models.TextField(max_length=1000,blank=True)
	registrant_postalCode=models.TextField(max_length=1000,blank=True)
	registrant_country=models.TextField(max_length=1000,blank=True)
	registrant_fax=models.TextField(max_length=1000,blank=True)
	registrant_faxExt=models.TextField(max_length=1000,blank=True)
	registrant_telephone=models.TextField(max_length=1000,blank=True)
	registrant_telephoneExt=models.TextField(max_length=1000,blank=True)
	administrativeContact_email=models.TextField(max_length=1000,blank=True)
	administrativeContact_name=models.TextField(max_length=1000,blank=True)
	administrativeContact_organization=models.TextField(max_length=1000,blank=True)
	administrativeContact_street1=models.TextField(max_length=1000,blank=True)
	administrativeContact_street2=models.TextField(max_length=1000,blank=True)
	administrativeContact_street3=models.TextField(max_length=1000,blank=True)
	administrativeContact_street4=models.TextField(max_length=1000,blank=True)
	administrativeContact_city=models.TextField(max_length=1000,blank=True)
	administrativeContact_state=models.TextField(max_length=1000,blank=True)
	administrativeContact_postalCode=models.TextField(max_length=1000,blank=True)
	administrativeContact_country=models.TextField(max_length=1000,blank=True)
	administrativeContact_fax=models.TextField(max_length=1000,blank=True)
	administrativeContact_faxExt=models.TextField(max_length=1000,blank=True)
	administrativeContact_telephone=models.TextField(max_length=1000,blank=True)
	administrativeContact_telephoneExt=models.TextField(max_length=1000,blank=True)

class excel_data(models.Model):
	domainName=models.TextField(max_length=1000,blank=True)
	registrarName= models.TextField(max_length=1000,blank=True)
	contactEmail=models.TextField(max_length=1000,blank=True)
	whoisServer=models.TextField(max_length=500,blank=True)
	nameServers=models.TextField(max_length=500,blank=True)
	createdDate=models.TextField(max_length=500,blank=True)
	updatedDate=models.TextField(max_length=500,blank=True)
	expiresDate=models.TextField(max_length=500,blank=True)
	standardRegCreatedDate=models.TextField(max_length=1000,blank=True)
	standardRegUpdatedDate=models.TextField(max_length=1000,blank=True)
	standardRegExpiresDate=models.TextField(max_length=1000,blank=True)
	status=models.TextField(max_length=1000,blank=True)
	Audit_auditUpdatedDate=models.TextField(max_length=1000,blank=True)
	registrant_email=models.TextField(max_length=1000,blank=True)
	registrant_name=models.TextField(max_length=1000,blank=True)
	registrant_organization=models.TextField(max_length=1000,blank=True)
	registrant_country=models.TextField(max_length=500,blank=True)
	registrant_telephone=models.TextField(max_length=1000,blank=True)
	registrant_street1=models.TextField(max_length=1000,blank=True)
	registrant_street2=models.TextField(max_length=1000,blank=True)
	registrant_street3=models.TextField(max_length=1000,blank=True)
	registrant_street4=models.TextField(max_length=1000,blank=True)
	registrant_city=models.TextField(max_length=1000,blank=True)
	registrant_state=models.TextField(max_length=1000,blank=True)
	registrant_postalCode=models.TextField(max_length=1000,blank=True)
	registrant_country=models.TextField(max_length=1000,blank=True)
	registrant_fax=models.TextField(max_length=1000,blank=True)
	registrant_faxExt=models.TextField(max_length=1000,blank=True)
	registrant_telephone=models.TextField(max_length=1000,blank=True)
	registrant_telephoneExt=models.TextField(max_length=1000,blank=True)
	administrativeContact_email=models.TextField(max_length=1000,blank=True)
	administrativeContact_name=models.TextField(max_length=1000,blank=True)
	administrativeContact_organization=models.TextField(max_length=1000,blank=True)
	administrativeContact_street1=models.TextField(max_length=1000,blank=True)
	administrativeContact_street2=models.TextField(max_length=1000,blank=True)
	administrativeContact_street3=models.TextField(max_length=1000,blank=True)
	administrativeContact_street4=models.TextField(max_length=1000,blank=True)
	administrativeContact_city=models.TextField(max_length=1000,blank=True)
	administrativeContact_state=models.TextField(max_length=1000,blank=True)
	administrativeContact_postalCode=models.TextField(max_length=1000,blank=True)
	administrativeContact_country=models.TextField(max_length=1000,blank=True)
	administrativeContact_fax=models.TextField(max_length=1000,blank=True)
	administrativeContact_faxExt=models.TextField(max_length=1000,blank=True)
	administrativeContact_telephone=models.TextField(max_length=1000,blank=True)
	administrativeContact_telephoneExt=models.TextField(max_length=1000,blank=True)
	
	
class admin_domain(models.Model):
	user=models.ForeignKey(User,on_delete=models.CASCADE)
	domain=models.TextField(max_length=1000)

class admin_combination(models.Model):
	original_domain = models.ForeignKey(admin_domain,on_delete=models.CASCADE)
	domain_name=models.TextField(max_length=500,blank=True)
	fuzzer=models.TextField(max_length=500,blank=True)

class organisation_admin(models.Model):
	user = models.ForeignKey(User, on_delete=models.CASCADE)
	company= models.TextField(max_length=500, blank=True)
	admin=models.BooleanField(default="False")

class activate_invite(models.Model):
	email = models.EmailField()
	company=models.TextField(max_length=1000,blank=True)
	timestamp = models.DateTimeField(auto_now_add=True,auto_now=False) 
	ip_addr = models.CharField(max_length=200,blank=True)
	hashed=models.CharField(max_length=100,blank=False)
	expired=models.BooleanField()
	def __unicode__(self):
		return self.email
