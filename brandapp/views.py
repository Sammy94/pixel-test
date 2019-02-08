from __future__ import unicode_literals

from django.shortcuts import render

# Create your views here.
# -*- coding: utf-8 -*-
#from __future__ import unicode_literals
from django.shortcuts import render
from django.shortcuts import render
from brandapp.models import *
from ticketapp.settings import *
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect, HttpResponse
from django.contrib.auth import authenticate, login
from django.conf import settings
from django.contrib import messages
from django.core.mail import send_mail
import dnstwist
import threading
#import thread
import hashlib
import random
from django.contrib.auth import logout
from django.shortcuts import render_to_response
from django.core.paginator import Paginator,EmptyPage, PageNotAnInteger
#from helpdesk.models import *
import _thread
import time
import whois
from django.utils.crypto import get_random_string
from django.template.loader import render_to_string
from django.urls import reverse

# Create your views here.

from django.http import HttpResponse
from PIL import Image

def image_load(request):
    print("\nImage Loaded\n")
    red = Image.new('RGB', (1, 1))
    response = HttpResponse(content_type="image/png")
    red.save(response, "PNG")
    print(response)
    return response


def check(request):
	fuzz = dnstwist.DomainFuzz('google.com')
	try:
		fuzz.generate()
	except Exception as e:
		print(e)
	dom=fuzz.domains

	return HttpResponse(dom)

def register(request):
	fname=request.POST.get('fname','')
	lname=request.POST.get('lname','')
	uname=request.POST.get('uname','')
	email=request.POST.get('email','')
	pass1=request.POST.get('pass1','')
	pass2=request.POST.get('pass2','')
	domain=request.POST.get('domain','')
	keywords=request.POST.get('keyword','')

	print(len(pass1))
	data_val=""
	if (request.method == "POST"):	
		if (pass1==pass2):
			if len(pass1)>6:
				print("why is this ")
				if len(uname)>4:
					try:
						u = User.objects.get(username=uname)
						data_val="<font color='red'>Username taken</font>"
					except Exception as e:
						try:
							e = User.objects.get(email=email)
							data_val="<font color='red'>Email taken</font>"
						except Exception as e:

							user = User.objects.create_user(username=uname,email=email,password=pass1,first_name=fname,last_name=lname)
							user.is_active=False
							user.save()
							em= User.objects.get(email=email)
							emf=str(random.random())+str(em)
							ran=hashlib.sha256(emf.encode('utf-8')).hexdigest()

							#hashlib.sha256(str(random.getrandbits(256)).encode('utf-8')).hexdigest()
							ip=get_client_ip(request)
							a=activate(email=email,hashed=ran,ip_addr=ip,expired=False)
							a.save()
							usr= userinfo(user=user,company=domain)
							usr.save()

							new_keyword=[x.strip() for x in keywords.split(',')]

							for i in new_keyword:
								keywords= Keywords(user=user,keyword=i)
								keywords.save()

							dom= domains(member=user,domain=domain)
							dom.save()
							em= User.objects.get(email=email)
							mailed_verify(email,ran,request)
							_thread.start_new_thread( calculate_combinations, (uname,dom) )
							#calculate_combinations(uname,dom)

							

							return render(request,'login.html')
				else:
					data_val="<font color='red'>Username should be more than 4 characters</font>"

			else:
				data_val="<font color='red'>Passwords should be more than 6 characters</font>"
		else:
			data_val="<font color='red'>Passwords do not match</font>"
	context={

	"msg":data_val
	}

	return render(request,'register.html',context)


def signin(request):
	if (request.method=="POST"):
		uname=request.POST.get('uname','')
		passwd=request.POST.get('pass1','')
		print(uname)
		print(passwd)
		#user = auth.authenticate(username=uname,password=passwd)
		user = authenticate(request, username=uname, password=passwd)

		if user is not None:
			print("user logged in")
			login(request,user)
			return HttpResponseRedirect('/dashboard')	
		else:
			print("auth failed")
			return render(request,'login.html')	  
	return render(request,'login.html')



# def signin(request):
# 	if (request.method=="POST"):
# 		uname=request.POST.get('uname','')
# 		passwd=request.POST.get('pass1','')
# 		user = authenticate(username=uname, password=passwd)
# 		if user is not None:
# 			print("user exists")
# 			login(request,user)
# 			domain=domains.objects.filter(member=request.user)
# 			for i in domain:
# 				print(i.domain)
# 				#get_matching_domains(request,i.id)
# 			#domain_obj=DetectionTable.objects.filter(user=request.user)
# 			#import thread
# 			#thread.start_new_thread(checkMyDomain, (request,))
# 			user_status=userinfo.objects.get(user=request.user)
# 			if(user_status.is_previously_loggedin==False):
# 				return HttpResponseRedirect('/settings')

# 			return HttpResponseRedirect('/dashboard')			
# 		else:
			
# 			return render(request,'login.html')	   
# 	else:
# 		return render(request,'login.html')

# def add_assets(request):
# 	title=request.POST.get('title','')
# 	slug=request.POST.get('slug','')
# 	email=request.POST.get('email','')
# 	locale=request.POST.get('locale','')
# 	public_sub=request.POST.get('public_sub','')
# 	email_sub=request.POST.get('email_sub','')
# 	user_info=userinfo.objects.get(user=request.user)
# 	edays=request.POST.get('edays','')
# 	new_ticket_cc=request.POST.get('new_ticket_cc','')
# 	update_ticket_cc=request.POST.get('update_ticket_cc','')
# 	email_type=request.POST.get('email_type','')
# 	hostname=request.POST.get('hostname','')
# 	port=request.POST.get('port','')
# 	ssl=request.POST.get('ssl','')
# 	email_uname=request.POST.get('email_uname','')
# 	email_pass=request.POST.get('email_pass','')
# 	imap_folder=request.POST.get('imap_folder','')
# 	socks_proxy=request.POST.get('socks_proxy','')
# 	logging_type=request.POST.get('logging_type','')
# 	default_owner=request.POST.get('default_owner','')

# 	if (request.method=='POST'):
# 		print(title, slug,email,locale,public_sub,email_sub,edays,new_ticket_cc,update_ticket_cc,email_type,hostname,
# 		port,ssl,email_uname,email_pass,imap_folder,socks_proxy,logging_type,default_owner, user_info.company)

# 		q=Queue.objects.get_or_create(title=title,slug=slug,locale=locale,allow_public_submission=True,email_address=email,
# 			escalate_days=edays,new_ticket_cc=new_ticket_cc,updated_ticket_cc=update_ticket_cc,email_box_type=email_type,
# 			email_box_host=hostname,email_box_port=port,email_box_user=email_uname,email_box_pass=email_pass,company=user_info.company)

# 	return render(request,'assets.html')


def dashboard(request):
	user=User.objects.get(id=request.user.id)
	result=Detection.objects.filter(user=user)
	flag=True

	if result.exists():
		flag=True
	else:
		flag=False

	context={
	"flag":flag,
	"user":user,
	"domain_obj":result,

	}

	return render(request,'dashboard.html',context)

def addTicket(request):
	if (request.user.is_authenticated==False) or (request.user.is_active==False):
		return HttpResponseRedirect('/login')
	category1=request.POST.get('category1','')
	priority=request.POST.get('priority','')
	#comapnies = comapnies.objects.all()
	url=request.POST.get('url','')
	title=request.POST.get('title','')
	summary=request.POST.get('sum','')
	domain=request.POST.get('domain','')
	description=request.POST.get('des','')
	incident_detail=request.POST.get('incident_detail','')
	impact=request.POST.get('impact','')
	recom_action=request.GET.get('recom_action','')
	unique_id=generateUID()
	# fourofour=False
	# company=""
	msg=""
	# try:
	# 	data=comapnies.objects.get(username=init)
	# 	company=data.username
	# except Exception as e:
	# 	fourofour=True
	b="%s" %(request.user)
	paths=''
	uploaderror=0
	category_list=category.objects.all()

	if(request.method == "POST"):
		print("post")
		try:
			for count, x in enumerate(request.FILES.getlist("files")):
				if(count==5):
					break
				else:
					hh=upload_file(x,b)
					if (hh!='not'):
						paths=paths+","+hh
						print("uploaded")
						print(paths)
		except Exception as e:
			uploaderror=1
			print("upload error")
		a=User.objects.get(username=request.user.username)

	if(category!='' and title!='' and description!='' and uploaderror!=1 ):
		try:
			#aib=company_users.objects.filter(company=init)
			query1=ticketsetting(user=a,category=category1,status="Open",url=url,incident_id=unique_id,description=description,title=title,domain=domain,priority=priority,pimage=str(paths),incident_details=incident_detail,recom_action=recom_action,impact=impact)
			query1.save()

			print(query1)
			w=whois.whois(domain)
			if w['status']!=None:
				import simplejson as json
				#w['creation_date'][0]
				query2=whoisinfo(domain_detected=domain,ticketid=query1,registrant_email=json.dumps(w['emails']),registrant_name=w['registrar'],whoisServer=w['whois_server'])
				query2.save()
				print(query2.registrant_email)
			else:
				print("no status")

			# msgbody=a+" Has Reported "+ bugtype +" bug on "+ url
			# budid=Submissions.objects.filter(username=a).order_by('-timestamp')[:1]
			# for i in budid:
			# 	bugid=i.id
			# ext='/bugbox.php?id='+str(bugid)
			# for i in aib:
			# 	ss=Notification_hacker(username=i.username,message=msgbody,external_link=ext)
			# 	ss.save()
			# 	ssd=messages(username=i.username,messageid=bugid)
			# 	ssd.save()
			msg="<font color='green'>Submission was Successful</font>"
		except Exception as e:
			print(e)
			msg="<font color='red'>error</font>"

	else:
		if(request.method == "POST"):
			msg="<font color='red'>Error, Bugtype, Title, POC are required aslo only jpg, png and zip files are allowed</font>"
		else:
			pass
	context={
	"msg":msg,
	"category_list":category_list
	
	#"comapnies":comapnies,
	
	}
	return render(request,'add-ticket.html',context)

def upload_file(f,a):
	print("upload")
	try:

		filename, ext = os.path.splitext(f.name)
		siz=f.size
		mime=f.content_type
		comm=Commments.objects.filter(bugid=id,is_internal=False).order_by('id')
		l=len(comm)
	except Exception as e:
		print(e)

	print(mime)
	print(ext)
	print(siz)
	if (mime == 'image/png' or mime == 'image/jpeg' or mime ==  'application/zip'):
		
		print(mime)
		mime = True
	else:
		mime = False
	print("mime is "+str(mime))
	if (ext == '.png' or ext == '.zip' or ext == '.jpg' or ext == '.jpeg'):
		exti=True
	else:
		exti=False
	print("ext is "+str(ext))
	if (siz<=20971520 and exti== True and mime == True):
		
		try:

			emf=str(random.random())+str(a)
			ran=hashlib.sha256(emf.encode('utf-8')).hexdigest()
			kk=ran+a+ext
		except Exception as e:
			print(e)
		
		path=os.path.dirname(BASE_DIR)+"/brand-reputation/uploaded/"+kk
		
		print("path is" + str(path))
		try:


			destination=open(path, 'wb+')
			for chunk in f.chunks():
				#print(len(chunk))
				destination.write(chunk)
			destination.close()
			print("tryyy")
		except Exception as e:
			print(e)
		print(kk)
		return kk
	else:
		return "not"

def generateUID():
    uid = get_random_string(length=16, allowed_chars=u'0123456789')
    #date = datetime.datetime.now()

    #result = '%s-%s-%s_%s' % (date.year, date.month, date.day, uid)
    print(uid)

    try:
        obj = ticketsetting.objects.get(incident_id=uid)
    except Exception as e:
        return uid
    else:
        return generateUID()

# def dashboard(request):	
# 	# domain=domains.objects.filter(member=request.user)
# 	# for i in domain:
# 	# 	print(i.domain)
# 	# 	get_matching_domains(request,i.id)
# 	result=DetectionTable.objects.filter(user=request.user)
# 	import datetime
# 	if request.method == 'POST':
# 		m=datetime.datetime.now()

# 		time=request.POST.get('timeline')


# 		if time=='lastseven':
# 			abs=datetime.datetime.now() - datetime.timedelta(days=7)
# 			print(abs)
# 			print(datetime.datetime.now())
# 			result=DetectionTable.objects.filter(user=request.user,timestamp__range=[abs,datetime.datetime.now()])
# 			print(result)
# 		if time=='lastmonth':
# 			m=datetime.datetime.now()
# 			month =str((m.month))
# 			result = DetectionTable.objects.filter(user=request.user,timestamp__month =month)
# 		if time=='alltime':
# 			result=DetectionTable.objects.filter(user=request.user)

# 	user=User.objects.get(id=request.user.id)
				
# 	#month =str((m.month))
# 	#notify=notifications.objects.filter(user=request.user)
# 	#count=len(notify)
# 	context={
# 	"user":user,
# 	"domain_obj":result,
# 	# "count":count
# 		}
# 	return render(request,'dashboard.html',context)


# # Search the combinations of a domain with the excel_data , if anything matches store it in Detection table
# def get_matching_domains(request,domain):
# 	from django.db import connection
# 	cursor = connection.cursor()
# 	cursor.execute("Select * from bprotect_combination inner join bprotect_excel_data on bprotect_combination.domain_name=bprotect_excel_data.domainName where bprotect_combination.original_domain_id=%s",[domain])	
# 	row=cursor.fetchall()
# 	print("domain_org"+str(domain))
# 	#print(cursor.rowcount)
# 	counting=cursor.rowcount
# 	print("start row")
# 	#print(row)
# 	domain_obj=[]
# 	original_domain=domains.objects.get(id=domain)
# 	#user_obj=User.objects.get(username=user)
# 	for number in range(counting):
# 		domain_detected_obj=DetectionTable.objects.get_or_create(user=request.user,domain_detected=row[number][1] ,registrant_email=row[number][6], 
# 		whoisServer=row[number][7],createdDate=row[number][9],registrant_state=row[number][24],registrant_country=row[number][27],detection_type="domain",original_domain=original_domain.domain,
# 		registrant_organization=row[number][5]
# 		)
# 		# message=row[number][1]
# 		# message = message +"has been registered"
# 		# notify=notifications.objects.get_or_create(user=request.user,message=message,domain_name=row[number][1],created_date=row[number][9],detected_type="domain")
# 		#domain_obj.append(row[number])
# 		#print("row data"+row[number][6])
		

# def table(request):
# 	return render(request,'tables.html')


# def search(request):
# 	from django.db.models import Q
# 	msg=''
# 	keyword=request.POST.get('keyword')
# 	try:
# 		#get_domainlist=DetectionTable.objects.filter
# 		search_result=DetectionTable.objects.filter(Q(domain_detected__contains=keyword)|Q(detection_type__contains=keyword)|Q(original_domain__contains=keyword),user=request.user)
# 		#search_result=search_result.objects.filter(user=request.user)
# 		paginator = Paginator(search_result,5) 
# 		page = request.GET.get('page',1)
# 		search_result = paginator.page(page)
# 	except Exception as e:
# 		msg="No results found"
# 	print(request.user)
# 	#print(str(search_result))
	
# 	context={
# 		"search_result":search_result,
# 		"msg":msg,
		
# 		}
# 	return render(request,"search.html",context)

# # Get the matching query from detection table and send email to the particular id
# def email(request,init):
# 	domain_obj= DetectionTable.objects.get(id=init)
# 	context={
# 	"domain_obj":domain_obj
# 	}
# 	return render(request,'email.html',context)
	


# # Get the subject , message and tolist and check if the email exists in the detection database.
# def sendemail(request):
# 	print("sjjjjjjsjdhsakjdjashdkjashdkjadhkj")
# 	toemail=request.POST.get('to_email')
# 	subject=request.POST.get('subject')
# 	message=request.POST.get('message')
# 	for x in toemail.split(','):
# 		try:
# 			print("try")
# 			query= DetectionTable.objects.get(user=request.user,registrant_email=x)
# 			mailed(toemail,message,subject,request)
# 		except Exception as e:
# 			print(x+"mail not found")
# 	# context={
# 	# msg:"<font color='green'>Email Sent</font>"
# 	# }

# 	return HttpResponseRedirect('/dashboard')

def logout_view(request):
    logout(request)
    return HttpResponseRedirect('/login')

# # open the workbook and store the entire data inside temp database
# def excel_import(request,filename):
# 	import json
# 	import xlrd
# 	workbook = xlrd.open_workbook(filename)
# 	worksheet = workbook.sheet_by_index(0)
# 	print("excel_import")
# 	#print(worksheet.nrows)


# 	for row in range (1, worksheet.nrows):		
# 		domainName=worksheet.cell_value(row,0)
# 		registrarName= worksheet.cell_value(row,1)
# 		contactEmail=worksheet.cell_value(row,2)
# 		whoisServer=worksheet.cell_value(row,3)
# 		nameServers=worksheet.cell_value(row,4)
# 		createdDate=worksheet.cell_value(row,5)
# 		updatedDate=worksheet.cell_value(row,6)
# 		expiresDate=worksheet.cell_value(row,7)
# 		standardRegCreatedDate=worksheet.cell_value(row,8)
# 		standardRegUpdatedDate=worksheet.cell_value(row,9)
# 		standardRegExpiresDate=worksheet.cell_value(row,10)
# 		status=worksheet.cell_value(row,11)
# 		Audit_auditUpdatedDate=worksheet.cell_value(row,12)
# 		registrant_email=worksheet.cell_value(row,13)
# 		registrant_name=worksheet.cell_value(row,14)
# 		registrant_organization=worksheet.cell_value(row,15)
# 		registrant_street1=worksheet.cell_value(row,16)
# 		registrant_street2=worksheet.cell_value(row,17)
# 		registrant_street3=worksheet.cell_value(row,18)
# 		registrant_street4=worksheet.cell_value(row,19)
# 		registrant_city=worksheet.cell_value(row,20)
# 		registrant_state=worksheet.cell_value(row,21)
# 		registrant_postalCode=worksheet.cell_value(row,22)
# 		registrant_country=worksheet.cell_value(row,23)
# 		registrant_fax=worksheet.cell_value(row,24)
# 		registrant_faxExt=worksheet.cell_value(row,25)
# 		registrant_telephone=worksheet.cell_value(row,26)
# 		registrant_telephoneExt=worksheet.cell_value(row,27)
# 		administrativeContact_email=worksheet.cell_value(row,28)
# 		administrativeContact_name=worksheet.cell_value(row,29)
# 		administrativeContact_organization=worksheet.cell_value(row,30)
# 		administrativeContact_street1=worksheet.cell_value(row,31)
# 		administrativeContact_street2=worksheet.cell_value(row,32)
# 		administrativeContact_street3=worksheet.cell_value(row,33)
# 		administrativeContact_street4=worksheet.cell_value(row,34)
# 		administrativeContact_city=worksheet.cell_value(row,35)
# 		administrativeContact_state=worksheet.cell_value(row,36)
# 		administrativeContact_postalCode=worksheet.cell_value(row,37)
# 		administrativeContact_country=worksheet.cell_value(row,38)
# 		administrativeContact_fax=worksheet.cell_value(row,39)
# 		administrativeContact_faxExt=worksheet.cell_value(row,40)
# 		administrativeContact_telephone=worksheet.cell_value(row,41)
# 		administrativeContact_telephoneExt=worksheet.cell_value(row,42)
	
# 		#print(domainName,registrarName)	

# 		#store the excel to the database		
# 		query=temp_data.objects.get_or_create(domainName=domainName,registrarName=registrarName,
# 		contactEmail=contactEmail,whoisServer=whoisServer,nameServers=nameServers,createdDate=createdDate,updatedDate=updatedDate,
# 		expiresDate=expiresDate,standardRegCreatedDate=standardRegCreatedDate,standardRegUpdatedDate=standardRegUpdatedDate,
# 		standardRegExpiresDate=standardRegExpiresDate,status=status,Audit_auditUpdatedDate=Audit_auditUpdatedDate,
# 		registrant_email=registrant_email,registrant_name=registrant_name,registrant_organization=registrant_organization,
# 		registrant_street1=registrant_street1,registrant_street2=registrant_street2,registrant_street3=registrant_street3,
# 		registrant_street4=registrant_street4,registrant_city=registrant_city,registrant_state=registrant_state,
# 		registrant_postalCode=registrant_postalCode,registrant_country=registrant_country,registrant_fax=registrant_fax,
# 		registrant_faxExt=registrant_faxExt,registrant_telephone=registrant_telephone,registrant_telephoneExt=registrant_telephoneExt,
# 		administrativeContact_email=administrativeContact_email,administrativeContact_name=administrativeContact_name,
# 		administrativeContact_organization=administrativeContact_organization,administrativeContact_street1=administrativeContact_street1,
# 		administrativeContact_street2=administrativeContact_street2,administrativeContact_street3=administrativeContact_street3,
# 		administrativeContact_street4=administrativeContact_street4,administrativeContact_city=administrativeContact_city,
# 		administrativeContact_state=administrativeContact_state,administrativeContact_postalCode=administrativeContact_postalCode,
# 		administrativeContact_country=administrativeContact_country,administrativeContact_fax=administrativeContact_fax,
# 		administrativeContact_faxExt=administrativeContact_faxExt,administrativeContact_telephone=administrativeContact_telephone,
# 		administrativeContact_telephoneExt=administrativeContact_telephoneExt)

		
# 		cron_jon_update_domains(request)		


# 	return HttpResponse("success")


# def post_domain(request):
# 	#calculate_combinations(request,'trepp.asia')
# 	return HttpResponse("qwdwqdqwdd")


def calculate_combinations(user,dom_obj):
	import os
	print("calculate comb")
	domainname=dom_obj.domain
	print(domainname)
	try:
		os.system("dnstwist --csv "+domainname+"> "+domainname+".csv")
		dom_obj
		print(os.system("dnstwist --csv "+ domainname))
		import csv
		filename=domainname+'.csv'
		with open(filename) as csvfile:
			reader = csv.DictReader(csvfile)
			for row in reader:
				combination.objects.get_or_create(original_domain=dom_obj,domain_name=row['domain-name'],fuzzer=row['fuzzer'])
				# w=whois.whois(row['domain-name'])
				# print(w)
				print(row['fuzzer'], row['domain-name'])
	except Exception as e:
		print(e)
	user_obj=User.objects.get(username=user)
		# _thread.start_new_thread( find_matching_domain, (user_obj) )
	find_matching_domain(user_obj)
		
	return HttpResponse("success")


def find_matching_domain(user_obj):
	domain_obj=domains.objects.filter(member=user_obj)
	for i in domain_obj:
		print("domain check")

		avail_list=[]

		domain_check_list=combination.objects.filter(original_domain=i)
		for dom in domain_check_list:

			print(dom)

			w=whois.whois(dom.domain_name)
			if w['status']!=None:
				import simplejson as json
				#w['creation_date'][0]
				Detection.objects.get_or_create(user=user_obj,domain_detected=dom.domain_name,registrant_email=json.dumps(w['emails']),registrant_name=w['registrar'],original_domain=dom.original_domain,whoisServer=w['whois_server'])
			else:
				print("no status")
	return HttpResponse("success")
			

def inbox(request):
	user=User.objects.get(id=request.user.id)
	result=Detection.objects.filter(user=user)
	flag=True
	print(user.id)

	if result.exists():
		flag=True
	else:
		flag=False

	ticket_list=ticketsetting.objects.filter(user=request.user)
	
	context={
	"flag":flag,
	"user":user,
	"domain_obj":result,
	"ticket_list":ticket_list
	}

	return render(request,"inbox.html",context)



def email_temp(request):


	if request.method == "POST":

		content=request.POST.get('content')
		print(content)

		return HttpResponse(content)

	return render(request,"email.html")


def add_temp(request):
	category_list=""
	if request.method == "POST":
		categoryname=request.POST.get('category')
		subject=request.POST.get('subject')
		content=request.POST.get('content')
		print(content)
		try:
			category_obj=category.objects.get(category_name=categoryname)
			temp=emailTemplate.objects.get_or_create(category=category_obj,content=content,subject=subject)
		except Exception as e:
			print(e)

	category_list=category.objects.all()


	context={
	"category_list":category_list
	}
	return render(request,'new_template.html',context)


def get_template(request):
	temp=request.POST.get('temp_value')
	print("getttttttt")
	print(temp)

	email_content=''

	try:
		category_obj=category.objects.get(category_name=temp)
		temp=emailTemplate.objects.get(category=category_obj)
		email_content=temp.content
		print(email_content)
	except Exception as e:
		print(e)
		email_content=''
	

	
	return HttpResponse(email_content)




from django.views.decorators.cache import never_cache

@never_cache
def view_template(request):
	
	init=request.GET.get('init','')
	category_list=""
	whoisemail=[]
	ticket_id=init
	ticketid=init
	print(init)
	email_list=""
	email_content=""

	categoryname=ticketsetting.objects.get(id=init)

	categoryobj=category.objects.get(category_name=categoryname.category)
	#ticket_id=ticketsetting.objects.get(id=ticketid)
	# try:

	# 	email_content=emailTemplate.objects.get(category=categoryobj.id)
	# 	print("ticketid")
	# 	print(ticket_id)
	# except Exception as e:
	# 	email_content=" "

	try:
		email=whoisinfo.objects.get(ticketid=init)
		import json
		email_list = json.loads(email.registrant_email)
		print(email.list[0])
	except Exception as e:
		print(e)


	print(email_list)


	try:
		email_content=emailTemplate.objects.get(category=categoryobj).content

	except Exception as e:
		email_content=''

	if request.method == "POST":
		email_list=request.POST.getlist('to')
		print(email_list)

		for i in range(len(email_list)):
			print(email_list[i])
		#categoryname=request.POST.get('category')
		subject=request.POST.get('subject')
		content=request.POST.get('content')
		from_email = EMAIL_HOST_USER
		to_list=['singh.94soumya@outlook.com.']
		#context_data["image_url"] = equest.build_absolute_uri(reverse("image_load"))


		ctx = {
			'content': content,
			'image_url':request.build_absolute_uri("http://tracking.domain.com/image_load")

			}
		message = render_to_string('mailer.html', ctx)
		send_mail(subject,message,from_email,email_list,html_message=message,fail_silently=False)

		return HttpResponseRedirect('/admin-inbox')


	category_list=category.objects.all()
	print(email_content)

	context={
	"category_list":category_list,
	"content":email_content,
	"email_list":email_list
	}
	return render(request,'view_template.html',context)




def ainbox(request):
	ticket_list=ticketsetting.objects.all()
	
	context={
	"ticket_list":ticket_list
	}

	return render(request,"admin-inbox.html",context)


def ainbox_d(request):
	if request.user.is_authenticated==True:
		comm=""
		status_txt=''
		status=request.POST.get('select1','')
		print(status)
		#id=request.GET.get('id','')
		id=request.GET.get('id','')
		ide=id
		
		print(id)
		import os
		#print(os.path.join(os.path.dirname(BASE_DIR)))
		
		#comment=request.POST.get('markdow','')
		if (request.user.is_authenticated==False):
			return HttpResponseRedirect('/login')
		a="%s" %(request.user)
		username=a
		paths=''
		msg=""
		uploaderror=0
		comment=request.POST.get('comment','')
		print(comment)
		if(request.method == "POST"):
			try:
				status=request.POST.get('select1','')
				print(status)

				if status=='4':
					status_txt='Open'
				if status=='0':
					status_txt='Resolved'
				if status=='1':
					status_txt="Closed"
				if status=='3':
					status_txt="Duplicate"

				status_change=ticketsetting.objects.get(id=ide)
				status_change.status=status_txt
				status_change.save()

				if(status == '4' or status == '0' or status == '1' or status == '3'):
					comment=username + " has changed the status to "+ status_txt
					kk=Commments(username=a,ticketid=id,filenames=str(paths),comments=comment)
					kk.save()


				for count, x in enumerate(request.FILES.getlist("files")):
					if(count==5):
						break
					else:
						#hh=upload_file(x,a)
						hh=handle_uploaded_file(x,a)
						print(hh)
						if (hh!='not'):
							paths=paths+","+hh					
			except Exception as e:
				print(e)
				uploaderror=1

			if (comment!='' and uploaderror != 1):
				try:
					
					kk=Commments(username=a,ticketid=id,filenames=str(paths),comments=comment)
					kk.save()
					
				except Exception as e:
					print(e)
					msg="<font color='red'> Technical Glitch </font>"
			else:
				msg="<font color='red'> Please note only jpg,png and zip files are allowed, and comment is required</font> "
		
		try:
			result=ticketsetting.objects.get(id=id)
			print("id is"+id)
			# comm=messages.objects.filter(username=a,messageid=id,is_read=False).update(is_read=True)

			k=result.pimage
			k=k.split(',')
			# hacker=result.username
			comm=Commments.objects.filter(ticketid=id).order_by('id')
			l=len(comm)
		except Exception as e:
			print(e)
			result=""
			k=''
			comm=''
			l=0
		if id=='':
			result =''
			k=""
			comm=""
			l=0
		else:
			a=""
		
		print(result)
		
		context={
		
		"result":result,
		"comm":comm,
		"k":k,
		"username":username,
		}
		return render(request,"admin-inbox-detail.html",context)
	else:
		logout(request)
		return HttpResponseRedirect('/login')




def hinbox_d(request,init):
	if request.user.is_authenticated==True:
		comm=""
		#id=request.GET.get('id','')
		id=init
		print(id)
		import os
		#print(os.path.join(os.path.dirname(BASE_DIR)))
		
		#comment=request.POST.get('markdow','')
		if (request.user.is_authenticated==False):
			return HttpResponseRedirect('/login')
		a="%s" %(request.user)
		username=a
		paths=''
		msg=""
		uploaderror=0
		comment=request.POST.get('comment','')
		if(request.method == "POST"):
			try:
				for count, x in enumerate(request.FILES.getlist("files")):
					if(count==5):
						break
					else:
						#hh=upload_file(x,a)
						hh=handle_uploaded_file(x,a)
						print(hh)
						if (hh!='not'):
							paths=paths+","+hh
							

			except Exception as e:
				print(e)
				uploaderror=1

			if (comment!='' and uploaderror != 1):
				try:
					
					kk=Commments(username=a,ticketid=id,filenames=str(paths),comments=comment)
					kk.save()
					
				except Exception as e:
					print(e)
					msg="<font color='red'> Technical Glitch </font>"
			else:
				msg="<font color='red'> Please note only jpg,png and zip files are allowed, and comment is required</font> "
		
		try:
			result=ticketsetting.objects.get(id=id)
			print("id is"+id)
			# comm=messages.objects.filter(username=a,messageid=id,is_read=False).update(is_read=True)

			k=result.pimage
			k=k.split(',')
			# hacker=result.username
			comm=Commments.objects.filter(ticketid=id).order_by('id')
			l=len(comm)
		except Exception as e:
			print(e)
			result=""
			k=''
			comm=''
			l=0
		if id=='':
			return HttpResponseRedirect('login')
		else:
			a=""
		
		context={
		
		"result":result,
		"comm":comm,
		"k":k,
		
		"username":username,
		}
		return render(request,"hacker-inbox-detail.html",context)
	else:
		logout(request)
		return HttpResponseRedirect('/login')


def handle_uploaded_file(f,a):
	filename, ext = os.path.splitext(f.name)
	siz=f.size
	mime=f.content_type
	if (mime == 'image/png' or mime == 'image/jpeg' or mime ==  'application/zip'):
		#print(mime)
		mime = True
	else:
		mime = False
	#print("mime is "+str(mime))
	if (ext == '.png' or ext == '.zip' or ext == '.jpg' or ext == '.jpeg'):
		exti=True
	else:
		exti=False
	#print("ext is "+str(ext))
	if (siz<=20971520 and exti== True and mime == True):
		am= str(random.random())+str(a)
		am.encode('utf-8')
		#kk=hashlib.sha256(am).hexdigest()+a+ext
		rand_username = str(random.random())+str(a)
		kk=hashlib.sha256(rand_username.encode('utf-8')).hexdigest()
		# randomm=str(random.random())+str(a).encode('utf-8')
		# kk=hashlib.sha256(randomm).hexdigest()+a+ext
		path=os.path.dirname(BASE_DIR)+"/uploaded/"+kk
		#print(path)
		destination=open(path, 'wb+')
		for chunk in f.chunks():
			#print(len(chunk))
			destination.write(chunk)
		destination.close()
		return kk
	else:
		return "not"

# def calculate_combinations(user,domainname):
# 	print("calculate_combinations")
# 	try:
# 		domain_search=admin_domain.objects.get(domain=domainname)
# 		get_com=admin_combination.objects.filter(original_domain=domain_search)
# 		domain_obj=domains.objects.get(member=user,domain=domainname)
# 		for j in get_com:
# 			combination.objects.get_or_create(original_domain=domain_obj,domain_name=j.domain_name,fuzzer=j.fuzzer)
# 	except Exception as e:
# 		print(e)
# 		fuzz = dnstwist.DomainFuzz(domainname)
# 		try:
# 			fuzz.generate()
# 		except Exception as e:
# 			print(e)
# 		dom=fuzz.domains
# 		domain_obj=domains.objects.get(member=user,domain=domainname)
# 		for i in dom:
# 			domain=i['domain-name']
# 			fuz=i['fuzzer']
# 			combination_query=combination.objects.get_or_create(original_domain=domain_obj,domain_name=domain,fuzzer=fuz)
# 		domain=domains.objects.filter(member=user)
# 		for i in domain:
# 			print("user="+str(user))
			

# 	return HttpResponse("weewde")

# def checkMyKeywords(user):
# 	keyw_list=Keywords.objects.filter(user=user)


	

# 	for i in keyw_list:
# 		print(i.keyword)
# 	# 	match=excel_data.objects.filter(domainName__icontains=i.keyword)
# 	# 	for j in match:
# 	# 		DetectionTable.objects.get_or_create(user=user,domain_detected=j.domainName ,registrant_email=j.registrant_email, 
# 	# 		whoisServer=j.whoisServer,createdDate=j.whoisServer,registrant_state=j.registrant_state,registrant_country=j.registrant_country
# 	# 		)
# 	from django.db import connection
# 	cursor = connection.cursor()
# 	print(connection.queries)
	
# 	#print(request.user.id)
# 	userid=user.id

# 	print("%s" %(userid))


# 	userins=User.objects.get(id=userid)
# 	cursor.execute("Select * FROM  bprotect_excel_data JOIN bprotect_keywords ON bprotect_excel_data.domainName like concat('%',bprotect_keywords.keyword,'%') where bprotect_keywords.user_id="+str(userid))
	
# 	#getdata="Select * FROM  bprotect_temp_data JOIN bprotect_keywords ON bprotect_temp_data.domainName like concat('%',bprotect_keywords.keyword,'%') where bprotect_keywords.user_id=%d",[user.id]

# 	#print("Select * FROM  bprotect_temp_data JOIN bprotect_keywords ON bprotect_temp_data.domainName like concat('%',bprotect_keywords.keyword,'%') where bprotect_keywords.user_id=%d",[user.id])
# 	#print(getdata.query)
# 	#result_set=dictfetchall(cursor)
# 	row = cursor.fetchall()
# 	counting=cursor.rowcount
# 	print(row)
# 	for number in range(counting):		
# 		domain_detected_obj=DetectionTable.objects.get_or_create(user=userins,domain_detected=row[number][43] ,registrant_email=row[number][2], 
# 		whoisServer=row[number][3],createdDate=row[number][5],registrant_state=row[number][24],registrant_country=row[number][27],detection_type="keyword"
# 		)
# 		# notify=notifications.objects.get_or_create(user=userins,domain_name=row[number][43],created_date=row[number][5],detected_type='keyword')
# 		# message=row[number][43]
# 		# message=message+'has been registered'
# 		#email
# 		print(row[number][2])
# 		# domainName
# 		print(row[number][43])
# 		#whois
# 		print(row[number][3])
# 		#created
# 		print(row[number][5])
# 	return HttpResponse("WDEWd")

		

# def checkMyDomain(user,domain):
# 	# info=domains.objects.get(member=user,domain=domain)
# 	# domain_name=info.domain
# 	print("wdwedwedewdedewdewdewdewd")
# 	calculate_combinations(user,domain)
# 	return HttpResponse("success")


# def mailed(email,message,subject,request):
# 	subject = subject
# 	message = email
# 	from_email = EMAIL_HOST_USER
# 	to_list = [email,EMAIL_HOST_USER]
# 	send_mail(subject,message,from_email,to_list,fail_silently=False)


# def notify_user(email,Subject,message,request):
# 	subject = Subject
# 	message = message
# 	from_email = EMAIL_HOST_USER
# 	to_list = [email,EMAIL_HOST_USER]
# 	send_mail(subject,message,from_email,to_list,fail_silently=True)


def mailed_verify(email,code,request):
	subject = 'Registration to Brand Protection'
	message = 'Please Verify.\n Code is http://'+str(host_get_name(request))+'/'+'verify.dll?token='+code+'&email='+email
	from_email = EMAIL_HOST_USER
	to_list = [email,EMAIL_HOST_USER]
	send_mail(subject,message,from_email,to_list,fail_silently=True)

def host_get_name(request):
	return request.META['HTTP_HOST']

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0] + ","+request.META.get('REMOTE_ADDR')
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def verify(request):
	msg=""
	if request.user.is_authenticated:
		return HttpResponseRedirect('/dashboard')
	tok=request.GET.get('token','')
	email=request.GET.get('email','')
	if(tok=='' and email ==''):
			return HttpResponseRedirect('login')
	else:
		try:
			print("inside tru")
			a=activate.objects.get(hashed=tok,expired=False)
			#print a.email+ " "+email
			if(a.email==email):
				query2=User.objects.get(email=a.email)
				query2.is_active=True
				query2.save()
				a.expired=True
				a.save()
				user= User.objects.get(email=a.email)
				domainname=domains.objects.get(member=user).domain
				print(domainname)
				#checkMyDomain(user,domainname)
				#checkMyKeywords(user)
				msg="""

<h1 class="bb-center">Congrats!!</h1>
                    <h5 class="bb-center">Your account has been activated, Please <a href="login">Login</a></h5>
				"""

		except Exception as e:
			print(e)
			msg="<font color='red'>Invalid Token</font>"
	context={
	"msg":msg,
	}
	return HttpResponse(msg)

# def excel_upload(request):
# 	if request.method == 'POST':

# 		a="%s" %(request.user)
# 		print(request.FILES['test'])
# 		#up=upload_cv(request.FILES['test'],a)
# 		try:
# 			up=upload_excel(request.FILES['test'],a)
# 		except Exception as e:
# 			print(e)
# 			up='not'
# 		print("filename"+up)
# 		if (up!='not'):
# 			print("file uploaded successfully")
# 			# if file is uploaded successfully , store the data in the temp database
# 			excel_import(request,up)


# 	return render(request,'file-upload.html')
	

# def upload_excel(f,a):
# 	filename, ext = os.path.splitext(f.name)
# 	siz=f._size
# 	mime=f.content_type
# 	# Check file size and type, if conditions matches upload to Development/uploaded folder. 	
# 	if (mime == 'application/pdf' or mime == 'application/msword'):
# 		print mime
# 		mime = True
# 		print mime
# 	else:
# 		mime = False
# 	# if (ext == '.csv'):
# 	# 	exti=True
# 	# else:
# 	# 	exti=False
# 	exti=True
# 	print("extnsion"+str(exti))
	
# 	if (siz<=20971520 and exti== True):
# 		# Generate a random string and attach it with the username , this will give a unique file name
# 		kk=hashlib.sha256(str(random.random())+str(a)).hexdigest()+ext

		
# 		print(kk)
# 		path=os.path.dirname(BASE_DIR)+"/brandprotection/"+kk
# 		print ("path"+str(path))
# 		destination=open(path, 'wb+')
# 		for chunk in f.chunks():
# 			#print len(chunk)
# 			destination.write(chunk)
		
# 		destination.close()
# 		return kk
# 	else:
# 		return "not"
	

# def cron_jon_update_domains(request):
# 	from django.contrib.auth.models import User
# 	from django.db import connection
# 	print('cron job')
# 	cursor = connection.cursor()
	
# 	cursor.execute("Select * from bprotect_combination inner join bprotect_temp_data on bprotect_combination.domain_name=bprotect_temp_data.domainName")	
# 	row=cursor.fetchall()
# 	#print(row)
# 	counting=cursor.rowcount
# 	for number in range(counting):
# 		get_original_domain=combination.objects.get(domain_name=row[number][1]).original_domain
# 		print(str(get_original_domain.member))
# 		#domain_name=domains.objects.filter(domain=row[number][1])
# 		# print("domainname"+ str(domain_name))
# 		# for i in domain_name:
# 		usern=get_original_domain.member
# 		user=User.objects.get(username=usern)
# 		domain_detected_obj=DetectionTable.objects.get_or_create(user=user,domain_detected=row[number][1] ,registrant_email=row[number][6], 
# 		whoisServer=row[number][7],createdDate=row[number][9],registrant_state=row[number][24],registrant_country=row[number][27],
# 		registrant_organization=row[number][34],detection_type='domain',original_domain=get_original_domain)
# 		email=user.email
# 		Subject="New domain registered"
# 		domian_target=row[number][1]
# 		message=domian_target+"has beeeen registered recently"
# 		#notify_user(email,Subject,message,request)
# 		#notify=notifications.get_or_create(user=user,message=message,domain_name=row[number][1],created_date=row[number][9],detected_type='domain')
# 		thread.start_new_thread(notify_user,(email,Subject,message,request))
# 	get_matching_keywords(request)

# 	return HttpResponse("jhjkhkj")

		
# def get_matching_keywords(request):	
# 	#terms = request.GET.get('terms', None)
# 	#from django.db import connection
# 	from django.db import connection
# 	cursor = connection.cursor()
# 	print(connection.queries)
# 	#from django.db.models import Q
# 	key_list = Keywords.objects.all()

# 	print("get all keywords list:"+str(key_list.query))

# 	cursor.execute("Select * FROM  bprotect_temp_data JOIN bprotect_keywords ON bprotect_temp_data.domainName like concat('%',bprotect_keywords.keyword,'%')")
	
# 	#result_set=dictfetchall(cursor)
# 	result_set = cursor.fetchall()
# 	counting=cursor.rowcount

# 	for i in range(counting):
# 		print(result_set[i][46])
# 		user=User.objects.get(id=result_set[i][46])
# 		domain_detected_obj=DetectionTable.objects.get_or_create(user=user,domain_detected=row[number][1] ,registrant_email=row[number][6], 
# 		whoisServer=row[number][7],createdDate=row[number][9],registrant_state=row[number][24],registrant_country=row[number][27],
# 		registrant_organization=row[number][34],detection_type='domain')
# 		keyword_target=row[number][1]
# 		message=keyword_target+"has beeeen registered recently"
# 		#notify=notifications.get_or_create(user=user,message=message,domain_name=row[number][1],created_date=row[number][9],type='keyword')



#  	return HttpResponse("keywords matching done")


# def dataimport(request):
# 	import json
# 	import xlrd
# 	workbook = xlrd.open_workbook('whois.xls')
# 	worksheet = workbook.sheet_by_index(0)
# 	print(worksheet.nrows)


# 	for row in range (1, worksheet.nrows):		
# 		domainName=worksheet.cell_value(row,0)
# 		registrarName= worksheet.cell_value(row,1)
# 		contactEmail=worksheet.cell_value(row,2)
# 		whoisServer=worksheet.cell_value(row,3)
# 		nameServers=worksheet.cell_value(row,4)
# 		createdDate=worksheet.cell_value(row,5)
# 		updatedDate=worksheet.cell_value(row,6)
# 		expiresDate=worksheet.cell_value(row,7)
# 		standardRegCreatedDate=worksheet.cell_value(row,8)
# 		standardRegUpdatedDate=worksheet.cell_value(row,9)
# 		standardRegExpiresDate=worksheet.cell_value(row,10)
# 		status=worksheet.cell_value(row,11)
# 		Audit_auditUpdatedDate=worksheet.cell_value(row,12)
# 		registrant_email=worksheet.cell_value(row,13)
# 		registrant_name=worksheet.cell_value(row,14)
# 		registrant_organization=worksheet.cell_value(row,15)
# 		registrant_street1=worksheet.cell_value(row,16)
# 		registrant_street2=worksheet.cell_value(row,17)
# 		registrant_street3=worksheet.cell_value(row,18)
# 		registrant_street4=worksheet.cell_value(row,19)
# 		registrant_city=worksheet.cell_value(row,20)
# 		registrant_state=worksheet.cell_value(row,21)
# 		registrant_postalCode=worksheet.cell_value(row,22)
# 		registrant_country=worksheet.cell_value(row,23)
# 		registrant_fax=worksheet.cell_value(row,24)
# 		registrant_faxExt=worksheet.cell_value(row,25)
# 		registrant_telephone=worksheet.cell_value(row,26)
# 		registrant_telephoneExt=worksheet.cell_value(row,27)
# 		administrativeContact_email=worksheet.cell_value(row,28)
# 		administrativeContact_name=worksheet.cell_value(row,29)
# 		administrativeContact_organization=worksheet.cell_value(row,30)
# 		administrativeContact_street1=worksheet.cell_value(row,31)
# 		administrativeContact_street2=worksheet.cell_value(row,32)
# 		administrativeContact_street3=worksheet.cell_value(row,33)
# 		administrativeContact_street4=worksheet.cell_value(row,34)
# 		administrativeContact_city=worksheet.cell_value(row,35)
# 		administrativeContact_state=worksheet.cell_value(row,36)
# 		administrativeContact_postalCode=worksheet.cell_value(row,37)
# 		administrativeContact_country=worksheet.cell_value(row,38)
# 		administrativeContact_fax=worksheet.cell_value(row,39)
# 		administrativeContact_faxExt=worksheet.cell_value(row,40)
# 		administrativeContact_telephone=worksheet.cell_value(row,41)
# 		administrativeContact_telephoneExt=worksheet.cell_value(row,42)
	
# 		print(domainName,registrarName)	

# 		#store the excel to the database		
# 		query=excel_data.objects.get_or_create(domainName=domainName,registrarName=registrarName,
# 		contactEmail=contactEmail,whoisServer=whoisServer,nameServers=nameServers,createdDate=createdDate,updatedDate=updatedDate,
# 		expiresDate=expiresDate,standardRegCreatedDate=standardRegCreatedDate,standardRegUpdatedDate=standardRegUpdatedDate,
# 		standardRegExpiresDate=standardRegExpiresDate,status=status,Audit_auditUpdatedDate=Audit_auditUpdatedDate,
# 		registrant_email=registrant_email,registrant_name=registrant_name,registrant_organization=registrant_organization,
# 		registrant_street1=registrant_street1,registrant_street2=registrant_street2,registrant_street3=registrant_street3,
# 		registrant_street4=registrant_street4,registrant_city=registrant_city,registrant_state=registrant_state,
# 		registrant_postalCode=registrant_postalCode,registrant_country=registrant_country,registrant_fax=registrant_fax,
# 		registrant_faxExt=registrant_faxExt,registrant_telephone=registrant_telephone,registrant_telephoneExt=registrant_telephoneExt,
# 		administrativeContact_email=administrativeContact_email,administrativeContact_name=administrativeContact_name,
# 		administrativeContact_organization=administrativeContact_organization,administrativeContact_street1=administrativeContact_street1,
# 		administrativeContact_street2=administrativeContact_street2,administrativeContact_street3=administrativeContact_street3,
# 		administrativeContact_street4=administrativeContact_street4,administrativeContact_city=administrativeContact_city,
# 		administrativeContact_state=administrativeContact_state,administrativeContact_postalCode=administrativeContact_postalCode,
# 		administrativeContact_country=administrativeContact_country,administrativeContact_fax=administrativeContact_fax,
# 		administrativeContact_faxExt=administrativeContact_faxExt,administrativeContact_telephone=administrativeContact_telephone,
# 		administrativeContact_telephoneExt=administrativeContact_telephoneExt)


# 	return HttpResponse("successs")

# def dictfetchall(cursor): 
#     "Returns all rows from a cursor as a dict" 
#     desc = cursor.description 
#     return [
#             dict(zip([col[0] for col in desc], row)) 
#             for row in cursor.fetchall() 
#     ]

# def keyword_test(request):
# 	#terms = request.GET.get('terms', None)
# 	#from django.db import connection
# 	from django.db import connection
# 	cursor = connection.cursor()
# 	print(connection.queries)
# 	#from django.db.models import Q

# 	key_list = Keywords.objects.all()

# 	print("get all keywords list:"+str(key_list.query))

# 	cursor.execute("Select * FROM  bprotect_temp_data JOIN bprotect_keywords ON bprotect_temp_data.domainName like concat('%',bprotect_keywords.keyword,'%')")
	
# 	#result_set=dictfetchall(cursor)
# 	result_set = cursor.fetchall()
# 	counting=cursor.rowcount

# 	for i in range(counting):
# 		print(result_set[i][46])
# 		print(result_set[i][2])
# 		print(result_set[i][1])
# 		print(result_set[i][3])
# 	print(counting)
# 	print(result_set)
# 	return HttpResponse("seach done")

# def user_settings(request):
# 	user=User.objects.get(username=request.user)
# 	get_user_domains=domains.objects.filter(member=request.user)
# 	get_user_keywords=Keywords.objects.filter(user=user)

# 	print(len(get_user_domains))
# 	print(len(get_user_keywords))
# 	print(str(get_user_domains))

# 	context={

# 	'keywords_list':get_user_keywords,
# 	'domain_list':get_user_domains
# 	}
# 	print(request.user)
# 	return render(request,'settings.html',context)


# def del_domain(request):
# 	domain_name=request.POST.get('domain_name')
# 	user=User.objects.get(username=request.user)
# 	update_domain=domains.objects.get(member=request.user,domain=domain_name).delete()
# 	#DetectionTable.objects.filter(user=request.user,original_domain=domain_name).delete()

# 	return HttpResponse("success")

# def edit_keyword(request):
# 	old_keyword=request.POST.get('old_keyword')
# 	new_keyword=request.POST.get('value')

# 	print(old_keyword)
# 	print(new_keyword)

# 	user=User.objects.get(username=request.user)
# 	update_keyword=Keywords.objects.get(user=request.user,keyword=old_keyword)

# 	update_keyword.keyword = new_keyword  # change field
# 	update_keyword.save()
# 	checkMyKeywords(request.user)
# 	return HttpResponse("success")

# def del_keyword(request):

# 	keyword_name=request.POST.get('keyword_name')
# 	user=User.objects.get(username=request.user)
# 	update_domain=Keywords.objects.get(user=request.user,keyword=keyword_name).delete()
# 	return HttpResponse("success")

# #Edit domain
# def edit_domain(request):
# 	old_domain=request.POST.get('old_domain')
# 	new_domain=request.POST.get('value')
# 	print(new_domain)
# 	print(old_domain)
# 	user=User.objects.get(username=request.user)

# 	update_domain=domains.objects.get(member=request.user,domain=old_domain)
# 	update_domain.domain = new_domain  # change field
# 	update_domain.save()
# 	print("saved")
# 	#DetectionTable.objects.filter(user=request.user,original_domain=old_domain).delete()
# 	checkMyDomain(request.user,new_domain)
# 	get_matching_domains(request,update_domain.id)
# 	return HttpResponse("deew")

# def add_keyword(request):
# 	keyword=request.POST.get('keyword_name')
	
# 	newkeyword=Keywords.objects.get_or_create(user=request.user,keyword=keyword)
# 	checkMyKeywords(request.user)
# 	return HttpResponse("success")


# def add_domain(request):
# 	new_domain=request.POST.get('domain_name')
# 	print(new_domain)
# 	newdomain=domains.objects.get_or_create(member=request.user,domain=new_domain)
# 	#newdomain.domain
# 	checkMyDomain(request.user,new_domain)
# 	domain=domains.objects.filter(member=request.user)
# 	for i in domain:
# 		print(i.domain)
# 		get_matching_domains(request,i.id)
# 	return HttpResponse("deew")

# def del_alerts(request):
# 	alert_id=request.POST.get('id')
# 	return HttpResponse("success")



# def get_alerts(request):
# 	print(request.POST.get('timeline'))
# 	return HttpResponse("success")


# def admin_search(request):
# 	domain=request.POST.get('domain')
# 	#domain='bugsbounty.com'
# 	print(domain)
# 	domain_name=admin_domain.objects.get_or_create(user=request.user,domain=domain)
# 	admin_calculate_combinations(request.user,domain)
# 	return HttpResponse("success")


# def admin_calculate_combinations(user,domainname):
# 	print("calculate_combinations")
# 	fuzz = dnstwist.DomainFuzz(domainname)
# 	try:
# 		fuzz.generate()
# 	except Exception as e:
# 		print(e)
# 	dom=fuzz.domains
# 	domain_obj=admin_domain.objects.get(user=user,domain=domainname)
# 	for i in dom:
# 		domain=i['domain-name']
# 		fuz=i['fuzzer']
# 		combination_query=admin_combination.objects.get_or_create(original_domain=domain_obj,domain_name=domain,fuzzer=fuz)
# 	domain=admin_combination.objects.filter(original_domain=domain_obj)
# 	# import xlwt
# 	# book = xlwt.Workbook(encoding="utf-8")
# 	# sheet1 = book.add_sheet("Sheet 1")

# 	# import csv
# 	# with open('output.csv', 'w') as f:
# 	# 	writer = csv.writer(f)
# 	for i in domain:
# 		print(i.domain)
# 	# 		writer.writerow([i.domain_name])

		
# 	# path = './output.csv'
# 	# if os.path.exists(path):
# 	# 	with open(path, "r") as excel:
# 	# 		data = excel.read()
# 	# 	response = HttpResponse(data,content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
# 	# 	response['Content-Disposition'] = 'attachment; filename=%s_output.csv' 
# 	# 	return response
# 	# else:
# 	return HttpResponse("success")


# def download(request):
# 	import csv
# 	response = HttpResponse(content_type='text/csv')
# 	response['Content-Disposition'] = 'attachment; filename="somefilename.csv"'
# 	writer = csv.writer(response)
# 	writer.writerow(['First row', 'Foo', 'Bar', 'Baz'])
# 	writer.writerow(['Second row', 'A', 'B', 'C', '"Testing"', "Here's a quote"])
# 	return response

# def send_invite(request):
# 	email=request.POST.get('email','')
# 	company=request.POST.get('company','')
# 	username=request.POST.get('uname','')
# 	if(request.method=="POST"):
# 		user = User.objects.create_user(username=username,email=email)
# 		user.is_active=False
# 		user.save()
# 		em= email+company
# 		ran=hashlib.sha256(str(random.random())+str(em)).hexdigest()
# 		print(ran)
# 		ip=get_client_ip(request)
# 		a=activate_invite(email=email,company=company,hashed=ran,ip_addr=ip,expired=False)
# 		a.save()
# 		mailed(email,ran,company,request)
# 	return render(request,'send_invite.html')


# def mailed(email,code,company,request):
# 	subject = 'Invitation from Brand Protection'
# 	message = 'Please Verify.\n Code is http://'+str(host_get_name(request))+'/'+'verify_invite?token='+code+'&email='+email+'&company='+company
# 	from_email = EMAIL_HOST_USER
# 	to_list = [email,EMAIL_HOST_USER]
# 	send_mail(subject,message,from_email,to_list,fail_silently=False)

# def verify_invite(request):
# 	msg=""
# 	if request.user.is_authenticated():
# 		return HttpResponseRedirect('/dashboard')
# 	tok=request.GET.get('token','')
# 	email=request.GET.get('email','')
# 	company=request.GET.get('company','')
# 	if(tok=='' and email ==''):
# 			#return HttpResponseRedirect('login')
# 			return HttpResponse("nottt")
# 	else:
# 		try:
# 			print("inside tru")
# 			a=activate_invite.objects.get(hashed=tok)
# 			print a.email+ " "+email
# 			if(a.email==email):
# 				print(email)
# 				activate_user=User.objects.get(email=email)
# 				activate_user.is_active=True
# 				activate_user.save()
# 				a.expired=True
# 				a.save()
# 				user_info=userinfo.objects.get_or_create(user=activate_user,company=company)
# 				msg="""

# <h1 class="bb-center">Congrats!!</h1>
#                     <h5 class="bb-center">Your account has been activated, Please <a href="login">Login</a></h5>
# 				"""

# 		except Exception, e:
# 			print(e)
# 			msg="<font color='red'>Invalid Token</font>"
# 	context={
# 	"msg":msg,
# 	}
# 	return HttpResponse(msg)
	



# def getLink(request):
# 	fname=request.POST.get('fname','')
# 	lname=request.POST.get('lname','')
# 	pass1=request.POST.get('pass1','')
# 	pass2=request.POST.get('pass2','')
# 	domain=request.POST.get('domain','')
# 	keywords=request.POST.get('keyword','')
# 	username=request.POST.get('uname','')
# 	q=Queue.objects.all()
# 	print(q)
# 	if (request.method == "POST"):
# 		user=User.objects.get(username=uname)
# 		#password=pass1,first_name=fname,last_name=lname
# 		user.first_name=fname
# 		user=last_name=lname
# 		user.password=pass1
# 		user.save()
# 		#return render(request,'login.html')
# 		return HttpResponseRedirect('/login')	

# 	return render(request,'org_admin.html')
