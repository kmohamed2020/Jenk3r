from prettytable import PrettyTable
import requests
from textwrap import wrap
from pathlib import Path
import html
import os 


class bcolors: #Class for having the codes of each color to be used while printing output on console in collored manner
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'

# Function to print Error Messages, just change the color of the message to be RED.
def printError(error):
	print(bcolors.FAIL+str(error)+bcolors.ENDC)
	pass

def printLine(error):
	print(bcolors.OKBLUE+str(error)+bcolors.ENDC)
	pass

# Function to print Normal Messages, just change the color of the message to be GREEN.
def printMessage(message):
	print(bcolors.OKGREEN+str(message)+bcolors.ENDC)
	pass

# Function to change the Color of string to be GREEN.
def greenMessage(message):
	newMsg = (bcolors.OKGREEN+str(message)+bcolors.ENDC)
	return newMsg

# Function to change the Color of string to be Yellow.
def yellowMessage(message):
	newMsg = (bcolors.WARNING+str(message)+bcolors.ENDC)
	return newMsg

# Function to change the Color of string to be RED.
def redMessage(message):
	newMsg = (bcolors.FAIL+str(message)+bcolors.ENDC)
	return newMsg

# Function to print Warning Messages, just change the color of the message to be Yellow.
def printWarning(warning):
	print(bcolors.WARNING+str(warning)+bcolors.ENDC)
	pass

class Jenk3r:
	"""docstring for Jenk3r"""
	def __init__(self, Url, path=""):
		self.IPAddress = Url.split("/")[2].split(":")[0] # IP Address of the Jenkins instance.
		self.Port = Url.split("/")[2].split(":")[1] # Port of the Jenkins instance.
		#self.url = "http://"+str(IPAddress)+":"+str(Port) # URL of the Jenkins instance.
		self.url = Url
		self.Username = None
		self.Password = None
		self.Authenticated = 0 # Flag to indicate if users creds will be used or not. (Provided by User or Later by BruteForcing).
		self.UsersDetails = [] # List to contain Users details as list per user ['Full name','Username','assigned project'].
		self.UsersDetailsDone = 0 # Flag to indicate that the Users Enumeration is done or not.
		self.statusCode = 0 # Flag to indicate that the online status check is done or not.
		self.SysInfo = []
		self.Jobs = []
		self.JobsDetailsDone = 0 # Flag to indicate that the Users Enumeration is done or not.
		self.RCE = -1 # Flag to indicate if Remote Code Execution is available on that Jenkins instance.
		self.debug = 0
		self.usersTable = None
		self.jobsTable = None
		self.RCETable = None
		self.dirPath = path+self.IPAddress
	
	def setCreds(self,Username,Password):
		self.Username = Username
		self.Password = Password
		self.Authenticated = 1

	# Function to get the Users from Jenkins (Currently) with Anonymous access.
	def getUsers(self):
		# Declaring Empty list to contain the users details.
		usersDetails = []
		webRequest = ""
		# The Case of this Jenkin instance's online status is not checked yet.
		if self.statusCode == 0:
			printWarning("\n[+] It seems that this Jenkins instance connction status is not verified.")
			# Checking this Jenkins instance online status. 
			self.checkStatus()
			# Calling the same function for continue working again (recursion).
			self.getUsers()
		# The Case of this Jenkins instance require Authenitcation, and the Users Enumeration process will not be done, and empty list is returned.
		elif self.statusCode == 403 and self.Authenticated == 0:
			printError("\n[+] This Jenkins Instance require Authentication and Credenials is not availble.")
			# return Empty list
			return usersDetails
		elif self.debug == 1:
			printMessage("\n[+] Getting users details, please be patient.")
		
		try:# The case of Anonymous requests
			if self.Authenticated == 0:
				webRequest = requests.get(self.url+"/asynchPeople/api/json", timeout=5)
			else:# The case of using Credenials while sending requests
				webRequest = requests.get(self.url+"/asynchPeople/api/json", timeout=5, auth=(self.Username, self.Password))
				pass
			# Assign the web request's response in Json format to a variable
			dic = webRequest.json()
			# Extracting the users dictionary from the whole returned dictionary
			users = dic['users']
			#Looping on users dictionary
			for user in users:
				# Variable to contain the full name of the user
				fullName = user['user']['fullName']
				# Variable to contain the username of the user
				username = user['user']['absoluteUrl'].split("/")[4]
				# Check if the user has assigned to any Project
				if user['project'] is None: #The case of no project for that user
					project = "None"
				else: # The case of having project assign to that user
					project = user['project']['name']
				# List to contain all user details [fullname, username, projectname]
				usersDetails.append([fullName, username, project])
			# Indicates that the operation of User Enumeration has been done successfully.
			self.UsersDetailsDone = 1
		except Exception as e: # The Case of error while sending request
			printError("[+] Connection Error while getting Users details.")
			# Indicates that the operation of User Enumeration has been failed.
			self.UsersDetailsDone = -1
		# Assign the Object's userDetails list with the result list of the function
		self.UsersDetails = usersDetails
		# Return the list of the users details
		return usersDetails
	
	#Function to check the status of the target URL by sending a web request and checking the status code of the response,
	def checkStatus(self): # debug variable to set to 1 for getting verbos output, and by default set to 0
		if self.debug == 1:# If debug set to 1, printing message
			printMessage("Checking this URL: "+self.url)

		#Using Try/Except for sending the web request to the victim
		try:
			#send web request to the target URL with timeout 5 seconds
			webRequest = requests.get(self.url, timeout=5)
			#Getting the status code from the response
			statusCode = webRequest.status_code
			#Assign the status code from the response to the object variable
			self.statusCode =  statusCode
			if self.debug == 1:# If debug set to 1, printing debuging info
				if str(self.statusCode) == "200":
					printMessage("[+]"+self.IPAddress+" is alive!")
					self.print()
				elif str(self.statusCode) == "403":
					printWarning("[+]"+self.IPAddress+" is alive!, but require Authentication")
				else:
					printWarning("[+]"+self.IPAddress+" is not alive! and Status Code : "+str(self.statusCode))
				printLine("\t\t##########################################################")
		except Exception as e:# If web request failed
			if self.debug == 1:# If debug set to 1, printing message
				printError("Could not connect!")
			#Set the status code variable in the object to 404, just to indicate that it's not connected.
			self.statusCode = 404

	# Function to print users summary, just the number of Enumerated users, but it checks also that the Users Enumeration process is already done.	
	def printUsersSummary(self):
		# The Case of the User Enumeration is already done, the number of the enumerated users is greater than 0 , and also the status code of this jenkins instance is 200 (Open Authentication)
		if self.UsersDetailsDone == 1 and len(self.UsersDetails) == 0 and self.statusCode == 200:
			printError("\n[+] This Jenkins instance has no users to be printed")
			return -1
		# The Case of the number of the enumerated users is not 0, and also this jenkins instance is requiring authentication.
		elif len(self.UsersDetails) == 0 and self.statusCode == 403:
			printError("\n[+] This Jenkins Instance required Authentication and Credenials was not availble.")
			return -1 # In cases needed while debuging the code
		# The Case of this jenkins instance's status code is not checked.
		elif self.statusCode == 0:
			printWarning("\n[+] It seems that this Jenkins instance connction status is not verified.")
			# Checking this Jenkins instance online status. 
			self.checkStatus()
			# Calling the same function again to continue after checking the status (recuersion)
			self.printUsersSummary()
			return 1 # In cases needed while debuging the code
		# The Case of User Enumeration process is not done and this Jenkins instance has Open Authentication
		elif self.UsersDetailsDone == 0 and len(self.UsersDetails) == 0 and self.statusCode == 200:
			printWarning("\n[+] It seems that this Jenkins instance's users are not enumerated, Enumerating Now, Please be patient.")
			# Enumerating users for this Jenkins instance. 
			self.getUsers()
			# Calling the same function again to continue after checking the status (recuersion)
			self.printUsersSummary()
			return 1 # In cases needed while debuging the code
		# The Case of User Enumeration Failed.
		elif self.UsersDetailsDone == -1 and len(self.UsersDetails) == 0 and self.statusCode == 200:
			printError("\n[+] This Jenkins Instance User Enumeration Failed.")
			return -1 # In cases needed while debuging the code
		printMessage("\n[+] This Jenkins Instance has "+str(len(self.UsersDetails))+ " users.")
		return 1 # In cases needed while debuging the code

	def printUsersDetails(self,  html = 0):
		# The Case of the User Enumeration is already done, the number of the enumerated users is greater than 0 , and also the status code of this jenkins instance is 200 (Open Authentication)
		if self.UsersDetailsDone == 1 and len(self.UsersDetails) == 0 and self.statusCode == 200:
			printError("\n[+] This Jenkins instance has no users to be printed")
			return -1 # In cases needed while debuging the code
		# The Case of the number of the enumerated users is not 0, and also this jenkins instance is requiring authentication.
		elif len(self.UsersDetails) == 0 and self.statusCode == 403:
			printError("\n[+] This Jenkins Instance required Authentication and Credenials was not availble.")
			return -1 # In cases needed while debuging the code
		# The Case of this jenkins instance's status code is not checked.
		elif self.statusCode == 0:
			printWarning("\n[+] It seems that this Jenkins instance connction status is not verified.")
			# Checking this Jenkins instance online status. 
			self.checkStatus()
			# Calling the same function again to continue after checking the status (recuersion)
			self.printUsersDetails()
			return 1 # In cases needed while debuging the code
		# The Case of User Enumeration process is not done and this Jenkins instance has Open Authentication
		elif self.UsersDetailsDone == 0 and len(self.UsersDetails) == 0 and self.statusCode == 200:
			printWarning("\n[+] It seems that this Jenkins instance's users are not enumerated, Enumerating Now, Please be patient.")
			# Enumerating users for this Jenkins instance. 
			self.getUsers()
			# Calling the same function again to continue after checking the status (recuersion)
			self.printUsersDetails()
			return 1 # In cases needed while debuging the code
		# The Case of User Enumeration Failed.
		elif self.UsersDetailsDone == -1 and len(self.UsersDetails) == 0 and self.statusCode == 200:
			printError("\n[+] This Jenkins Instance User Enumeration process Failed.")
			return -1 # In cases needed while debuging the code

		# Declare and define a PrettyTable object to be used while printing the users in table format
		table = PrettyTable()
		# Define users table columns
		table.field_names = ['#','Full Name', 'Username', 'Project']
		if html == 0:
			printMessage("\n[+] The details of Jenkins Instance users: ")
		counter = 1 # Counter variable just for showing number of records in the printed table
		# Loop on the Enumerated Users (USersDetails) list 
		for user in self.UsersDetails:
			# Add the Counter, the record numer in the table. No relation to the real data
			user.insert(0,str(counter))
			if html == 0:
				# Add new raw (User record) to the table.
				table.add_row(user)
			else:
				table.add_row([user[0],user[1],'<a href="'+self.url+'/user/'+user[2]+'">'+user[2]+'</a>',user[3]])
			# Increase the Counter by 1
			counter += 1
		self.usersTable = table
		if html == 0:
			# Print the table on the Terminal
			print(table)
		return 1 # In cases needed while debuging the code

	def getJobs(self):
		# Declaring Empty list to contain the users details.
		Jobs = []
		webRequest = ""
		# The Case of this Jenkin instance's online status is not checked yet.
		if self.statusCode == 0:
			printWarning("\n[+] It seems that this Jenkins instance connction status is not verified.")
			# Checking this Jenkins instance online status. 
			self.checkStatus()
			# Calling the same function for continue working again (recursion).
			self.getJobs()
		# The Case of this Jenkins instance require Authenitcation, and the Jobs Enumeration process will not be done, and empty list is returned.
		elif self.statusCode == 403 and self.Authenticated == 0:
			printError("\n[+] This Jenkins Instance require Authentication and Credenials is not availble.")
			# return Empty list
			return Jobs
		elif self.debug == 1:
			printMessage("\n[+] Getting Jobs details, please be patient.")
		
		try:# The case of Anonymous requests
			if self.Authenticated == 0:
				webRequest = requests.get(self.url+"/api/json?tree=jobs[name]", timeout=5)
			else:# The case of using Credenials while sending requests
				webRequest = requests.get(self.url+"/api/json?tree=jobs[name]", timeout=5, auth=(self.Username, self.Password))
			# Assign the web request's response in Json format to a variable
			dic = webRequest.json()
			# Extracting the Jobs dictionary from the whole returned dictionary
			jobs = dic['jobs']
			#Looping on Jobs dictionary
			for job in jobs:
				jobName = job['name']
				#printWarning("[+] Working on Job :"+jobName)
				URL = self.url+"/job/"+jobName+"/api/json"
				if self.Authenticated == 0:
					request = requests.get(URL, timeout=5)
				else:
					request = requests.get(URL, timeout=5, auth=(self.Username, self.Password))
				jobDetailsJson = request.json()
				description = jobDetailsJson['description']
				jobUrl =  jobDetailsJson['url']
				jobUrlSplit = jobUrl.split("/")
				jobUrl = self.url+"/"+jobUrlSplit[3]+"/"+jobUrlSplit[4]
				Jobs.append([jobName, description, jobUrl])
			self.JobsDetailsDone = 1
		except Exception as e: # The Case of error while sending request
			printError("[+] Connection Error While getting Jobs details.")
			self.JobsDetailsDone = -1
		# Assign the Object's Jobs list with the result list of the function
		self.Jobs = Jobs
		# Return the list of the Jobs details
		return Jobs

	def printJobsDetails(self,  html = 0):
		# The Case of the User Enumeration is already done, the number of the enumerated jobs is greater than 0 , and also the status code of this jenkins instance is 200 (Open Authentication)
		if self.JobsDetailsDone == 1 and len(self.Jobs) == 0 and self.statusCode == 200:
			printError("\n[+] This Jenkins instance has no jobs to be printed")
			return -1 # In cases needed while debuging the code
		# The Case of the number of the enumerated jobs is not 0, and also this jenkins instance is requiring authentication.
		elif len(self.Jobs) == 0 and self.statusCode == 403:
			printError("\n[+] This Jenkins Instance required Authentication and Credenials was not availble.")
			return -1 # In cases needed while debuging the code
		# The Case of this jenkins instance's status code is not checked.
		elif self.statusCode == 0:
			printWarning("\n[+] It seems that this Jenkins instance connction status is not verified.")
			# Checking this Jenkins instance online status. 
			self.checkStatus()
			# Calling the same function again to continue after checking the status (recuersion)
			self.printJobsDetails()
			return 1 # In cases needed while debuging the code
		# The Case of Jobs Enumeration process is not done and this Jenkins instance has Open Authentication
		elif self.JobsDetailsDone == 0 and len(self.Jobs) == 0 and self.statusCode == 200:
			printWarning("\n[+] It seems that this Jenkins instance's jobs are not enumerated, Enumerating Now, Please be patient.")
			# Enumerating jobs for this Jenkins instance. 
			self.getJobs()
			# Calling the same function again to continue after checking the status (recuersion)
			self.printJobsDetails()
			return 1 # In cases needed while debuging the code
		# The Case of Jobs Enumeration Failed
		elif self.JobsDetailsDone == -1 and len(self.Jobs) == 0 and self.statusCode == 200:
			printError("\n[+] The Job Enumeration process Failed.")
			return -1 # In cases needed while debuging the code
		# Declare and define a PrettyTable object to be used while printing the jobs in table format
		table = PrettyTable()
		# Define jobs table columns
		table.field_names = ["#", "Job name", "Description", "URL"]
		if html == 0:
			printMessage("\n[+] The details of Jenkins Instance Jobs: ")
		counter = 1 # Counter variable just for showing number of records in the printed table
		# Loop on the Enumerated Jobs (Jobs) list 
		for job in self.Jobs:
			# Add the Counter, the record numer in the table. No relation to the real data
			job.insert(0,str(counter))
			# Add new raw (User record) to the table.
			if job[2] is not None and len(job[2]) > 70 and html == 0:
				descriptionSub = wrap(job[2] or '', 70) or ['']
				table.add_row([job[0],job[1],descriptionSub[0],job[3]])
				for sub in descriptionSub[1:]:
					table.add_row(['','',sub,''])
			elif html == 1:
				table.add_row([job[0],job[1],job[2],'<a href="'+job[3]+'">'+job[3]+'</a>'])
			else:
				table.add_row(job)
			# Increase the Counter by 1
			counter += 1
		self.jobsTable = table
		if html == 0:
			# Print the table on the Terminal
			print(table)
			
		return 1 # In cases needed while debuging the code

	# Function to print jobs summary, just the number of Enumerated jobs, but it checks also that the Jobs Enumeration process is already done.	
	def printJobsSummary(self):
		# The Case of the Job Enumeration is already done, the number of the enumerated jobs is greater than 0 , and also the status code of this jenkins instance is 200 (Open Authentication)
		if self.JobsDetailsDone == 1 and len(self.Jobs) == 0 and self.statusCode == 200:
			printError("\n[+] This Jenkins instance has no jobs to be printed")
			return -1
		# The Case of the number of the enumerated jobs is not 0, and also this jenkins instance is requiring authentication.
		elif len(self.Jobs) == 0 and self.statusCode == 403:
			printError("\n[+] This Jenkins Instance required Authentication and Credenials was not availble.")
			return -1 # In cases needed while debuging the code
		# The Case of this jenkins instance's status code is not checked.
		elif self.statusCode == 0:
			printWarning("\n[+] It seems that this Jenkins instance connction status is not verified.")
			# Checking this Jenkins instance online status. 
			self.checkStatus()
			# Calling the same function again to continue after checking the status (recuersion)
			self.printJobsSummary()
			return 1 # In cases needed while debuging the code
		# The Case of Job Enumeration process is not done and this Jenkins instance has Open Authentication
		elif self.JobsDetailsDone == 0 and len(self.Jobs) == 0 and self.statusCode == 200:
			printWarning("\n[+] It seems that this Jenkins instance's jobs are not enumerated, Enumerating Now, Please be patient.")
			# Enumerating users for this Jenkins instance. 
			self.getJobs()
			# Calling the same function again to continue after checking the status (recuersion)
			self.printJobsSummary()
			return 1 # In cases needed while debuging the code
		# The Case of Job Enumeration process Failed.
		elif self.JobsDetailsDone == -1 and len(self.Jobs) == 0 and self.statusCode == 200:
			printError("\n[+] This Jop Enumeration process Failed.")
			return -1 # In cases needed while debuging the code
		printMessage("\n[+] This Jenkins Instance has "+str(len(self.Jobs))+ " jobs.")
		return 1 # In cases needed while debuging the code

	def checkRCE(self):
		rceURL = self.url+"/script"
		if self.debug == 1:# If debug set to 1, printing message
			printMessage("Checking RCE on this URL: "+rceURL)

		#Using Try/Except for sending the web request to the victim
		try:
			#send web request to the target URL with timeout 5 seconds
			webRequest = requests.get(rceURL, timeout=5)
			#Getting the status code from the response
			statusCode = webRequest.status_code
			

			if statusCode == 200:
				#Assign the status code from the response to the object variable
				self.RCE =  1
			elif statusCode == 403:
				self.RCE =  -1

			if self.debug == 1:# If debug set to 1, printing debuging info
				if str(statusCode) == "200":
					printMessage("[+]"+self.url+" has RCE!")
				elif str(self.statusCode) == "403":
					printWarning("[+]"+self.url+" is alive!, but has no RCE.")
				else:
					printWarning("[+]"+self.IPAddress+" is not alive! and Status Code : "+str(statusCode))
				printLine("\t\t##########################################################")
		except Exception as e:# If web request failed
			printError("[+] Connection Error while checking RCE.")
			#Set the status code variable in the object to 404, just to indicate that it's not connected.
			self.RCE = -2

	def printRCEStatus(self, html = 0):
		if self.RCE == 1:
			# This Jenkins instance is live and has RCE
			if html == 0:
				printMessage("[+] This Jenkins instance has RCE! with Open Authentication.")
			table = PrettyTable()
			table.field_names = ['RCE','URL']
			table.add_row(["Yes" , '<a href="'+self.url+'/script'+'">'+"Click Here!"+'</a>'])
			self.RCETable = table
		elif self.RCE == 0:
			# This Jenkins instance's RCE was not checked
			if html == 0:
				printWarning("[+] This Jenkins instance RCE is not checked!")
			self.checkRCE()
			self.printRCEStatus()
		elif self.RCE == -1:
			# This Jenkins instance is live but has no RCE
			if html == 0:
				printWarning("[+] This Jenkins instance has no RCE with Open Authentication")
		else:
			# This Jenkins instance is not alive!
			if html == 0:
				printError("[+] This Jenkins instanceis not alive!")
			pass

	def getRCEStatus(self, html = 0):
		result = None
		if self.RCE == 0:
			# This Jenkins instance's RCE was not checked
			if html == 0:
				printWarning("[+] This Jenkins instance RCE is not checked!")
			self.checkRCE()
			self.getRCEStatus()
		else:
			# return the RCE status of this Jenkins instance
			return self.RCE

	def getSummary(self):
		detailsSummary = {
		'RCE': self.RCE,
		'users': self.UsersDetails,
		'usersEnum': self.UsersDetailsDone,
		'jobs': self.Jobs,
		'jobsEnum': self.JobsDetailsDone,
		'statusCode': self.statusCode,
		'url': self.url
		}
		return detailsSummary

	def writeUsersHTMLFile(self):
		self.printUsersDetails(html = 1)
		if len(self.UsersDetails) > 0:
			Html_file= open(self.dirPath+"/"+"Users.html","w")
			Html_file.write(html.unescape(self.usersTable.get_html_string(title="Users Enumeration",attributes={
            'border': 1,
            'style': 'border-width: 1px; border-collapse: collapse;'
        })))
			Html_file.close()
	
	def writeJobsHTMLFile(self):
		self.printJobsDetails(html = 1)
		if len(self.Jobs) > 0:
			Html_file= open(self.dirPath+"/"+"Jobs.html","w")
			Html_file.write(html.unescape(self.jobsTable.get_html_string(title="Jobs Enumeration",attributes={
            'border': 1,
            'style': 'border-width: 1px; border-collapse: collapse; align: center;'
        })))
			Html_file.close()

	def writeRCEHTMLFile(self):
		rce = self.printRCEStatus(html = 1)
		if self.RCETable is not None and self.RCE == 1:
			Html_file= open(self.dirPath+"/"+"RCE.html","w")
			Html_file.write(html.unescape(self.RCETable.get_html_string(title="RCE Details",attributes={
            'border': 1,
            'style': 'border-width: 1px; border-collapse: collapse; align: center;'
        })))
			Html_file.close()

	def setResultPath(self, path):
		self.dirPath = path


	def writeSummaryHTMLFile(self):
		Path(self.dirPath).mkdir(parents=True, exist_ok=True)
		self.writeUsersHTMLFile()
		self.writeJobsHTMLFile()
		self.writeRCEHTMLFile()

	def asses(self):
		self.checkStatus()
		self.getUsers()
		self.getJobs()
		self.checkRCE()
		

def JenkinsInstancesAssess(URLs, writeResults = 0 , resultsFile = ""):
	if resultsFile is not None:
		Path(resultsFile).mkdir(parents=True, exist_ok=True)
		
	JenkinsInstances = []
	for URL in URLs:
		j = Jenk3r(URL)
		if writeResults == 1:
			j.setResultPath(path=resultsFile)

		JenkinsInstances.append(j)
	table = PrettyTable()
	table.field_names = ['#','URL', 'Users Enum', 'Projects Enum', 'RCE']

	tableHTML = PrettyTable()
	tableHTML.field_names = ['#','URL', 'Users Enum', 'Projects Enum', 'RCE']

	counter = 1
	for Jenkin in JenkinsInstances:
		printMessage("[+] Working on Jenkins Instance: "+ Jenkin.url)
		Jenkin.asses()
		result = Jenkin.getSummary().copy()
		url = result['url']
		RCE = None
		usersEnum = None
		jobsEnum = None

		if result['RCE'] == 1:
			RCE = "Yes!"
		else:
			RCE = "No"

		if result['usersEnum'] == 1 and len(result['users']) > 0:
			usersEnum = "Got Users!"
		elif result['usersEnum'] == 1 and len(result['users']) == 0:
			usersEnum = "No Users Found"
		else:
			usersEnum = "No"


		if result['jobsEnum'] == 1 and len(result['jobs']) > 0:
			jobsEnum = "Got Jobs!"
		elif result['jobsEnum'] == 1 and len(result['jobs']) == 0:
			jobsEnum = "No Jobs Found"
		else:
			jobsEnum = "No"

		table.add_row([counter, url, usersEnum, jobsEnum, RCE])
		if writeResults == 1:
			tableHTML.add_row([counter, '<a href="'+url+'">'+url+'</a>', '<a href="file://'+os.getcwd()+"/"+Jenkin.IPAddress+"/Users.html"+'">'+usersEnum+'</a>', '<a href="file://'+os.getcwd()+"/"+Jenkin.IPAddress+"/Jobs.html"+'">'+jobsEnum+'</a>', '<a href="file://'+os.getcwd()+"/"+Jenkin.IPAddress+"/RCE.html"+'">'+RCE+'</a>'])
		counter += 1

		if writeResults == 1:
			Jenkin.writeSummaryHTMLFile()
	print(table)

	Html_file= open("Summary.html","w")
	Html_file.write(html.unescape(tableHTML.get_html_string(attributes={
            'border': 1,
            'style': 'border-width: 1px; border-collapse: collapse; align: center;'
        })))
	Html_file.close()

	
		


def main():
	j = Jenk3r("http://192.168.1.101:8080")
	j.setCreds("Admin","P@ssw0rd")

	j.checkStatus()

	if j.statusCode != 404:
		j.getUsers()
		j.printUsersSummary()
		j.printUsersDetails()

		j.getJobs()
		j.printJobsSummary()
		j.printJobsDetails()



if __name__ == '__main__':
	main()


	




