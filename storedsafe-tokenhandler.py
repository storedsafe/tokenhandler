#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
when          who                     why             what
20171005      fredrik@storedsafe.com  added timeout and permissions check
20170601      norin@storedsafe.com    login/refresh   Created

This is small script to login and aquire a token used for subsequent REST API calls.
It can also be used to keep a token alive, by schedule a '--check' regulary (e.g. cron(1)).

It is built for version 1.0 of StoredSafes REST-Like API.
Dependencies below in the "import" statements.
"""

import getpass
import httplib
import ssl
import json
import getopt
import sys
import re
import os.path
import stat
import syslog
from os.path import expanduser

__author__     = "Peter Norin"
__copyright__  = "Copyright 2017, AB StoredSafe"
__license__    = "GPL"
__version__    = "1.0.2"
__maintainer__ = "Peter Norin"
__email__      = "norin@storedsafe.com"
__status__     = "Production"

homeDir = expanduser("~")
os.umask(0066)

def main():
	checkDir(homeDir)
	try:
		opts, args = getopt.getopt(sys.argv[1:], "lco", ["login", "logout", "check", "help"] )
	except getopt.GetoptError as err:
		print(err)
		usage()
		sys.exit(2)
	if opts:
		pass
	else:
		usage()
		sys.exit(2)
	for o, a in opts:
		if o in ("-l", "--login"):
			login()
			break
		if o in ("-o", "--logout"):
			logout()
			break
		elif o in ("-h", "--help"):
			usage()
			sys.exit()
		elif o in ("-c", "--check"):
			check()
			break
		else:
			assert False, "unhandled option"

def usage():
	print("Usage: %s [-loc]" % sys.argv[0])
	print " --login (or -l)	To login to the StoredSafe appliance"
	print " --logout (or -o)	To logout from the StoredSafe appliance"
	print " --check (or -c)	To check/refresh already obtained token\n"
	print "All actions require that you firstly authenticate in order to obtain a token."
	print "Once you have a token you can use it to authenticate new REST operations.\n"
	print "Authentication information is saved to ~/.storedsafe-client.rc, be sure to protect it properly."

def login():
	if os.path.isfile(homeDir + '/.storedsafe-client.rc'):
		checkRC(homeDir + '/.storedsafe-client.rc')
		file_ = open(homeDir + '/.storedsafe-client.rc', 'r')
		for line in file_:
			if "username" in line:
				line = re.sub('username:([a-zA-Z0-9]+)\n$', r'\1', line)
				answer = str(raw_input("Username is set to \"" + line + "\", do you want to keep it? (<Y>/n): "))
				if answer == ('n' or 'N'):
					userName = str(raw_input('Enter Username: '))
				else:
					userName = line
			if "mysite" in line:
				line = re.sub('mysite:([a-zA-Z0-9.]+)\n$', r'\1', line)
				answer = str(raw_input("Site is set to \"" + line + "\", do you want to keep it? (<Y>/n): "))
				if answer == ('n' or 'N'):
					mysite = str(raw_input('Enter Site (storedsafe.example.com): '))
				else:
					mysite = line
			if "apikey" in line:
				line = re.sub('apikey:([a-zA-Z0-9]+)\n$', r'\1', line)
				answer = str(raw_input("Apikey is set to \"" + line + "\", do you want to keep it? (<Y>/n): "))
				if answer == ('n' or 'N'):
					apiKey = str(raw_input('Enter Apikey: '))
				else:
					apiKey = line
		file_.close()
	else:
		userName = str(raw_input("Enter Username: "))
		apiKey = str(raw_input("Enter Apikey: "))
		mysite = str(raw_input("Enter Site (storedsafe.example.com): "))

	passWord = getpass.getpass('Enter Password: ')
	otp = getpass.getpass('Press Yubikey: ')

	try:
		loginJson = {
			'username':userName,
			'keys':passWord + apiKey + otp
		}
		c = httplib.HTTPSConnection(mysite, context=ssl._create_unverified_context())
		c.request("POST", "/api/1.0/auth", json.dumps(loginJson))
	except:
		print("No connection to \"%s\". Check network connectivity." % mysite)
		sys.exit()

	response = c.getresponse()
	print response.status, response.reason
	data = response.read()
	jsonObject = json.loads(data)
	if jsonObject["CALLINFO"]["status"] == 'SUCCESS':
		print "Login succeeded, please remember to log out when done."
		with open(homeDir + '/.storedsafe-client.rc', 'w') as file_:
			file_.write('token:' + jsonObject["CALLINFO"]["token"] + '\n')
			file_.write('username:' + userName + '\n')
			file_.write('apikey:' + apiKey + '\n')
			file_.write('mysite:' + mysite + '\n')
			file_.close()
	else:
		print "Login failed."
		sys.exit()

def checktoken():
	if os.path.isfile(homeDir + '/.storedsafe-client.rc'):
		pass
	else:
		print "You need to log on first."
		sys.exit()
	checkRC(homeDir + '/.storedsafe-client.rc')
	file_ = open(homeDir + '/.storedsafe-client.rc', 'r')
	for line in file_:
		if "token" in line:
			token = re.sub('token:([a-zA-Z0-9]+)\n$', r'\1', line)
			if token == 'none':
				syslog.syslog(syslog.LOG_ERR, 'ERROR: StoredSafe Token Handler not logged in.')
				print "Not logged in."
				sys.exit()
			return token
	file_.close()

def cleartoken():
	checkRC(homeDir + '/.storedsafe-client.rc')
	with open(homeDir + '/.storedsafe-client.rc', 'r') as file_:
		for line in file_:
			if "username" in line:
				userName = re.sub('username:([a-zA-Z0-9]+)\n$', r'\1', line)
			if "apikey" in line:
				apiKey = re.sub('apikey:([a-zA-Z0-9]+)\n$', r'\1', line)
			if "mysite" in line:
				mysite = re.sub('mysite:([a-zA-Z0-9.]+)\n$', r'\1', line)
		file_.close()
	with open(homeDir + '/.storedsafe-client.rc', 'w') as file_:
		file_.write('apikey:' + apiKey + '\n')
		file_.write('mysite:' + mysite + '\n')
		file_.write('username:' + userName + '\n')
		file_.write('token:none' + '\n')
		file_.close()

def checksite():
	if os.path.isfile(homeDir + '/.storedsafe-client.rc'):
		pass
	else:
		print "You need to log on first."
		sys.exit()
	checkRC(homeDir + '/.storedsafe-client.rc')
	file_ = open(homeDir + '/.storedsafe-client.rc', 'r')
	for line in file_:
		if "mysite" in line:
			mysite = re.sub('mysite:([a-zA-Z0-9.]+)\n$', r'\1', line)
			if mysite == 'none':
				print "Not logged in."
				sys.exit()
			return mysite
	file_.close()

def logout():
	token = checktoken()
	mysite = checksite()

	try:
		c = httplib.HTTPSConnection(mysite, context=ssl._create_unverified_context())
		c.request("GET", "/api/1.0/auth/logout?token=" + token)
	except:
		print("No connection to \"%s\". Check network connectivity." % mysite)
		sys.exit()

	response = c.getresponse()
	data = response.read()
	jsonObject = json.loads(data)
	if jsonObject["CALLINFO"]["status"] == 'SUCCESS':
		print "Logout successful."
		cleartoken()
	else:
		print "Login has expired."
		cleartoken()
		sys.exit()

def check():
	token = checktoken()
	mysite = checksite()

	try:
		checkJson = { 'token':token }
		c = httplib.HTTPSConnection(mysite, context=ssl._create_unverified_context())
		c.request("POST", "/api/1.0/auth/check", json.dumps(checkJson))
	except:
		print("No connection to \"%s\". Check network connectivity." % mysite)
		sys.exit()

	response = c.getresponse()
	print response.status, response.reason
	data = response.read()
	jsonObject = json.loads(data)
	if jsonObject["CALLINFO"]["status"] == 'SUCCESS':
		pass
	else:
		syslog.syslog(syslog.LOG_ERR, 'ERROR: StoredSafe Token Handler not logged in.')
		print "Not logged in."
		cleartoken()
		sys.exit()

def checkDir(p):
	if os.path.isdir(p):
		st = os.stat(p)
		if ((bool(st.st_mode & stat.S_IROTH)) or \
			(bool(st.st_mode & stat.S_IWOTH)) or\
			(bool(st.st_mode & stat.S_IWGRP))):
			print("Insecure permissions on home directory \"%s\". Exiting." % p)
			sys.exit()
	else:
		print("\"%s\" is not a file." % p)
		sys.exit()

def checkRC(p):
	if os.path.isfile(p):
		st = os.stat(p)
		if ((bool(st.st_mode & stat.S_IROTH)) or \
			(bool(st.st_mode & stat.S_IWOTH)) or \
			(bool(st.st_mode & stat.S_IRGRP)) or \
			(bool(st.st_mode & stat.S_IWGRP))):
			print("Insecure permissions on the rc file \"%s\". Exiting." % p)
			sys.exit()
	else:
		print("\"%s\" is not a file." % p)
		sys.exit()

if __name__ == '__main__':
    main()
