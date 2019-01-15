#! python3
'''
Author: Arjun Bhardwaj
Purpose:
		This is a simple program that can enable a user to do the following at the moment:
			1. Look up any string or a hash in their local repository of PDF files
			2. Look up that hash on virus total and quickly get the results 
			
		Some random Hash values to test the code:
			e5fe9d3dd274d76fed1b9ae3f3ff83a46146771e
			7657fcb7d772448a6d8504e4b20168b8
		This program will be called from a .BAT file which will remove the need to manually run the code by opening command prompt	
'''
import os
import sys
import json
import PyPDF2
import requests
## os.walk function provides three values, the folder name, the sub folders in that folder name and the file names in the foldername.
## To access the contents you have to run a for loop as shown below
def localHashCheck(uservalue):
	counter = 0
	#Enter the folder name where your reports are kept in the os.walk paramater.
	for foldername, subfolders, filenames in os.walk('S:\\My_Scipts\\Hash_Check_python\\reports'): 
		print('------------------------------------------------------------------')
		print('Directory structure of the local Intel Repository')
		print('Folder Path '+ foldername)
		if subfolders:
			print('The Subfolders in the '+ foldername + 'are: ' + ','.join(subfolders))
		if not filenames:
			print('No reports in the folder to look into')
			continue
		print('The reports in the '+ foldername + ' are: ' + ','.join(filenames))
		print('------------------------------------------------------------------\n')
		for file in filenames: #loop to open each file in the the filename variable
			pdffile=open(file, 'rb')
			reader = PyPDF2.PdfFileReader(pdffile)
			for pagenumber in range(reader.numPages):
				extractedData = reader.getPage(pagenumber).extractText()
				if uservalue in extractedData:
					print ('###################################################################')
					print ("found value on page number "+ str(pagenumber) +" of document " + file)
					print ('###################################################################\n')
					counter = 1
			pdffile.close()
	if counter == 0:
				print('Hash information not available in local documents')		

def jsonOutput(jsonData, sort=True, indents=4):
		os.chdir('S:\\My_Scipts\\Hash_Check_python\\Output')
		if type(jsonData) is str:
			file = open('output.json','w')
			file.write(json.dumps(json.loads(jsonData), sort_keys=sort, indent=indents))
			file.close()
		else:
			file = open('output.json','w')
			file.write(json.dumps(jsonData, sort_keys=sort, indent=indents))
			file.close()
			return None
			
def virusTotalCheck(uservalue):
	user_api_key = '84783793d082d8ea1751e904c8b404e29ef8c54ec6677717275900c39910f82e'
	user_hash = uservalue
	params = {
    'apikey': user_api_key,
    'resource': user_hash 
		}
	try:
		response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
	except:
		print('API connection issue')
	jsonData = response.json()
	response = int(jsonData.get('response_code'))
	if response == 0:
		print ('###################################################################')
		print (user_hash + ' is not in Virus Total')
		print ('###################################################################\n')
	elif response == 1:
		positiveHits = int(jsonData.get('positives'))
		if positiveHits == 0:
			print ('###################################################################')
			print (user_hash + ' is not malicious')
			print ('###################################################################\n')
		else:
			print ('###################################################################')
			print (user_hash + ' is malicious. Hit Count:' + str(positiveHits))
			print ('Detailed output provided in json file')
			print ('###################################################################\n')
			jsonOutput(jsonData)
	else:
		print ('hash could not be searched. Please try again later.')
	

def main():
	os.chdir('S:\\My_Scipts\\Hash_Check_python\\reports')	
	print("enter the Hash value you want to search for in the reports directory")
	uservalue = str(input())
	print('\n*******************************************************************\n')
	print('Please select from the following: ')
	print('\t 1. search in your local repository')
	print('\t 2. search VirusTotal')
	print('\t 3. Exit\n')
	print('*******************************************************************\n')
	userChoice=str(input())
	print()
	if userChoice in ['1','one','One','first','First']:
		localHashCheck(uservalue)
	elif userChoice in ['2','two','Two','second','Second']:
		virusTotalCheck(uservalue)
	elif userChoice in ['3','three','Three','third','Third']:
		exit()
	else: print('Invalid option')
		
main()		