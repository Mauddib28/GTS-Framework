#!/usr/bin/python

'''
 The purpose of this code is to download, decompress, and prepare for grabbing CVE information
   for a user passed CVE value

 Author:        Paul A. Wortman
 Last Edit:     6/9/2021 
'''

import json     # Import for working with json
import requests # Import for requesting data from websites
import sys      # Import for determining passed arguments
import re       # Import for using regex in python
import argparse # Import for easy help and usage message, issue error, and writing user-friendly command-line script
import xmltodict# Import for conversion of XML data to dictionary
import zipfile  # Import for unzipping files
import os       # Import for path functions

'''
 Globals
'''
# Debugging Variables
debug_bit = 0
# NVD Database names
nvdRecent="nvdcve-1.1-recent.json"
nvd2021="nvdcve-1.1-2021.json"
nvd2020="nvdcve-1.1-2020.json"
nvd2019="nvdcve-1.1-2019.json"
nvd2018="nvdcve-1.1-2018.json"
nvd2017="nvdcve-1.1-2017.json"
nvd2016="nvdcve-1.1-2016.json"
nvd2015="nvdcve-1.1-2015.json"
nvd2014="nvdcve-1.1-2014.json"
nvd2013="nvdcve-1.1-2013.json"
nvd2012="nvdcve-1.1-2012.json"
nvd2011="nvdcve-1.1-2011.json"
nvd2010="nvdcve-1.1-2010.json"
nvd2009="nvdcve-1.1-2009.json"
nvd2008="nvdcve-1.1-2008.json"
nvd2007="nvdcve-1.1-2007.json"
nvd2006="nvdcve-1.1-2006.json"
nvd2005="nvdcve-1.1-2005.json"
nvd2004="nvdcve-1.1-2004.json"
nvd2003="nvdcve-1.1-2003.json"
nvd2002="nvdcve-1.1-2002.json"
# Above redone as a dictionary
nvdDict = {
	"Recent": "nvdcve-1.1-recent.json",
	"2021": "nvdcve-1.1-2021.json",
	"2020": "nvdcve-1.1-2020.json",
	"2019": "nvdcve-1.1-2019.json",
	"2018": "nvdcve-1.1-2018.json",
	"2017": "nvdcve-1.1-2017.json",
	"2016": "nvdcve-1.1-2016.json",
	"2015": "nvdcve-1.1-2015.json",
	"2014": "nvdcve-1.1-2014.json",
	"2013": "nvdcve-1.1-2013.json",
	"2012": "nvdcve-1.1-2012.json",
	"2011": "nvdcve-1.1-2011.json",
	"2010": "nvdcve-1.1-2010.json",
	"2009": "nvdcve-1.1-2009.json",
	"2008": "nvdcve-1.1-2008.json",
	"2007": "nvdcve-1.1-2007.json",
	"2006": "nvdcve-1.1-2006.json",
	"2005": "nvdcve-1.1-2005.json",
	"2004": "nvdcve-1.1-2004.json",
	"2003": "nvdcve-1.1-2003.json",
	"2002": "nvdcve-1.1-2002.json"
}

'''
 Function definitions
'''

# Function to unzip a file
def dezipDatabase(dbSaveLoc, dbName, dezipLoc):
	# Path to file
	filePath = dbSaveLoc + dbName
	# Unzip contents
	with zipfile.ZipFile(filePath, 'r') as zip_ref:
		    zip_ref.extractall(dezipLoc)

# Function for grabbing database zip and saving it locally
def grabSaveDatabase(dbURL, dbSaveLoc, dbName):
	# Request info
	response = requests.get(dbURL)
	# Create save location
	saveLoc = dbSaveLoc + dbName
	# Write information to file
	with open(saveLoc, 'wb') as dbFile:
		    dbFile.write(response.content)

# Function for checking, pulling, and decompressing NVD Databases
#   Note: Eventually add only update of databaes that relate to specific year (e.g. passed year)
#   Nota Bene: The database zips ONLY go as far back as 2002
def updateDatabases(CVEPassed):
	# No use of CVEPassed yet
	## Local variables
	# List of URLs for various NVD databases
	url_nvdRecent="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip"
	url_nvd2021="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2021.json.zip"
	url_nvd2020="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020.json.zip"
	url_nvd2019="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2019.json.zip"
	url_nvd2018="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2018.json.zip"
	url_nvd2017="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2017.json.zip"
	url_nvd2016="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2016.json.zip"
	url_nvd2015="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2015.json.zip"
	url_nvd2014="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2014.json.zip"
	url_nvd2013="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2013.json.zip"
	url_nvd2012="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2012.json.zip"
	url_nvd2011="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2011.json.zip"
	url_nvd2010="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2010.json.zip"
	url_nvd2009="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2009.json.zip"
	url_nvd2008="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2008.json.zip"
	url_nvd2007="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2007.json.zip"
	url_nvd2006="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2006.json.zip"
	url_nvd2005="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2005.json.zip"
	url_nvd2004="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2004.json.zip"
	url_nvd2003="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2003.json.zip"
	url_nvd2002="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2002.json.zip"
	# List of filenames for saved database zips
	zip_nvdRecent="nvdcve-1.1-recent.json.zip"
	zip_nvd2021="nvdcve-1.1-2021.json.zip"
	zip_nvd2020="nvdcve-1.1-2020.json.zip"
	zip_nvd2019="nvdcve-1.1-2019.json.zip"
	zip_nvd2018="nvdcve-1.1-2018.json.zip"
	zip_nvd2017="nvdcve-1.1-2017.json.zip"
	zip_nvd2016="nvdcve-1.1-2016.json.zip"
	zip_nvd2015="nvdcve-1.1-2015.json.zip"
	zip_nvd2014="nvdcve-1.1-2014.json.zip"
	zip_nvd2013="nvdcve-1.1-2013.json.zip"
	zip_nvd2012="nvdcve-1.1-2012.json.zip"
	zip_nvd2011="nvdcve-1.1-2011.json.zip"
	zip_nvd2010="nvdcve-1.1-2010.json.zip"
	zip_nvd2009="nvdcve-1.1-2009.json.zip"
	zip_nvd2008="nvdcve-1.1-2008.json.zip"
	zip_nvd2007="nvdcve-1.1-2007.json.zip"
	zip_nvd2006="nvdcve-1.1-2006.json.zip"
	zip_nvd2005="nvdcve-1.1-2005.json.zip"
	zip_nvd2004="nvdcve-1.1-2004.json.zip"
	zip_nvd2003="nvdcve-1.1-2003.json.zip"
	zip_nvd2002="nvdcve-1.1-2002.json.zip"
	## Downloading the databases
	# Hardcoded location (may want to make temp)
	#databaseLoc="/tmp/"
	databaseLoc="./"
	dezipLoc="./"
        ## Update Everything
	# Grab database zip and save locally
	grabSaveDatabase(url_nvdRecent, databaseLoc, zip_nvdRecent)
	grabSaveDatabase(url_nvd2021, databaseLoc, zip_nvd2021)
	grabSaveDatabase(url_nvd2020, databaseLoc, zip_nvd2020)
	grabSaveDatabase(url_nvd2019, databaseLoc, zip_nvd2019)
	grabSaveDatabase(url_nvd2018, databaseLoc, zip_nvd2018)
	grabSaveDatabase(url_nvd2017, databaseLoc, zip_nvd2017)
	grabSaveDatabase(url_nvd2016, databaseLoc, zip_nvd2016)
	grabSaveDatabase(url_nvd2015, databaseLoc, zip_nvd2015)
	grabSaveDatabase(url_nvd2014, databaseLoc, zip_nvd2014)
	grabSaveDatabase(url_nvd2013, databaseLoc, zip_nvd2013)
	grabSaveDatabase(url_nvd2012, databaseLoc, zip_nvd2012)
	grabSaveDatabase(url_nvd2011, databaseLoc, zip_nvd2011)
	grabSaveDatabase(url_nvd2010, databaseLoc, zip_nvd2010)
	grabSaveDatabase(url_nvd2009, databaseLoc, zip_nvd2009)
	grabSaveDatabase(url_nvd2008, databaseLoc, zip_nvd2008)
	grabSaveDatabase(url_nvd2007, databaseLoc, zip_nvd2007)
	grabSaveDatabase(url_nvd2006, databaseLoc, zip_nvd2006)
	grabSaveDatabase(url_nvd2005, databaseLoc, zip_nvd2005)
	grabSaveDatabase(url_nvd2004, databaseLoc, zip_nvd2004)
	grabSaveDatabase(url_nvd2003, databaseLoc, zip_nvd2003)
	grabSaveDatabase(url_nvd2002, databaseLoc, zip_nvd2002)
	# Decompress/Unzip database JSON files
	dezipDatabase(databaseLoc, zip_nvdRecent, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2021, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2020, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2019, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2018, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2017, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2016, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2015, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2014, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2013, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2012, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2011, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2010, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2009, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2008, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2007, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2006, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2005, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2004, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2003, dezipLoc)
	dezipDatabase(databaseLoc, zip_nvd2002, dezipLoc)

# Function call for openning and returning JSON data
def getJSON(jsonFile):
	# Check current working directoy
	currDir = os.getcwd()
        # 
	if debug_bit != 0:
		print("Path:\t{0}".format(currDir))
	# Check if the path is from the Standards directory or from elsewhere
	if os.path.basename(currDir) != "Standards":
		# Change prefix to filename path
		jsonFile = currDir + "/Standards/" + jsonFile
		# Else do nothing
	with open(jsonFile) as json_file:
		data = json.load(json_file)
	return data

# Function to return a cost of attack value
def getCVEca(jsonData, cveID):
	# TODO: Have method for generating a Cost of Attack based on a CVE ID
	# Method space-hodler
        # Default return since another method does not exist yet
        if debug_bit != 0:
                print("[?] Nota Bene:\tCost of Attack is being assumed as 2.0 for now")
        return 2.0

# Functoin to search for CVE entry in database and return CVSS V3 Base Score
def grabCVSSv3(jsonData, cveID):
	# Run forCVE-2019-13021 loop searching for the CVE
	for item in jsonData['CVE_Items']:
		# Check match of CVE being searched for
		if item['cve']['CVE_data_meta']['ID'] == cveID:
			##### Check if the baseMetricV3 exists.... if not grab the V2 value (FALLBACK)  | IF there is nothing within item['impact'] then assign a negative number!
			if ('baseMetricV2' not in item['impact']) and ('baseMetricV3' not in item['impact']):
				return -1.0
			elif 'baseMetricV3' not in item['impact']:
				return item['impact']['baseMetricV2']['cvssV2']['baseScore']
			else:
				# Return base score
				return item['impact']['baseMetricV3']['cvssV3']['baseScore']
	# No match.... Return negative number
	return -1

# Function to return the year of a passed CVE
def getCVEyear(cveID):
	try:
		# group(1) because a search group was provided; default is 0 with complete match to regex statement
		found = re.search('-(\d\d\d\d)-', cveID).group(1)
		return found
	except AttributeError:
		found = ''
		return found

# Function for converting a file containing CVEs (i.e. one CVE per line) and converts it into a list; can be used to then generate the riskValDb.json output for integration with SMART Databases
def cveFile2List(filename):
	# Read in the contents using the read method and splitlines function; will NOT have newline characters included in the list
	with open(filename, 'r') as file_handle:
		# Convert file contents into a list
		cveList = file_handle.read().splitlines()
	return cveList

# Function to generate a riskValDB.json-style output relating to passed CVEs
def genCVErisk(cveList):
	# Local variables for function
	outputFile="riskValDb.json.tmp"
	cveData = {
	}
	# Run for loop through list of CVEs
	for cveID in cveList:
		# Loop specific variables for entry generation
		cveCVSS="-1.0"
		cveCa="-1.0"
		#print("[?] CVE ID - {0}".format(cveID))
		# Determine which year-database the specific CVE ID is from
		cveYear = getCVEyear(cveID)
		cveDb = nvdDict[cveYear]
		cveDatabase = getJSON(cveDb)
		# Return the CVSS value for the CVE ID  | Note: The below should allow for the information to be placed into the JSON database with proper quotations
		cvssVal=grabCVSSv3(cveDatabase, cveID)
		cveCVSS="{0}".format(str(cvssVal))
		# Return the Cost of Attack value for the CVE ID
		cveCa = "{0}".format(str(getCVEca(cveDatabase, cveID))) #"2.0"
		# Debugging
		#print("[?] Data Check:\n\tCVE ID:\t{0}\n\tPs Val:\t{1}\n\tCa Val:\t{2}\n\tCVSS Val:\t{3}\n\tDb File:\t{4}".format(cveID, cveCVSS, cveCa, str(cvssVal), cveDb))
		# Create entry for the CVE ID and aggregate to larger JSON output
		cveData[cveID] = {
			"Probability of Success": cveCVSS,
			"Cost of Attack": cveCa
		}
	# Write aggregated JSON entries to default output file
	with open(outputFile, 'w') as json_file:
		json.dump(cveData, json_file, indent="\t")         # Set change of indent from 4-spaces to use of tabs (\t)

# Function call for grabbing the CVSS score for a given CVE
def cvelistAPI(CVEPassed):
	'''
	# Ensuring passing of a CVE ID before continuing
	print("Number of arguments: " + str(len(sys.argv)) + " arguments")
	print("Argument List: " + str(sys.argv))

	# Check that an argument was passed
	if len(sys.argv) < 2:
	    print("[-] Error: No argument was passed to the script!")
	    print("-- Pass a specific CVE to grab information for:\n\tcveGrab.py CVE-XXXX-XXXX")
	    sys.exit()
	'''

	# Debugging line for checking that CVE was grabbed correctly
	#print("Input Variable: " + str(CVEPassed))
	
	# Check that the argument passed is actually a CVE ID
	cveID = CVEPassed #sys.argv[1]
	print("[+] Grabbed " + str(cveID) + " as the ID argument")
	
	print("[*] Checking actual CVE ID was passed....")
        # Checking that cveID should be of the form "CVE-\d\d\d\d-\d\d\d\d" | NOTE: Need to fix this to allow for a larger number of CVE match
	cveCheck = re.match("([cC][vV][eE])-\d\d\d\d-\d{4,7}", cveID)
	if cveCheck:
	    print("[+] Passed argument matches CVE ID formatting")

	    # Attempt to grab the CVE record
	    print("[*] Preparing API interaction with the cve.cirl.lu website for CVE information collection")
	    baseURL = "http://cve.circl.lu/api/cve/"
	    request_url = "%s%s" % (baseURL, cveID)
	    print("[*] Performing GET request for the CVE information")
	    cveResponse = requests.get(request_url)
	
	    # Check was the response code was for the GET
	    print("[*] Verifying the response code from the GET request")
	    #   If 404 -> Return error about non-existant CVE
	    if cveResponse.status_code == 404:
	        print("[-] GET request returned 404.... CVE record not found")
	        print("-- Re-run script with an existing CVE record")
	        sys.exit()
	    #   If 200 -> Return successful grab of CVE record
	    elif cveResponse.status_code == 200:
	        print("[+] GET request returned 200... Successfully found CVE record.")
	        print("[+] Decoding the JSON response into a python dictionary object")
                # NOTE: Found that this can still return 200 but not actually have been found (e.g. cveData is None)
	        cveData = cveResponse.json()
	    else:   
	        print("[-] GET request resonse code unknown....\n\tResponse: " + str(cveResponse.status_code) + "\n\tDetermine how this code should be interpreted")
	        sys.exit()
            
	    if cveData is not None:
	        print("[*] Returning the CVSS score from the retrieved CVE record")
	        print("\tCVE: \t\t" + str(cveID) + "\n\tCVSS V2 Score: \t" + str(cveData["cvss"]))
	        return cveData["cvss"]
	    else:
	         print("[-] CVE passed did not return anything..... ERROR")
	         return None
	else:
	    print("[-] Passed argument does NOT match CVE ID formatting\n\tPassed: " + cveID + " needs to be in format CVE-XXXX-XXXX")
	    probOfSuccess = float(input('What is the Probabilitiy of Success for ' + str(cveID) + ' (from 0.0 to 10.0): '))
	    print("[*] Returning user provided Probability of Success")
	    return probOfSuccess    # DO NOT MAKE TO 0.0 to 1.0 SCALE HERE!!! WILL BE CHANGED LATER WHEN CALLED

# Function call for grabbing a single CVSS score for a given CVE
def singleCVE_CVSSreturn(CVEPassed):
	'''
	# Ensuring passing of a CVE ID before continuing
	print("Number of arguments: " + str(len(sys.argv)) + " arguments")
	print("Argument List: " + str(sys.argv))
	
	# Check that an argument was passed
	if len(sys.argv) < 2:
	    print("[-] Error: No argument was passed to the script!")
	    print("-- Pass a specific CVE to grab information for:\n\tcveGrab.py CVE-XXXX-XXXX")
	    sys.exit()

        # Added Functionality:  Adding to the CVE risk database when importings CVEs
	'''
	
	# Debugging line for checking that CVE was grabbed correctly
	#print("Input Variable: " + str(CVEPassed))
	
	# Check that the argument passed is actually a CVE ID
	cveID = CVEPassed #sys.argv[1]
	if debug_bit != 0:
		print("[+] Grabbed " + str(cveID) + " as the ID argument")
		print("[*] Checking actual CVE ID was passed....")
	# Checking that cveID should be of the form "CVE-\d\d\d\d-\d\d\d\d" | NOTE: Need to fix this to allow for a larger number of CVE match
	cveCheck = re.match("([cC][vV][eE])-\d\d\d\d-\d{4,7}", cveID)
	if cveCheck:
		if debug_bit != 0:
			print("[+] Passed argument matches CVE ID formatting")
	
		# Pull out the year that the CVE is from
		if debug_bit != 0:
			print("[*] Obtaining year of CVE...")
		cveYear = getCVEyear(cveID)
	
		# Read from the correct database
		if debug_bit != 0:
			print("[*] Setting database to correct one for CVE being examined")
		cveDatabase = nvdDict[cveYear]
	
		# Check that was able to read from the JSON database correctly
		if debug_bit != 0:
			print("[*] Reading from the year-specific database")
		cveData = getJSON(cveDatabase)
           
		# Check that data got returned correctly
		if cveData is not None:
			if debug_bit != 0:
				print("[*] Returning the CVSS score from the retrieved CVE record")
			cvssScore = grabCVSSv3(cveData, cveID)
			# Check that a correct CVSS score was returned (non-negative one)
			if cvssScore < 0:
				# Noramlly want input from the user; commenting out to automate
				# Assuming now if the Ps is negative, force to 0; issue due to online read
				#print("[-] Negative CVSS score returned")
				#probOfSuccess = float(input('What is the Probabilitiy of Success for ' + str(cveID) + ' (from 0.0 to 10.0): '))
				#print("[*] Returning user provided Probability of Success")
				# Forcing probOfSuccess = 0.0
				probOfSuccess = 0.0
				return probOfSuccess    # DO NOT MAKE TO 0.0 to 1.0 SCALE HERE!!! WILL BE CHANGED LATER WHEN CALLED
			else:
				if debug_bit != 0:
					print("\tCVE: \t\t" + str(cveID) + "\n\tCVSS V3 Score: \t" + str(cvssScore))
				return cvssScore
		else:
			if debug_bit != 0:
				print("[-] CVE passed did not return anything..... ERROR")
			return None
	# Response if unable to read from database correctly
	else:
		print("[-] Passed argument does NOT match CVE ID formatting\n\tPassed: " + cveID + " needs to be in format CVE-XXXX-XXXX")
		probOfSuccess = float(input('What is the Probabilitiy of Success for ' + str(cveID) + ' (from 0.0 to 10.0): '))
		print("[*] Returning user provided Probability of Success")
		return probOfSuccess    # DO NOT MAKE TO 0.0 to 1.0 SCALE HERE!!! WILL BE CHANGED LATER WHEN CALLED

# Function call for grabbing the CVSS score for a given CVE
# Note: Function is written to take in a given CVE 
def main(CVEPassed, CVEData):
	# Debugging line for checking that CVE was grabbed correctly
	#print("Input Variable: " + str(CVEPassed))
	
	# Check that the argument passed is actually a CVE ID
	cveID = CVEPassed #sys.argv[1]
	if debug_bit != 0:
		print("[+] Grabbed " + str(cveID) + " as the ID argument")
		print("[*] Checking actual CVE ID was passed....")
	# Checking that cveID should be of the form "CVE-\d\d\d\d-\d\d\d\d" | NOTE: Need to fix this to allow for a larger number of CVE match
	cveCheck = re.match("([cC][vV][eE])-\d\d\d\d-\d{4,7}", cveID)
	if cveCheck:
		if debug_bit != 0:
			print("[+] Passed argument matches CVE ID formatting")
	
		# Pull out the year that the CVE is from
		#if debug_bit != 0:
			#print("[*] Obtaining year of CVE...")
		#cveYear = getCVEyear(cveID)
	
		# Read from the correct database
		#if debug_bit != 0:
			#print("[*] Setting database to correct one for CVE being examined")
		#cveDatabase = nvdDict[cveYear]
	
		# Check that was able to read from the JSON database correctly
		#if debug_bit != 0:
			#print("[*] Reading from the year-specific database")
		#cveData = getJSON(cveDatabase)
		cveData = CVEData
                # NOTE: Moved loading of JSON databases to the SMART/combineScript.py
           
		# Check that data got returned correctly
		if cveData is not None:
			if debug_bit != 0:
				print("[*] Returning the CVSS score from the retrieved CVE record")
			cvssScore = grabCVSSv3(cveData, cveID)
			# Check that a correct CVSS score was returned (non-negative one)
			if cvssScore < 0:
				# Noramlly want input from the user; commenting out to automate
				# Assuming now if the Ps is negative, force to 0; issue due to online read
				#print("[-] Negative CVSS score returned")
				#probOfSuccess = float(input('What is the Probabilitiy of Success for ' + str(cveID) + ' (from 0.0 to 10.0): '))
				#print("[*] Returning user provided Probability of Success")
				# Forcing probOfSuccess = 0.0
				probOfSuccess = 0.0
				return probOfSuccess    # DO NOT MAKE TO 0.0 to 1.0 SCALE HERE!!! WILL BE CHANGED LATER WHEN CALLED
			else:
				if debug_bit != 0:
					print("\tCVE: \t\t" + str(cveID) + "\n\tCVSS V3 Score: \t" + str(cvssScore))
				return cvssScore
		else:
			if debug_bit != 0:
				print("[-] CVE passed did not return anything..... ERROR")
			return None
	# Response if unable to read from database correctly
	else:
		print("[-] Passed argument does NOT match CVE ID formatting\n\tPassed: " + cveID + " needs to be in format CVE-XXXX-XXXX")
		probOfSuccess = float(input('What is the Probabilitiy of Success for ' + str(cveID) + ' (from 0.0 to 10.0): '))
		print("[*] Returning user provided Probability of Success")
		return probOfSuccess    # DO NOT MAKE TO 0.0 to 1.0 SCALE HERE!!! WILL BE CHANGED LATER WHEN CALLED

# Function that allows this script to be imported without automatically running the main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Use API call to grab CVSS V3/V2 score for a given CVE')
    parser.add_argument('CVE_ID', help='CVE ID that will be looked up to obtain the CVSS V2 score') # Note: nargs made python think this input was a list and NOT a string
    args = parser.parse_args()
    main(args.CVE_ID)
