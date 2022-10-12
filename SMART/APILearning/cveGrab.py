#!/usr/bin/python

'''
 The purpose of this code is to act as an API script for grabbing CVE information
   for a user passed CVE value

 Nota Bene: This code has been superceeded by that under the /Standards/ directory

 
 Author:        Paul A. Wortman
 Last Edit:     6/9/2021 
'''

import json     # Import for working with json
import requests # Import for requesting data from websites
import sys      # Import for determining passed arguments
import re       # Import for using regex in python
import argparse # Import for easy help and usage message, issue error, and writing user-friendly command-line script

'''
 Function definitions
'''

# Function calkl for grabbing the CVSS score for a given CVE
def main(CVEPassed):
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
	

# Function that allows this script to be imported without automatically running the main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Use API call to grab CVSS V2 score for a given CVE')
    parser.add_argument('CVE_ID', help='CVE ID that will be looked up to obtain the CVSS V2 score') # Note: nargs made python think this input was a list and NOT a string
    args = parser.parse_args()
    main(args.CVE_ID)
