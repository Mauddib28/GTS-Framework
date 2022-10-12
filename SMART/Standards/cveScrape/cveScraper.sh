#!/bin/bash

#####
# The purpose of this code is to perform scraping of CVE data to produce:
#	1) 
#	2) Text file containing all the mentioned CVE IDs; one CVE ID per line
#	3) Update to TAMSAT databases
#	4) Update to SMART databases
#
# Steps:
#	1) Copy and paste CVE data from website (CVE ID + Description) into a text file; one CVE per line
#	2) Use sed to remove any CVSS information from the CVE entries
#	3) Convert the CVE enteries into JSON format
#		- Ex: "CVE-YYYY-XXXXXX": "Description information"
#	4) Remove JSON issue characters; not sure how to do this automated....
#		- Characters:
#			& -> &amp;
#			< -> &lt;
#			> -> &gt;
#	5) Create file with CVEs listed; one CVE ID per line
#	6) Feed file into python function to make tmp riskValDb.json file
#	7) Merge riskValDb.json.tmp into main TAMSAT and SMART databases
#####

### Globals
cveListFile="cveList.txt"
#inFile="cveScrape.txt"
userFile="cveScrape.txt"
outFile="cveJSON.txt"
#tmpScrape="/tmp/scrape.tmp"
inFile="/tmp/scrape.tmp"

### Functions


### Main Code
## Check for user input file (the text file to be taken in)

# Check that any arguments were supplied
if [ $# -eq 0 ]; then
        echo "No arguments were supplied to the script"
        echo -e "Usage:\t./cveScraper.sh <CVE Text Scrape File>\n\nCVE Scrape File:\tCopy and pasted CVE ID and Description; one CVE per line"
        exit 0
fi

# Check to see if a variable was passed
if [ -z "$1" ]; then
        echo "ERROR: The first argument was not passed..... This should be the CVE scrape file"
        exit 0
else
        # Set the value of the AADL model file
        userFile=$1
fi

## Clean up the original scrape file to remove unwanted characters (JSON-related issues)
#	Examples:	&, <, >, \, "
cat $userFile | sed -r "s/\"/'/g" | sed -r 's/\\/\//g' | sed -r 's/</\&lt;/g' | sed -r 's/>/\&gt;/g' | sed -r 's/\&/\&amp;/g' > $inFile

## Convert CVE enteries into JSON format | Note: Adding in the 12 spaces for JSON formatting to be same as rest of database
cat $inFile | sed -r 's/\ CVSS.*$//g' | sed -r 's/^(CVE-[0-9]{4}-[0-9]{4,7})\ /\1\":\ \"/g' | sed -r 's/^/\"/g' | sed -r 's/$/\",/g' | sed -r 's/^/\ \ \ \ \ \ \ \ \ \ \ \ /g' > $outFile

## Create the file with listed CVEs
grep -Eo "CVE-20[0-9]{2}-[0-9]{4,7}[[:space:]]" $inFile | sed 's/[ \t]*$//g' > $cveListFile

### Optional Code
## Remove JSON issue characters

## Feed cveListFile into python function to generate riskValDb.json.tmp

## Merge into TAMSAT and SMART databases


### Clean up
#rm $tmpScrape
rm $inFile
