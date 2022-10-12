#!/bin/bash

###
# The purpose of this script is to act as a user GUI for combining the TAMSAT and SMART tools for determining
#	the security risk evaluation of a provided AADL model
# 
# Author:        Paul A. Wortman
# Last Edit:     3/5/2021 
###

# Check that any arguments were supplied
if [ $# -eq 0 ]; then
        echo "No arguments were supplied to the script"
	echo -e "Usage:\t./model2risk.sh <AADL Model File> <Output Location for Attack Tree File>\n\nAADL Model File:\tProvide in Format of <location>/<filename>\nAttack Tree Output:\tProvide in the Format of <location>/<filename>"
	exit 0
fi

# Check to see if a variable was passed
if [ -z "$1" ]; then
        echo "ERROR: The first argument was not passed..... This should be the <location>/<filename> of the AADL model file"
	exit 0
else
        # Set the value of the AADL model file
        aadlFile=$1
fi

# Check to see if a second variable was passed
if [ -z "$2" ]; then
        echo "ERROR: The second argument was not passed.... This should be the <location>/<filename> of the generated attack tree file"
        fileRename="largeRun"
	exit 0
else
        # Set the value of the file rename
        fileRename=$2
fi

# Check to see if a third variable was passed [if see a third then running in verbose mode?]
if [ -z "$3" ]; then
	verbosity=0
else
	echo "Verbose Mode Flag Passed"
	verbosity=1
fi

# Flavor text to indicate start of the bash script's execution
echo -e "=========================================="
echo -e "	TAMSAT and SMART Model Analysis	   "
echo -e "=========================================="
echo -e "\n\nStarting process....."

##
# Checks for existence of the corresponding directories		[ HARDCODED ]
#
# Note: Directories should be found as subdirectories of location where this script is being run
##
tamsatLocation="TAMSAT/"
smartLocation="SMART/"

# Check to ensure that the TAMSAT subdirectory in the expected location
if [[ -d $tamsatLocation ]]; then
	echo -e "[+] Able to locate the TAMSAT subdirectory"
else
	echo -e "[-] Unable to locate the TAMSAT tool..... Exiting"
	exit 1
fi

# Check to ensure that the SMART subdirectory in the expected location
if [[ -d $smartLocation ]]; then
	echo -e "[+] Able to locate the SMART subdirectory"
else
	echo -e "[-] Unable to locate the SMART tool...... Exiting"
	exit 1
fi

# Make call to the TAMSAT Tool
#	-> Note: First run with dummy/basic parameters
#tamsatInfile="testFiles/testFirewall.aadl"
#tamsatOutfile="testRun.attacktree"
tamsatInfile="../$aadlFile"
tamsatOutfile="../$fileRename"
assetOfImportance="database"

# Beginning TAMSAT portion of AADL model examination
echo -e "[*] Starting Translation of AADL Model to Security Attack Tree (TAMSAT)....."
cd $tamsatLocation
if [[ $verbosity -ne "0" ]]; then
	python readModel.py $tamsatInfile $tamsatOutfile $assetOfImportance --verbose
else
	python readModel.py $tamsatInfile $tamsatOutfile $assetOfImportance
fi

# Should now have an existing TAMSAT/testRun.attacktree (Note: Right now from default tamsatOutfile)

## Prepare/Move files for moving from TAMSAT to SMART model
echo -e "--------------------"
echo -e "  Transition Check  "
echo -e "--------------------"
echo -e "TAMSAT Output: $tamsatLocation$tamsatOutfile"

# Make call to the SMART Tool
#	-> Note: First run with dummy/basic parameters		| Maybe need to change into that directory first?
#smartInfile='TestFiles/easyDoS.attacktree'
smartOutfile='fullRun.output'
smartInfile="$tamsatOutfile"	# Note: Do not need the relative directory path (e.g. ../) since it is already included by SMART (?)
#smartInfile="$(basename -- $tamsatOutfile)"
echo -e "[*] Starting Security Model Adversarial Risk-based Tool for Security Design Evaluation (SMART)....."
cd ../$smartLocation
#cp ../$tamsatLocation$tamsatOutfile ./
#file $smartInfile

# Beginning SMART portion of AADL model examination
if [[ $verbosity -ne "0" ]]; then
	python combineScript.py $smartInfile $smartOutfile --verbose
else
	python combineScript.py $smartInfile $smartOutfile
fi

# Flavor text indicating the end of the bash script running
echo -e "[+] Completed AADL Model Attack Tree Generation to Security Risk Evalutation"
#python SMART/combineScript.py
