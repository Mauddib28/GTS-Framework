#!/bin/bash

###
# The purpose of this script is to act as a means to combine GAM, TAMSAT, and SMART for the generation and
#	evaluation of the security risk evaluation of the generated AADL models
# 
# Author:        Paul A. Wortman
# Last Edit:     3/24/2022 
###

# Check that any arguments were supplied
if [ $# -ne 1 ]; then
        echo "Incorrect arguments were supplied to the script"
	echo -e "Usage:\t./gtsFramework.sh <user_input_file>"
	exit 0
fi

# Check to see if a variable was passed
if [ -z "$1" ]; then
        echo "ERROR: The first argument was not passed..... This should be the <location>/<filename> of the AADL model file"
	exit 0
else
        # Set the value of the AADL model file
        userInputFile=$1
fi

# Check to see if a second variable was passed [if see a second then running in verbose mode?]
if [ -z "$2" ]; then
	verbosity=0
else
	echo "Verbose Mode Flag Passed"
	verbosity=1
fi

# Flavor text to indicate start of the bash script's execution
echo -e "=================================================================="
echo -e "	GAM + TAMSAT + SMART - Generation and Evaluation	   "
echo -e "=================================================================="
echo -e "\n\nStarting process.....\n"

##
# Checks for existence of the corresponding directories		[ HARDCODED ]
#
# Note: Directories should be found as subdirectories of location where this script is being run
##
gamLocation="GAM/"
tamsatLocation="TAMSAT/"
smartLocation="SMART/"
workingLocation="workDir/"

# Check to ensure that the GAM subdirectory in the expected location
if [[ -d $gamLocation ]]; then
	echo -e "[+] Able to locate the GAM subdirectory"
else
	echo -e "[-] Unable to locate the GAM tool...... Exiting"
	exit 1
fi

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

# Check to ensure that the working subdirectory exists, and if not then create it
if [[ -d $workingLocation ]]; then
	echo -e "[+] able to locate the WORKSPACE subdirectoy"
else
	echo -e "[-] Unable to locate the WORKSPACE subdirectory..... Creating it...."
	mkdir $workingLocation
fi

# Make call to the GAM Tool
#	-> Note: First dry run will be to force creation of a single type of AADL model file
## TODO: Evenutally have the model variations be introduced via provided input
#	- NOTE: For now do rough filename exatraction to obtain name of each AADL model file
echo -e "[*] Starting Generation of AADL Models (GAM)......"
echo -e "[!] NOTE: Currently ONLY implemented to generate database-firewall AADL model files\n"
cd $workingLocation
if [[ $verbosity -ne "0" ]]; then		# TODO: Add verbose tag into to GAM script code
	python ../$gamLocation/ModelGen/genAADLmodel.py ../$userInputFile #--verbose
else
	python ../$gamLocation/ModelGen/genAADLmodel.py ../$userInputFile
fi

## Check that AADL model files were produced?
# Grep test for ".aadl" files

# TODO: The below needs to be fixed / changed since the filenames no longer give the information about the AoI elements
# Cut and create array of database types 		# NOTE: Depends on assumption of <database>_firewall.aadl file format; extrapolating into a <database>_<firewall>.aadl file format
#file_array=$(ls *.aadl | cut -d'_' -f1 | sort | uniq)
# ^ Added *.aadl to clarify ONLY wanting model files
#firewall_array=$(ls *.aadl | cut -d'_' -f2 | cut -d'.' -f1 | sort | uniq)
# ^ Added second cut to remove the ".aadl" part of the original filename
file_array=$(ls *.aadl | cut -d'.' -f1 | sort | uniq)
#file_array=($(ls *.aadl | cut -d'.' -f1 | sort | uniq))
test_array=( $file_array )
# NOTE: Above addition of the extra '()' around the outside of the file_array setting to create an array; MAY NEED TO CHANGE THIS LATER
echo -e "[+] File array generated from GAM produced AADL files\n"
cd ../			# Return to the base directory that the risk is being run from

echo -e "--------------------"
echo -e "  Transition Check  "
echo -e "--------------------"

## Nota Bene: New version of GAM no longer requires this tracking
# NOTE: The following is a variables that contains the AoI for the SMART HOME MODELS (0-6) ONLY!!
#smart_home_aoi_array=("database" "database" "oracle_database" "database" "database" "oracle_database" "oracle_database" "mysql_database")
#num_of_files=${#test_array[@]}
#num_of_aois=${#smart_home_aoi_array[@]}
# Check that the two array length checks above are returning the same number (i.e. the same length)
#if [[ "$num_of_files" != "$num_of_aois" ]]; then
#	echo -e "[-] ERROR: Mismatch between the lengths of arrays used for TAMSAT generation.... Lengths are:\n\tnum_of_files\t-\t$num_of_files\n\tnum_of_aois\t-\t$num_of_aois"
#	exit 2
#else
#	echo -e "[+] The lengths of the two arrays used for proper TAMSAT generation"
#fi

# Variables for loop counting and matching AoI to model filename
#	- NOTE: Will need to be changed later when running larger combinations of model files
array_counter=0
### Begin larger loop for going through each generat,ed AADL mode file
for model_file in ${file_array[@]}; do
	echo -e "[*] Beginning TAMSAT + SMART on "$model_file"_"$firewall_model".aadl AADL model file"
	# Move working directory path to TAMSAT
	#tamsatInfile=$model_file"_firewall.aadl"
	tamsatInfile=$model_file".aadl"
	tamsatOutfile=$model_file".attacktree"
	#asset_of_importance=${smart_home_aoi_array[$array_counter]}
	echo -e "[?] Variable Check:\n\tInfile:\t\t$tamsatInfile\n\tOutfile:\t$tamsatOutfile"
	# Beginning TAMSAT portion of the AADL model examination
	echo -e "[*] Starting Translation of AADL Model to Security Attack Tree (TAMSAT)......"
	cd $tamsatLocation
	# TODO: Add in automation for TAMSAT creation through passing of the AoI from GAM
	#	- TODO: Correct the below to not pass the '$model_file' as the AoI, since the file name no longer carries the AoI an Firewall
	if [[ $verbosity -ne "0" ]]; then
#		python readModel.py ../$workingLocation$tamsatInfile ../$workingLocation$tamsatOutfile $asset_of_importance --verbose
		python readModel.py ../$workingLocation$tamsatInfile ../$workingLocation$tamsatOutfile --verbose

	else
#		python readModel.py ../$workingLocation$tamsatInfile ../$workingLocation$tamsatOutfile $asset_of_importance
		python readModel.py ../$workingLocation$tamsatInfile ../$workingLocation$tamsatOutfile

	fi
	# Should now have an existing TAMSAT attacktree
	# TODO: Add in automated functionality to TAMSAT so that the user does not have to provide AoI
	#	-> NOTE: Should eventually come from GAM	~!~
	## Prepare/Move working directory path from TAMSAT to SMART
	smartInfile=$model_file".attacktree"
	smartOutfile=$model_file".smart"
	# Beginning SMART portion of the AADL model examination
	echo -e "[*] Starting Security Model Adversarial Risk-based Tool for Security Design Evaluation (SMART)......"
	cd ../$smartLocation
	# Make call to the SMART Tool
	if [[ $verbosity -ne "0" ]]; then
		python combineScript.py ../$workingLocation$smartInfile ../$smartOutfile --verbose
	else
		python combineScript.py ../$workingLocation$smartInfile ../$smartOutfile
	fi
	# Track output from SMART for the purpose of summarizing together
	echo -e "[+] Completed TAMSAT + SMART for the $model_file + $firewall_model AADL model file"
	echo -e "\tSummary can be found:\t$smartOutfile"
	# Reset directory location back to the main directory
	cd ../
	let "array_counter++"
done

## Outputting formatted output from complete GAM + TAMSAT + SMART
# Output file location
fullRun_outfile="modelEval.gts"
# Clear out the output file
> $fullRun_outfile
## Run in a loop; perhaps combine with loop above??
# Begin outputting data in formatted sense
# Information to be included:
echo -e "-----========================================================-----\n" >> $fullRun_outfile
echo -e "\t\tGAM + TAMSAT + SMART (GTS) Summary for "$model_file" AADL Model\n" >> $fullRun_outfile
# Associated Files:
# Original Model File
echo -e "\tModel File Generated:\t\n" >> $fullRun_outfile
# Attack Tree
echo -e "\tAttack Tree File Generated:\t\n" >> $fullRun_outfile
# SR Evaluation Versions
echo -e "\tSecurity Risk Evaluation (Raw):\t\n" >> $fullRun_outfile
# Number of Path Combinations Evaluated
echo -e "\tNumber of Path Combinations:\t\n" >> $fullRun_outfile
# Number of Tuple Path Combinations
echo -e "\tNumber of Tuple Path Combinations:\t\n" >> $fullRun_outfile
# Full Security Cost (USD)
echo -e "\tFull Security Cost (USD):\t\n" >> $fullRun_outfile
# Max Subpath SR
echo -e "\tMax Subpath Security Risk:\t\n" >> $fullRun_outfile
# Max Subpath SR Associated CVEs
echo -e "\tMax Subpath Security Risk Associated CVEs:\t\n" >> $fullRun_outfile
# Max Subpath SR Associated Ps
echo -e "\tMax Subpath Security Risk Associated Ps:\t\n" >> $fullRun_outfile
# Most expensive path relative to top level 'potential path' paths
echo -e "\tMost Expensive Path Relative to\n\t\tTop Level 'Potential Path' Paths:\t\n" >> $fullRun_outfile
# Most expensive path relative to sub-list of 'potential CVE path' paths
echo -e "\tMost Expensive Path Relative to\n\t\tSub-List of 'Potential CVE Path' Paths:\t\n" >> $fullRun_outfile
# Imposed design constraints
echo -e "\tImposed Design Constraints:\t\n" >> $fullRun_outfile
echo -e "-----========================================================-----\n" >> $fullRun_outfile

## Flavor text indicating the end of the bash script running
echo -e "[+] Completed AADL Model Generation to Security Risk Evalutation"
#python SMART/combineScript.py
