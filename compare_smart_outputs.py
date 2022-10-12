###
# Python Script for Interpreting and Finding Information about SMART Output Files
###

### Imports
import re
import os
from ast import literal_eval as make_tuple              # Pull in to allow converting a string to tuple

### Globals
debugBit = 0
scale_amount = 1000         # Comes from SMART tool's scale amount

## Variables for Performing Regex (re) searches for key information within SMART output
# Most Risky Subpath Values
most_risky_subpath_tuple = "Most Expensive/Risky Subpath"
most_risky_subpath_cves = "Associated CVEs to Max SR Path"
most_risky_subpath__max_sr_subpath_aggregate_cost = "Maximum SR Seen from Subpath"
most_risky_subpath__max_sr_subpath_security_risk_cost = "Maxium SR Subpath - Total Cost"                ## Note: If this information is zero, then no existing attack paths
most_risky_subpath__max_sr_tuple_position = "Item in Potential Path Tuple SR"
most_risky_subpath__max_sr_subpath_product_array_location = "Item in Product Array of Max SR"
# Least Risky Subpath Values
least_risky_subpath_tuple = "Least Expensive/Risky Subpath Tuple"
least_risky_subpath_cves = "Associated CVEs to Min SR Subpath"
least_risky_subpath__min_sr_subpath_aggregate_cost = "Minimum SR Seen from Subpath Tuple"
least_risky_subpath__min_sr_subpath_security_risk_cost = "Minimum SR Subpath - Total Cost"              ## Note: If this information is zero, then no existing attack paths
least_risky_subpath__min_sr_tuple_position = "Item in Potential Path Tuple SR"
least_risky_subpath__min_sr_subpath_product_array_location = "Item in Product Array of Min SR"
# Full Path List Security risk Evaluation Generated Output, Number of Attack Paths, and Attack Path Elements
full_security_risk_path_evaluation = "Full Path List Security Risk Evaluation Generated Output"
total_number_of_potential_attack_paths = "Total Number of Potential Attack Paths"
attack_path_combinations_with_device_elements = "Attack Path Combinations Elements"
## Creating an array of all the information to be searched for in the SMART file
smart_file_value_regex_array = [most_risky_subpath_tuple, most_risky_subpath_cves, most_risky_subpath__max_sr_subpath_aggregate_cost, most_risky_subpath__max_sr_subpath_security_risk_cost, most_risky_subpath__max_sr_tuple_position, most_risky_subpath__max_sr_subpath_product_array_location, least_risky_subpath_tuple, least_risky_subpath_cves, least_risky_subpath__min_sr_subpath_aggregate_cost, least_risky_subpath__min_sr_subpath_security_risk_cost, least_risky_subpath__min_sr_tuple_position, least_risky_subpath__min_sr_subpath_product_array_location, full_security_risk_path_evaluation, total_number_of_potential_attack_paths, attack_path_combinations_with_device_elements]

# How to interpret the tuples provided by the Subpath Tuples
'''
        # Debug output to check values                                  # <=============== This is where we can interpret the contents of the Subpath variables; NOTE: Each entry contains information for Max SR + Item and Min SR + Item ONLY for the specific PATH combination
        subPathSR = pathList_SecurityRisk[trackPathVar][0]
        subPathMaxSR = pathList_SecurityRisk[trackPathVar][1]
        subPathMaxSRitem = pathList_SecurityRisk[trackPathVar][2]
        # TODO: Add the min version of variables for tracking
        subPathMinSR = pathList_SecurityRisk[trackPathVar][3]           # <----- Note: These are getting stuck with the subPathMaxSR value....
        subPathMinSRitem = pathList_SecurityRisk[trackPathVar][4]

'''
# TODO: Incorporate the above parsing of information to get a deeper dive on each potential attack path within the model

### Functions

## Function for reading a SMART output tuple and extracting the embedded information from the tuple
# Breakdown of the expected tuple content:
#   [0]     -       Subpath Security Risk                   (Aggregate for ENTIRE PATH)
#   [1]     -       Subpath Maximum Security Risk           (Single Attack Path)
#   [2]     -       Subpath Maximum Security Risk Item in Cartisian Product
#   [3]     -       Subpath Minimum Security Risk           (Single Attack Path)
#   [4]     -       Subpath Minimum Security Risk Item in Cartisian Product
#   -> NOTE: Each tuple will be respective to the Maximum SR subpath or the Minimum SR subpath tuples (i.e. most_risky_subpath_tuple, least_risky_subpath_tuple)
def read_and_return__smart_tuple_variable_extraction(smart_subpath_tuple):
    if debugBit != 0:
        print("[*] Read and Return the embedded variables from the provided Smart Subpath Tuple [ {0} ]".format(smart_subpath_tuple))
    # Extract the variables from the provided tuple
    subpath_security_risk_aggregate = smart_subpath_tuple[0]
    subpath_security_risk__max_single_path = smart_subpath_tuple[1] * scale_amount      # Note: These two values need to be scaled to match the same scale of USD provided by the aggregate paths
    subpath_security_risk_item__max_single_path = smart_subpath_tuple[2]                #       /
    subpath_security_risk__min_single_path = smart_subpath_tuple[3] * scale_amount      # -----/
    subpath_security_risk_item__min_single_path = smart_subpath_tuple[4]
    # Now return the extracted information
    return subpath_security_risk_aggregate, subpath_security_risk__max_single_path, subpath_security_risk_item__max_single_path, subpath_security_risk__min_single_path, subpath_security_risk_item__min_single_path

## Function for reading a SMART output file and extracting the key information
def read_and_return__smart_output_variables_json(smart_file_location):
    if debugBit != 0:
        print("[*] Extracting SMART file output from the SMART file [ {0} ]".format(smart_file_location))
    ## Created variables for function
    smart_variable_extraction_json = {}
    ## Reading the contents of the SMART output filename
    with open(smart_file_location) as smart_file:
        smart_file_contents = smart_file.read()
        if debugBit != 0:
            print("File Contents:\n{0}".format(smart_file_contents))
    ## Parse through the split lines of the original read to pull out all of the smart file contents
    for data_line in smart_file_contents.splitlines():
        # Search for the specific known variables output in the SMART output file
        for search_term in smart_file_value_regex_array:
            test_match = re.search(search_term, data_line, re.IGNORECASE)
            # Check that the test_match return something (i.e. a match to the search was found)
            if test_match:
                if debugBit != 0:
                    print("Found match for {0}\n\tLine:\t{1}".format(search_term, data_line))
                # Add the recognized information into the smart_variable_extraction_json structure
                smart_variable_extraction_entry = {
                        search_term : data_line.replace("\t", "").split(":")[1]     # Remove the tabs from the string, splits based on the colon (:), and return the data of interest
                        }
                smart_variable_extraction_json.update(smart_variable_extraction_entry)
    # At the end of this we have a full structure with the information from the provided file
    return smart_variable_extraction_json

## Function for reading the SMART output file JSON and finding the largest number of attack paths
def read_and_return__maximum_number_of_model_attack_paths(smart_data_json):
    maximum_number_of_attack_paths = 0      # Start at zero
    maximum_number_attack_paths__smart_file_entry = ''
    for smart_file_entry in smart_data_json:
        if float(smart_data_json[smart_file_entry][total_number_of_potential_attack_paths]) > maximum_number_of_attack_paths:
            maximum_number_of_attack_paths = float(smart_data_json[smart_file_entry][total_number_of_potential_attack_paths])
            maximum_number_attack_paths__smart_file_entry = smart_file_entry
    return maximum_number_of_attack_paths, maximum_number_attack_paths__smart_file_entry

## Function for reading the SMART output file JSON and finding the lowest number of attack paths
def read_and_return__minimum_number_of_model_attack_paths(smart_data_json):
    minimum_number_of_attack_paths = -1     # Start at a negative number
    minimum_number_attack_paths__smart_file_entry = ''
    for smart_file_entry in smart_data_json:
        if minimum_number_of_attack_paths != -1:    # If not dealing with the starting scenario
            if float(smart_data_json[smart_file_entry][total_number_of_potential_attack_paths]) < minimum_number_of_attack_paths:
                minimum_number_of_attack_paths = float(smart_data_json[smart_file_entry][total_number_of_potential_attack_paths])
                minimum_number_attack_paths__smart_file_entry = smart_file_entry
        else:
            minimum_number_of_attack_paths = float(smart_data_json[smart_file_entry][total_number_of_potential_attack_paths])
            minimum_number_attack_paths__smart_file_entry = smart_file_entry
    return minimum_number_of_attack_paths, minimum_number_attack_paths__smart_file_entry

## Function for reading the SMART output file JSON and finding the largest Security Risk from JUST THE ATTACK PATH
def read_and_return__maximum_security_risk_from_attack_path(smart_data_json):
    maximum_security_risk_from_single_attack_path = 0       # Start with the assumption that NO attack path is viable, go up from there
    maximum_sr_single_path__smart_file_entry = ''
    for smart_file_entry in smart_data_json:
        if float(smart_data_json[smart_file_entry][most_risky_subpath__max_sr_subpath_security_risk_cost]) > maximum_security_risk_from_single_attack_path:
            maximum_security_risk_from_single_attack_path = float(smart_data_json[smart_file_entry][most_risky_subpath__max_sr_subpath_security_risk_cost])
            maximum_sr_single_path__smart_file_entry = smart_file_entry
    return maximum_security_risk_from_single_attack_path, maximum_sr_single_path__smart_file_entry

## Function for reading the SMART output file JSON and finding the lowest Security Risk from JUST THE ATTACK PATH
def read_and_return__minimum_security_risk_from_attack_path(smart_data_json):
    minimum_security_risk_from_single_attack_path = -1       # Start with the assumption that NO attack path is viable, go up from there
    minimum_sr_single_path__smart_file_entry = ''
    for smart_file_entry in smart_data_json:
        if float(smart_data_json[smart_file_entry][least_risky_subpath__min_sr_subpath_security_risk_cost]) > minimum_security_risk_from_single_attack_path:
            minimum_security_risk_from_single_attack_path = float(smart_data_json[smart_file_entry][least_risky_subpath__min_sr_subpath_security_risk_cost])
            minimum_sr_single_path__smart_file_entry = smart_file_entry
    return minimum_security_risk_from_single_attack_path, minimum_sr_single_path__smart_file_entry

## Function for reading the SMART output file JSON and finding the largest Security Risk from AN AGGREGATE COST
#   - Note: Added output to give the "coordinates" for each record
def read_and_return__maximum_security_risk_from_aggregate_risk(smart_data_json):
    maximum_security_risk_from_aggregate_attack_paths = 0   # Start with the assumption that NO security risk is present in the model, go up from there
    maximum_sr_aggregate__smart_file_entry = ''
    for smart_file_entry in smart_data_json:
        if float(smart_data_json[smart_file_entry][most_risky_subpath__max_sr_subpath_aggregate_cost]) > maximum_security_risk_from_aggregate_attack_paths:
            maximum_security_risk_from_aggregate_attack_paths = float(smart_data_json[smart_file_entry][most_risky_subpath__max_sr_subpath_aggregate_cost])
            maximum_sr_aggregate__smart_file_entry = smart_file_entry
    return maximum_security_risk_from_aggregate_attack_paths, maximum_sr_aggregate__smart_file_entry

## Function for reading the SMART output file JSON and finding the lowest Security Risk from AN AGGREGATE COST      | TODO: Figure out why this is NOT seeing the minimum security risk model variation
def read_and_return__minimum_security_risk_from_aggregate_risk(smart_data_json):
    minimum_security_risk_from_aggregate_attack_paths = -1   # Start with the assumption that NO security risk is present in the model, go up from there
    minimum_sr_aggregate__smart_file_entry = ''
    for smart_file_entry in smart_data_json:
        if float(smart_data_json[smart_file_entry][least_risky_subpath__min_sr_subpath_aggregate_cost]) > minimum_security_risk_from_aggregate_attack_paths:
            minimum_security_risk_from_aggregate_attack_paths = float(smart_data_json[smart_file_entry][least_risky_subpath__min_sr_subpath_aggregate_cost])
            minimum_sr_aggregate__smart_file_entry = smart_file_entry
    return minimum_security_risk_from_aggregate_attack_paths, minimum_sr_aggregate__smart_file_entry

## Function for finding all SMART summary files that have a single attack path maximum security risk that is in the top 5% of results
def find_and_return__top_5_percent_max_security_risk_attack_path_models(smart_data_json, maximum_security_risk_from_single_attack_path):
    # Easy check that the maximum security risk  provided in non-zero; because otherwise this gets pointless
    if maximum_security_risk_from_single_attack_path == 0:
        print("[!] ERROR: Failure.... Maximum value pased was zero.... Freakout time!")
        exit()
    else:
        if debugBit != 0:
            print("\tValid Maximum Security Risk was passed to the function")
    # Determine what 5% of the max SR is
    five_percent_of_total = maximum_security_risk_from_single_attack_path * 0.05
    # Get the lower limit to search for
    lower_limit = maximum_security_risk_from_single_attack_path - five_percent_of_total
    return lower_limit

## Function for finding and returning the associated attack path combinations with devices
def find_and_return__attack_path_device_element_combinations(smart_data_json, smart_file_entry):
    if smart_file_entry == '':
        return None
    else:
        return smart_data_json[smart_file_entry][attack_path_combinations_with_device_elements]

## Function for tracking and extracting key variables from the original SMART JSON structure
#   - NOTE: Since this function will return a separate Min / Max then for every SINGLE ENTRY provided the function will RETURN FIVE DATA from the inquiry
def find_and_return__min_and_max_tuple_information(smart_data_json, smart_file_entry):
    ## Testing input to this function
    if debugBit != 0:   # ~!~
        print("SMART File Entry Name:\t{0}".format(smart_file_entry))
        if smart_file_entry != '':
            print("SMART File Entry:\t{0}".format(smart_data_json[smart_file_entry]))
    ## Check that a viable smart_file_entry was provided
    if smart_file_entry == '':      # NOTE: This scenario should not happen....
        max_tuple__subpath_security_risk_aggregate = None
        max_tuple__subpath_security_risk__max_single_path = None
        max_tuple__subpath_security_risk_item__max_single_path = None
        max_tuple__subpath_security_risk__min_single_path = None
        max_tuple__subpath_security_risk_item__min_single_path = None
        min_tuple__subpath_security_risk_aggregate = None
        min_tuple__subpath_security_risk__max_single_path = None
        min_tuple__subpath_security_risk_item__max_single_path = None
        min_tuple__subpath_security_risk__min_single_path = None
        min_tuple__subpath_security_risk_item__min_single_path = None
    else:
        ## Setup the variables
        # Find the Min and Max variables within the SMART JSON structure for the provided smart_file_entry
        #   - NOTE: At this point the extraction is a type string... Will need to convert into a list or set
        max_smart_subpath_tuple = make_tuple(smart_data_json[smart_file_entry][most_risky_subpath_tuple])
        min_smart_subpath_tuple = make_tuple(smart_data_json[smart_file_entry][least_risky_subpath_tuple])
        ## Extract out the tuple variable information from the SMART entries for Min and Max Attack Scenarios
        max_tuple__subpath_security_risk_aggregate, max_tuple__subpath_security_risk__max_single_path, max_tuple__subpath_security_risk_item__max_single_path, max_tuple__subpath_security_risk__min_single_path, max_tuple__subpath_security_risk_item__min_single_path = read_and_return__smart_tuple_variable_extraction(max_smart_subpath_tuple)
        min_tuple__subpath_security_risk_aggregate, min_tuple__subpath_security_risk__max_single_path, min_tuple__subpath_security_risk_item__max_single_path, min_tuple__subpath_security_risk__min_single_path, min_tuple__subpath_security_risk_item__min_single_path = read_and_return__smart_tuple_variable_extraction(min_smart_subpath_tuple)
    # Return the results
    return max_tuple__subpath_security_risk_aggregate, max_tuple__subpath_security_risk__max_single_path, max_tuple__subpath_security_risk_item__max_single_path, max_tuple__subpath_security_risk__min_single_path, max_tuple__subpath_security_risk_item__min_single_path, min_tuple__subpath_security_risk_aggregate, min_tuple__subpath_security_risk__max_single_path, min_tuple__subpath_security_risk_item__max_single_path, min_tuple__subpath_security_risk__min_single_path, min_tuple__subpath_security_risk_item__min_single_path

## Function for printing out the Min/Max Tuple information (NOTE: Purpose is to be coupled with the find_and_return__summary_of_smart_files() function for printing inside of that function's print statements
def find_and_pretty_print__min_and_max_tuple_information(smart_data_json, smart_file_entry):
    ## Gather the variables used for the print statements
    max_tuple__subpath_security_risk_aggregate, max_tuple__subpath_security_risk__max_single_path, max_tuple__subpath_security_risk_item__max_single_path, max_tuple__subpath_security_risk__min_single_path, max_tuple__subpath_security_risk_item__min_single_path, min_tuple__subpath_security_risk_aggregate, min_tuple__subpath_security_risk__max_single_path, min_tuple__subpath_security_risk_item__max_single_path, min_tuple__subpath_security_risk__min_single_path, min_tuple__subpath_security_risk_item__min_single_path = find_and_return__min_and_max_tuple_information(smart_data_json, smart_file_entry)
    # Begin the printing statements
    print("\t\t\t\t-=-=-=-=-=-=-\t\t\t\t\t-=-=-=-=-=-=-")
    print("\t\tMax Tuple - Maximum Subpath Security Risk - Aggregate Model Risk:\t\t{0}".format(max_tuple__subpath_security_risk_aggregate))
    print("\t\tMax Tuple - Maximum Subpath Security Risk - Single Attack Path:\t\t\t{0}".format(max_tuple__subpath_security_risk__max_single_path))
    print("\t\tMax Tuple - Maximum Subpath Security Risk Item - Single Attack Path:\t\t{0}".format(max_tuple__subpath_security_risk_item__max_single_path))
    print("\t\tMax Tuple - Minimum Subpath Security Risk - Single Attack Path:\t\t\t{0}".format(max_tuple__subpath_security_risk__min_single_path))
    print("\t\tMax Tuple - Minimum Subpath Security Risk Item - Single Attack Path:\t\t{0}".format(max_tuple__subpath_security_risk_item__min_single_path))
    print("\t\t\t\t-=-=-=-=-=-=-\t\t\t\t\t-=-=-=-=-=-=-")
    print("\t\tMin Tuple - Maximum Subpath Security Risk - Aggregate Model Risk:\t\t{0}".format(min_tuple__subpath_security_risk_aggregate))
    print("\t\tMin Tuple - Maximum Subpath Security Risk - Single Attack Path:\t\t\t{0}".format(min_tuple__subpath_security_risk__max_single_path))
    print("\t\tMin Tuple - Maximum Subpath Security Risk Item - Single Attack Path:\t\t{0}".format(min_tuple__subpath_security_risk_item__max_single_path))
    print("\t\tMin Tuple - Minimum Subpath Security Risk - Single Attack Path:\t\t\t{0}".format(min_tuple__subpath_security_risk__min_single_path))
    print("\t\tMin Tuple - Minimum Subpath Security Risk Item - Single Attack Path:\t\t{0}".format(min_tuple__subpath_security_risk_item__min_single_path))

## Function for finding and printing out a summary of the provided SMART JSON structure
def find_and_return__summary_of_smart_files(smart_data_json):
    ## Creating variables for the function
    number_of_smart_files = len(smart_data_json)
    # Min / Max from Single Attack Path
    maximum_seen_security_risk__single_attack_path, maximum_seen_sr_single_path__smart_file_entry = read_and_return__maximum_security_risk_from_attack_path(smart_data_json)
    minimum_seen_security_risk__single_attack_path, minimum_seen_sr_single_path__smart_file_entry = read_and_return__minimum_security_risk_from_attack_path(smart_data_json)
    # Min / Max from Aggregate Security Risk
    maximum_seen_security_risk__aggregate_model_risk, maximum_seen_sr_aggregate__smart_file_entry = read_and_return__maximum_security_risk_from_aggregate_risk(smart_data_json)
    minimum_seen_security_risk__aggregate_model_risk, minimum_seen_sr_aggregate__smart_file_entry = read_and_return__minimum_security_risk_from_aggregate_risk(smart_data_json)
    # Min / Max Number of Attack Paths from Models
    maximum_number_of_attack_paths_seen, maximum_number_attack_paths_seen__smart_file_entry = read_and_return__maximum_number_of_model_attack_paths(smart_data_json)
    minimum_number_of_attack_paths_seen, minimum_number_attack_paths_seen__smart_file_entry = read_and_return__minimum_number_of_model_attack_paths(smart_data_json)
    # Extracting the Attack Path Device Combinations for the Min / Max Number of Attack Paths from Models
    maximum_attack_paths_seen__device_combinations = find_and_return__attack_path_device_element_combinations(smart_data_json, maximum_number_attack_paths_seen__smart_file_entry)
    minimum_attack_paths_seen__device_combinations = find_and_return__attack_path_device_element_combinations(smart_data_json, minimum_number_attack_paths_seen__smart_file_entry)
    ## Printing out the summary informaiton to the screen
    print("[*] ======================== Summary of [ {0} ] SMART output files ====================== [*]".format(len(smart_data_json)))
    print("\tMaximum Amount of Security Risk for a Single Design - Single Attack Path:\t{0}".format(maximum_seen_security_risk__single_attack_path))
    find_and_pretty_print__min_and_max_tuple_information(smart_data_json, maximum_seen_sr_single_path__smart_file_entry)
    print("\tMinimum Amount of Security Risk for a Single Design - Single Attack Path:\t{0}".format(minimum_seen_security_risk__single_attack_path))
    find_and_pretty_print__min_and_max_tuple_information(smart_data_json, minimum_seen_sr_single_path__smart_file_entry)
    print("\t----------\t-----------\t----------\t---------------\t-----------------------------\t")
    print("\tMaximum Amount of Security Risk for a Single Design - Aggregate Model Risk:\t{0}".format(maximum_seen_security_risk__aggregate_model_risk))
    find_and_pretty_print__min_and_max_tuple_information(smart_data_json, maximum_seen_sr_aggregate__smart_file_entry)
    print("\tMinimum Amount of Security Risk for a Single Design - Aggregate Model Risk:\t{0}".format(minimum_seen_security_risk__aggregate_model_risk))
    find_and_pretty_print__min_and_max_tuple_information(smart_data_json, minimum_seen_sr_aggregate__smart_file_entry)
    print("\t----------\t-----------\t----------\t---------------\t-----------------------------\t")
    print("\tMaximum Number of Attack Paths for a Single Design:\t\t\t\t{0}".format(maximum_number_of_attack_paths_seen))
    print("\t\tAssociated Attack Path Device Combinations:\t\t{0}".format(maximum_attack_paths_seen__device_combinations))
    print("\tMinimum Number of Attack Paths for a Single Design:\t\t\t\t{0}".format(minimum_number_of_attack_paths_seen))
    print("\t\tAssociated Attack Path Device Combinations:\t\t{0}".format(minimum_attack_paths_seen__device_combinations))
    print("[+] ===================================================================================== [+]")

### Main Code

## Gathering the local directory files and searching for SMART output files
# Create variable for the list of smart files
smart_file_list = []
# Search the local directory for SMART files
for localFile in os.listdir():
    # Check if the file is a SMART output file
    if localFile.endswith(".smart"):
        if debugBit != 0:
            print("File:\t{0}".format(localFile))
        smart_file_list.append(localFile)
# Check to make sure that some SMART files were found
if not smart_file_list:
    # Scenario where no SMART files were found... Alert the user and have them re-run the analysis script
    print("[-] ERROR: No SMART output files were found.... Exiting....")
    exit()
else:
    print("[+] Found [ {0} ] number of SMART output files in the local directory".format(len(smart_file_list)))

## Now that we have a list of SMART files, time to dissect and extract their contents
#   - TODO: Update the code below to:
#       - Structure that contains a list of the filenames : associated_smart_data

smart_file_data_gathering = {}
interesting_smart_files = []
interesting_low_files = []

## Loop through the known SMART files and gather the information
for smart_file_location in smart_file_list:
    extracted_smart_data = read_and_return__smart_output_variables_json(smart_file_location)
    smart_file_data_gathering[smart_file_location] = extracted_smart_data

if debugBit != 0:
    print("Contents of the SMART data gathering:\n{0}".format(smart_file_data_gathering))

## Search through the outputs from the SMART files to find:
#   - Non-zero risk contributions 
#       -> High cost attack paths
#       -> Low cost attack paths
#   - Most attack paths
for smart_file_entry in smart_file_data_gathering:
    if float(smart_file_data_gathering[smart_file_entry][most_risky_subpath__max_sr_subpath_security_risk_cost]) != 0:
        if debugBit != 0:
            print("Oh shit... Look at the file [ {0} ]".format(smart_file_entry))
            print("\tInfo:\t{0}".format(smart_file_data_gathering[smart_file_entry][most_risky_subpath__max_sr_subpath_security_risk_cost]))
            print("\t\tType:\t{0}".format(type(smart_file_data_gathering[smart_file_entry][most_risky_subpath__max_sr_subpath_security_risk_cost])))
        if smart_file_entry not in interesting_smart_files:
            interesting_smart_files.append(smart_file_entry)
    if float(smart_file_data_gathering[smart_file_entry][least_risky_subpath__min_sr_subpath_security_risk_cost]) != 0:
        print("Woh.... Non-zero min attack path... Look at the file [ {0} ]".format(smart_file_entry))
        if smart_file_entry not in interesting_smart_files:
            interesting_smart_files.append(smart_file_entry)
        interesting_low_files.append(smart_file_entry)
## Print out the list of files that were found
print("Smart Files of interest:")
for interesting_file in interesting_smart_files:
    print("\t{0}".format(interesting_file))
print("Smart Files of interest - Low Numbers:")
if interesting_low_files != None:
    for interesting_file in interesting_low_files:
        print("\t{0}".format(interesting_file))
else:
    print("\tNone Found")


find_and_return__summary_of_smart_files(smart_file_data_gathering)

## TODO: Setup code so that with each set of variables extracted from the file we also couple the filename
#   - Include:
#       - Attack path information?
#       - Attack path CVEs?
#       - Asset of Importance?
#       - Model Filename
#   => Look into adding the 5% bit to SMART
