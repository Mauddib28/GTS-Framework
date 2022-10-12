###
#   The purpose of this code is to generate AADL model files using a series of functions for generating the necessary
#       i)      system
#       ii)     device
#       iii)    data
#       iv)     bus
#   elements, while either based on expected designs OR using user input to refine these models
#
#   Begin with Scenario #1 AADL design generation:  single || double machine design with protected information; Note: security is optional
#
#
#   Author:     Paul A. Wortman
#   Last Edit:  3/25/2022
#
#
#   TODO:
#       [x] Have GAM produce the new Smart Home Model
#           [ ] One Path (Simplest Version)     -   Database to GUI (No Sensors)
#           [ ] Two Path (Multiple Leaves)      -   Database to GUI and Sensor (One Data Type)
#           [x] Three Path (Multiple Entry)     -   Database to GUI, Sensor, and Application (Any Data Type)
#       [ ] Determine naming scheme for Smart Home Model AADL model
#           - Need to figure out a good method by which the various models will be generated and then fed into TAMSAT + SMART
#       [ ] Create a Class (?) for Generating each model set
#       [ ] Add in logic to check DURING THE GENERATION PROCESS if devices being added to the model have the correct / corresponding bus
#           - Ex: BreeZ Sensor being generated with a Zigbee Bus; SHOULD be a BreeZ Bus - Scenario #5
#       [ ] Create master function for generating a SMART HOME MODEL and have the input be the list of devices paired with the approriate bus (???)
#           -> Need a way to present the correct devices with their paired hardware requires as a series of inputs to the GAM (NOTA BENE: These are essentially the translated user requirements)
#           - Could create a set of master variables that are passed into the smart home model generation function, that way minimal changes need to be made and everything can be a set of preliminary variables
#       [x] Add in a Smart Home variant that includes use of a MySQL database
#       [ ] Make the user_pattern variable a global variable (e.g. user_pattern = '^user_')
#       [ ] Place all initial GAM variable generation and user input reading into a single function
#
# WE HAVE ACHIEVED FULL FRAMEWORK FUNCTIONALITY.... Now lets thread this frankenstein's monster together
###

'''
                # Variable that contains the AoI that will be searched for | Old default set to 'database'
                aoi = '' #'database'    # Will ask the user based on a preset list of items what the AoI should be | Right now set to default based on expected model
                # Create list of unique elements seen in nodes
                uniqueList = []
                for subList in foundPaths:
                    for item in subList:
                        if item not in {"Entry", "Exit"} and item not in uniqueList:    # Check that the item is not 'Entry', 'Exit', or already added to the unique list
                            uniqueList.append(item)
                # Ask the user what the Asset of Importance (aoi) will be
                print('Which of the following items is the Asset of Importance? (e.g. the item being protected)')
                for item in uniqueList:
                    print("\t{0}".format(item))
                while aoi not in uniqueList:            # Keep looping until the user response is in the uniqueList of node items
                    aoi = input('Please enter the Asset of Importance: ')


    # Create the file that the attack tree will be put into
    #attacktreeFile = open("generated.attacktree","w+")
    attacktreeFile = open(outputFile,"w+")
    # Write attacktree file header
    attacktreeFile.write('<?xml version="1.0" encoding="UTF-8"?>\n')      # NOTE: Use of ' character to escape " in strings
'''

### Import

import json                 # Creating GAM structures
import re                   # Text search
import itertools            # Creating combination sets
import random               # Selecting random subsets for testing
import argparse             # Import for having import variable parsing
import os                   # Mainly used for debugging the working directory

### Globals
debugBit = 0
developmentMode = 0     # ~!~ Flag to use the smaller sample of combination sets for the purpose of code development

### Functions

## Functions for writing comments into the AADL model file
# Function for writing basic comment within an AADL file
def generate_aadl_comment(outfile, commentContent, indentLevel=1):
    if debugBit != 0:
        print("[*] Generating AADL model file comment [ {0} ]".format(commentContent))
    #busName = "bluetooth"
    aadlFile = open(outfile, "a")
    for i in range(indentLevel):        # Note: The default value for indentLevel is 1
        aadlFile.write('\t')
    aadlFile.write('-- {0}\n'.format(commentContent))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating comment for AADL model file")

## Functions for writing the opening and closing header of the AADL model file
# Function for writing the opening/beginning header of the AADL design file
def genOpenHeader(packageName, outfile):
    if debugBit != 0:
        print("[*] Generating header for AADL design file")
    aadlFile = open(outfile, "w+")                              # Note: Use of "w+" here since this will write and truncate the file (e.g. delete old contents if same file name exists)
    aadlFile.write('package {0}\n'.format(packageName))         # Note: Use of ' character to escape " in strings
    aadlFile.write('public\n')
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating the opening AADL design file header")

# Function for writing the closing header of the design file
def genEndHeader(packageName, outfile):
    if debugBit != 0:
        print("[*] Generating tail of the AADL design file")
    aadlFile = open(outfile, "a")
    aadlFile.write('end {0};\n'.format(packageName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating the AADL closing AADL design file header")

## Functions for odd needs; e.g. adding in empty lines
# Function for adding an empty line to the AADL model file
def addEmptyLine(outfile):
    if debugBit != 0:
        print("[*] Adding an empty line to the AADL model file")
    aadlFile = open(outfile, "a")
    aadlFile.write('\n')
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed adding the empty line to the AADL model file")

## Functions for writing the Bus and Data Definitions of the AADL model file
# Function for writing basic "wireless" bus medium
def genWirelessMedium_basic(outfile):
    if debugBit != 0:
        print("[*] Generating basic wireless bus medium for AADL model file")
    busName = "wireless"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tbus {0}\n'.format(busName))
    aadlFile.write('\tend {0};\n'.format(busName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic wireless bus medium for AADL model file")

# Function for writing basic "ethernet" bus medium
def genEthernetMedium_basic(outfile):
    if debugBit != 0:
        print("[*] Generating basic ethernet bus medium for AADL model file")
    busName = "ethernet"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tbus {0}\n'.format(busName))
    aadlFile.write('\tend {0};\n'.format(busName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic ethernet bus medium for AADL model file")

# Function for writing basic "bluetooth" bus medium
def genBluetoothMedium_basic(outfile):
    if debugBit != 0:
        print("[*] Generating basic ethernet bus medium for AADL model file")
    busName = "bluetooth"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tbus {0}\n'.format(busName))
    aadlFile.write('\tend {0};\n'.format(busName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic ethernet bus medium for AADL model file")

# Function for writing basic bus medium using a given medium type (e.g. ethernet, wireless, bluetooth, zigbee)
def generate_bus_medium_basic(outfile, busName):
    if debugBit != 0:
        print("[*] Generating basic ethernet bus medium for AADL model file")
    #busName = "bluetooth"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tbus {0}\n'.format(busName))
    aadlFile.write('\tend {0};\n'.format(busName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic ethernet bus medium for AADL model file")

# Function for writing basic "request" type data
def genRequestData_basic(outfile):
    if debugBit != 0:
        print("[*] Generating basic request type data for AADL model file")
    dataName = "request"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdata {0}\n'.format(dataName))
    aadlFile.write('\tend {0};\n'.format(dataName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic request type data for AADL model file")

# Function for writing basic "response" type data
def genResponseData_basic(outfile):
    if debugBit != 0:
        print("[*] Generating basic response type data for AADL model file")
    dataName = "response"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdata {0}\n'.format(dataName))
    aadlFile.write('\tend {0};\n'.format(dataName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic response type data for AADL model file")

# Function for writing basic "plaintext" type data
def genPlaintextData_basic(outfile):
    if debugBit != 0:
        print("[*] Generating basic plaintext type data for AADL model file")
    dataName = "plaintext"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdata {0}\n'.format(dataName))
    aadlFile.write('\tend {0};\n'.format(dataName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic plaintext type data for AADL model file")

# Function for writing basic "encrypted" type data
def genEncryptedData_basic(outfile):
    if debugBit != 0:
        print("[*] Generating basic encrypted type data for AADL model file")
    dataName = "encrypted"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdata {0}\n'.format(dataName))
    aadlFile.write('\tend {0};\n'.format(dataName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic encrypted data for AADL model file")

# Function for writing basic type data provided  (e.g. http, ssh, smb)
def generate_data_basic(outfile, dataName):
    if debugBit != 0:
        print("[*] Generating basic encrypted type data for AADL model file")
    #dataName = "encrypted"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdata {0}\n'.format(dataName))
    aadlFile.write('\tend {0};\n'.format(dataName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic encrypted data for AADL model file")

## Functions for writing of the Device Definitions of the AADL model file
# Function for writing a basic "firewall" device with "request"/"response" IN/OUT data
def genFirewallDevice_basic_reqResModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic firewall device that uses request/response type data for the AADL model file")
    # Variables for use with deviceName, dataType
    deviceName = "firewall"
    dataType_res = "response"
    dataType_req = "request"
    aadlFile = open(outfile, "a")
    # Define the firewall device
    aadlFile.write('\tdevice {0}\n'.format(deviceName))
    # Define the features of the firewall device
    aadlFile.write('\t\tfeatures\n')
    # Adding in the request/response data IN/OUT event ports
    aadlFile.write('\t\t\tuser_request : in event data port {0};\n'.format(dataType_req))
    aadlFile.write('\t\t\tdatabase_res : in event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tuser_response : out event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tdatabase_req : out event data port {0};\n'.format(dataType_req))
    # Define the flows of the firewall device
    aadlFile.write('\t\tflows\n')
    # Adding in the request/response flow SINK/SOURCE elements
    aadlFile.write('\t\t\tusr_req_sink : flow sink user_request;\n')
    aadlFile.write('\t\t\tdb_res_sink : flow sink database_res;\n')
    aadlFile.write('\t\t\tusr_res_src : flow source user_response;\n')
    aadlFile.write('\t\t\tdb_req_src : flow source database_req;\n')
    # Define the end of the firewall device
    aadlFile.write('\tend {0};\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic firewall device that uses request/response data for the AADL model file")

# Function for writing an implementation of the basic "firewall" device with "request"/"response" IN/OUT data
def genFirewallDevice_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic firewall device that uses request/response type data for the AADL model file")
    deviceName = "firewall"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdevice implementation {0}.simple\n'.format(deviceName))
    aadlFile.write('\tend {0}.simple;\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implementation of a basic firewall device that users request/response type data for the AADL model file")

# Function for writing a basic "firewall" device with "plaintext" IN/OUT data
def genFirewallDevice_basic_plaintextModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic firewall device that uses plaintext type data for the AADL model file")
    deviceName = "firewall"
    dataType_plaintext = "plaintext"
    aadlFile = open(outfile, "a")
    # Define the firewall device
    aadlFile.write('\tdevice {0}\n'.format(deviceName))
    # Define the features of the firewall device
    aadlFile.write('\t\tfeatures\n')
    # Adding in the plaintext data IN/OUT event ports
    aadlFile.write('\t\t\tuser_request : in event data port {0};\n'.format(dataType_plaintext))
    aadlFile.write('\t\t\tdatabase_res : in event data port {0};\n'.format(dataType_plaintext))
    aadlFile.write('\t\t\tuser_response : out event data port {0};\n'.format(dataType_plaintext))
    aadlFile.write('\t\t\tdatabase_req : out event data port {0};\n'.format(dataType_plaintext))
    # Define the flows of the firewall device
    aadlFile.write('\t\tflows\n')
    # Adding in the plaintext flow SINK/SOURCE elements
    aadlFile.write('\t\t\tusr_req_sink : flow sink user_request;\n')
    aadlFile.write('\t\t\tdb_res_sink : flow sink database_res;\n')
    aadlFile.write('\t\t\tusr_res_src : flow source user_response;\n')
    aadlFile.write('\t\t\tdb_req_src : flow source database_req;\n')
    # Define the end of the firewall device
    aadlFile.write('\tend {0};\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic firewall device that uses plaintext data for the AADL model file")

# Function for writing an implementation of the basic "firewall" device with "plaintext" IN/OUT data
def genFirewallDevice_basic_plaintextModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic firewall device that uses plaintext type data for the AADL model file")
    deviceName = "database"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdevice implementation {0}.simple\n'.format(deviceName))
    aadlFile.write('\tend {0}.simple;\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implementation of a basic firewall device that uses plaintext type data for the AADL model file")

# Function for writing a basic "firewall" device with "encrypted" IN/OUT data
def genFirewallDevice_basic_encryptedModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic firewall device that uses encrypted type data for the AADL model file")
    deviceName = "firewall"
    dataType_encrypted = "encrypted"
    aadlFile = open(outfile, "a")
    # Define the firewall device
    aadlFile.write('\tdevice {0}\n'.format(deviceName))
    # Define the features of the firewall device
    aadlFile.write('\t\tfeatures\n')
    # Adding in the encrypted data IN/OUT event ports
    aadlFile.write('\t\t\tuser_request : in event data port {0};\n'.format(dataType_encrypted))
    aadlFile.write('\t\t\tdatabase_res : in event data port {0};\n'.format(dataType_encrypted))
    aadlFile.write('\t\t\tuser_response : out event data port {0};\n'.format(dataType_encrypted))
    aadlFile.write('\t\t\tdatabase_req : out event data port {0};\n'.format(dataType_encrypted))
    # Define the flows of the firewall device
    aadlFile.write('\t\tflows\n')
    # Adding in the encrypted flow SINK/SOURCE elements
    aadlFile.write('\t\t\tusr_req_sink : flow sink user_request;\n')
    aadlFile.write('\t\t\tdb_res_sink : flow sink database_res;\n')
    aadlFile.write('\t\t\tusr_res_src : flow source user_response;\n')
    aadlFile.write('\t\t\tdb_req_src : flow source database_req;\n')
    # Define the end of the firewall device
    aadlFile.write('\tend {0};\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic firewall device that uses encrypted data for the AADL model file")

# Function for writing an implementation of the basic "firewall" device with "encrypted" IN/OUT data
def genFirewallDevice_basic_encryptedModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic firewall device that uses encrypted type data for the AADL model file")
    deviceName = "firewall"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdevice implementation {0}.simple\n'.format(deviceName))
    aadlFile.write('\tend {0}.simple;\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implementation of a basic firewall device that uses encrypted type data for the AADL model file")

# Function for writing a basic Cisco firewall device with "request"/"response" IN/OUT data
def genFirewallDevice_cisco_basic_reqResModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic Cisco firewall device that uses request/response type data for the AADL model file")
    # Variables for use with deviceName, dataType
    deviceName = "cisco"
    dataType_res = "response"
    dataType_req = "request"
    aadlFile = open(outfile, "a")
    # Define the cisco device
    aadlFile.write('\tdevice {0}\n'.format(deviceName))
    # Define the features of the cisco device
    aadlFile.write('\t\tfeatures\n')
    # Adding in the request/response data IN/OUT event ports
    aadlFile.write('\t\t\tuser_request : in event data port {0};\n'.format(dataType_req))
    aadlFile.write('\t\t\tdatabase_res : in event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tuser_response : out event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tdatabase_req : out event data port {0};\n'.format(dataType_req))
    # Define the flows of the cisco device
    aadlFile.write('\t\tflows\n')
    # Adding in the request/response flow SINK/SOURCE elements
    aadlFile.write('\t\t\tusr_req_sink : flow sink user_request;\n')
    aadlFile.write('\t\t\tdb_res_sink : flow sink database_res;\n')
    aadlFile.write('\t\t\tusr_res_src : flow source user_response;\n')
    aadlFile.write('\t\t\tdb_req_src : flow source database_req;\n')
    # Define the end of the cisco device
    aadlFile.write('\tend {0};\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic Cisco firewall device that uses request/response data for the AADL model file")

# Function for writing an implementation of the basic cisco firewall device with "request"/"response" IN/OUT data
def genFirewallDevice_cisco_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic Cisco firewall device that uses request/response type data for the AADL model file")
    deviceName = "cisco"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdevice implementation {0}.simple\n'.format(deviceName))
    aadlFile.write('\tend {0}.simple;\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implementation of a basic Cisco firewall device that users request/response type data for the AADL model file")

# Function for writing a basic Barracuda firewall device with "request"/"response" IN/OUT data
def genFirewallDevice_barracuda_basic_reqResModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic Barracuda firewall device that uses request/response type data for the AADL model file")
    # Variables for use with deviceName, dataType
    deviceName = "barracuda"
    dataType_res = "response"
    dataType_req = "request"
    aadlFile = open(outfile, "a")
    # Define the barracuda device
    aadlFile.write('\tdevice {0}\n'.format(deviceName))
    # Define the features of the barracuda device
    aadlFile.write('\t\tfeatures\n')
    # Adding in the request/response data IN/OUT event ports
    aadlFile.write('\t\t\tuser_request : in event data port {0};\n'.format(dataType_req))
    aadlFile.write('\t\t\tdatabase_res : in event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tuser_response : out event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tdatabase_req : out event data port {0};\n'.format(dataType_req))
    # Define the flows of the barracuda device
    aadlFile.write('\t\tflows\n')
    # Adding in the request/response flow SINK/SOURCE elements
    aadlFile.write('\t\t\tusr_req_sink : flow sink user_request;\n')
    aadlFile.write('\t\t\tdb_res_sink : flow sink database_res;\n')
    aadlFile.write('\t\t\tusr_res_src : flow source user_response;\n')
    aadlFile.write('\t\t\tdb_req_src : flow source database_req;\n')
    # Define the end of the barracuda device
    aadlFile.write('\tend {0};\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic Barracuda firewall device that uses request/response data for the AADL model file")

# Function for writing an implementation of the basic barracuda firewall device with "request"/"response" IN/OUT data
def genFirewallDevice_barracuda_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic Barracuda firewall device that uses request/response type data for the AADL model file")
    deviceName = "barracuda"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdevice implementation {0}.simple\n'.format(deviceName))
    aadlFile.write('\tend {0}.simple;\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implementation of a basic Barracuda firewall device that users request/response type data for the AADL model file")

# Function for writing a basic Fortinet firewall device with "request"/"response" IN/OUT data
def genFirewallDevice_fortinet_basic_reqResModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic Fortinet firewall device that uses request/response type data for the AADL model file")
    # Variables for use with deviceName, dataType
    deviceName = "fortinet"
    dataType_res = "response"
    dataType_req = "request"
    aadlFile = open(outfile, "a")
    # Define the fortinet device
    aadlFile.write('\tdevice {0}\n'.format(deviceName))
    # Define the features of the fortinet device
    aadlFile.write('\t\tfeatures\n')
    # Adding in the request/response data IN/OUT event ports
    aadlFile.write('\t\t\tuser_request : in event data port {0};\n'.format(dataType_req))
    aadlFile.write('\t\t\tdatabase_res : in event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tuser_response : out event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tdatabase_req : out event data port {0};\n'.format(dataType_req))
    # Define the flows of the fortinet device
    aadlFile.write('\t\tflows\n')
    # Adding in the request/response flow SINK/SOURCE elements
    aadlFile.write('\t\t\tusr_req_sink : flow sink user_request;\n')
    aadlFile.write('\t\t\tdb_res_sink : flow sink database_res;\n')
    aadlFile.write('\t\t\tusr_res_src : flow source user_response;\n')
    aadlFile.write('\t\t\tdb_req_src : flow source database_req;\n')
    # Define the end of the fortinet device
    aadlFile.write('\tend {0};\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic Fortinet firewall device that uses request/response data for the AADL model file")

# Function for writing an implementation of the basic fortinet firewall device with "request"/"response" IN/OUT data
def genFirewallDevice_fortinet_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic Fortinet firewall device that uses request/response type data for the AADL model file")
    deviceName = "fortinet"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdevice implementation {0}.simple\n'.format(deviceName))
    aadlFile.write('\tend {0}.simple;\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implementation of a basic Fortinet firewall device that users request/response type data for the AADL model file")

# Function for writing a basic Juniper firewall device with "request"/"response" IN/OUT data
def genFirewallDevice_juniper_basic_reqResModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic Juniper firewall device that uses request/response type data for the AADL model file")
    # Variables for use with deviceName, dataType
    deviceName = "juniper"
    dataType_res = "response"
    dataType_req = "request"
    aadlFile = open(outfile, "a")
    # Define the juniper device
    aadlFile.write('\tdevice {0}\n'.format(deviceName))
    # Define the features of the juniper device
    aadlFile.write('\t\tfeatures\n')
    # Adding in the request/response data IN/OUT event ports
    aadlFile.write('\t\t\tuser_request : in event data port {0};\n'.format(dataType_req))
    aadlFile.write('\t\t\tdatabase_res : in event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tuser_response : out event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tdatabase_req : out event data port {0};\n'.format(dataType_req))
    # Define the flows of the juniper device
    aadlFile.write('\t\tflows\n')
    # Adding in the request/response flow SINK/SOURCE elements
    aadlFile.write('\t\t\tusr_req_sink : flow sink user_request;\n')
    aadlFile.write('\t\t\tdb_res_sink : flow sink database_res;\n')
    aadlFile.write('\t\t\tusr_res_src : flow source user_response;\n')
    aadlFile.write('\t\t\tdb_req_src : flow source database_req;\n')
    # Define the end of the juniper device
    aadlFile.write('\tend {0};\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic Juniper firewall device that uses request/response data for the AADL model file")

# Function for writing an implementation of the basic juniper firewall device with "request"/"response" IN/OUT data
def genFirewallDevice_juniper_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic Juniper firewall device that uses request/response type data for the AADL model file")
    deviceName = "juniper"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdevice implementation {0}.simple\n'.format(deviceName))
    aadlFile.write('\tend {0}.simple;\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implementation of a basic Juniper firewall device that users request/response type data for the AADL model file")

# Function for writing a basic Meraki firewall device with "request"/"response" IN/OUT data
def genFirewallDevice_meraki_basic_reqResModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic Meraki firewall device that uses request/response type data for the AADL model file")
    # Variables for use with deviceName, dataType
    deviceName = "meraki"
    dataType_res = "response"
    dataType_req = "request"
    aadlFile = open(outfile, "a")
    # Define the meraki device
    aadlFile.write('\tdevice {0}\n'.format(deviceName))
    # Define the features of the meraki device
    aadlFile.write('\t\tfeatures\n')
    # Adding in the request/response data IN/OUT event ports
    aadlFile.write('\t\t\tuser_request : in event data port {0};\n'.format(dataType_req))
    aadlFile.write('\t\t\tdatabase_res : in event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tuser_response : out event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tdatabase_req : out event data port {0};\n'.format(dataType_req))
    # Define the flows of the meraki device
    aadlFile.write('\t\tflows\n')
    # Adding in the request/response flow SINK/SOURCE elements
    aadlFile.write('\t\t\tusr_req_sink : flow sink user_request;\n')
    aadlFile.write('\t\t\tdb_res_sink : flow sink database_res;\n')
    aadlFile.write('\t\t\tusr_res_src : flow source user_response;\n')
    aadlFile.write('\t\t\tdb_req_src : flow source database_req;\n')
    # Define the end of the meraki device
    aadlFile.write('\tend {0};\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic Meraki firewall device that uses request/response data for the AADL model file")

# Function for writing an implementation of the basic meraki firewall device with "request"/"response" IN/OUT data
def genFirewallDevice_meraki_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic Meraki firewall device that uses request/response type data for the AADL model file")
    deviceName = "meraki"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdevice implementation {0}.simple\n'.format(deviceName))
    aadlFile.write('\tend {0}.simple;\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implementation of a basic Meraki firewall device that users request/response type data for the AADL model file")

# Function for writing a basic pfSense firewall device with "request"/"response" IN/OUT data
def genFirewallDevice_pfsense_basic_reqResModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic pfSense firewall device that uses request/response type data for the AADL model file")
    # Variables for use with deviceName, dataType
    deviceName = "pfsense"
    dataType_res = "response"
    dataType_req = "request"
    aadlFile = open(outfile, "a")
    # Define the pfsense device
    aadlFile.write('\tdevice {0}\n'.format(deviceName))
    # Define the features of the pfsense device
    aadlFile.write('\t\tfeatures\n')
    # Adding in the request/response data IN/OUT event ports
    aadlFile.write('\t\t\tuser_request : in event data port {0};\n'.format(dataType_req))
    aadlFile.write('\t\t\tdatabase_res : in event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tuser_response : out event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tdatabase_req : out event data port {0};\n'.format(dataType_req))
    # Define the flows of the pfsense device
    aadlFile.write('\t\tflows\n')
    # Adding in the request/response flow SINK/SOURCE elements
    aadlFile.write('\t\t\tusr_req_sink : flow sink user_request;\n')
    aadlFile.write('\t\t\tdb_res_sink : flow sink database_res;\n')
    aadlFile.write('\t\t\tusr_res_src : flow source user_response;\n')
    aadlFile.write('\t\t\tdb_req_src : flow source database_req;\n')
    # Define the end of the pfsense device
    aadlFile.write('\tend {0};\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic pfSense firewall device that uses request/response data for the AADL model file")

# Function for writing an implementation of the basic pfsense firewall device with "request"/"response" IN/OUT data
def genFirewallDevice_pfsense_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic pfSense firewall device that uses request/response type data for the AADL model file")
    deviceName = "pfsense"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdevice implementation {0}.simple\n'.format(deviceName))
    aadlFile.write('\tend {0}.simple;\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implementation of a basic pfSense firewall device that users request/response type data for the AADL model file")

# Function for writing a basic Sophos firewall device with "request"/"response" IN/OUT data
def genFirewallDevice_sophos_basic_reqResModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic Sophos firewall device that uses request/response type data for the AADL model file")
    # Variables for use with deviceName, dataType
    deviceName = "sophos"
    dataType_res = "response"
    dataType_req = "request"
    aadlFile = open(outfile, "a")
    # Define the sophos device
    aadlFile.write('\tdevice {0}\n'.format(deviceName))
    # Define the features of the sophos device
    aadlFile.write('\t\tfeatures\n')
    # Adding in the request/response data IN/OUT event ports
    aadlFile.write('\t\t\tuser_request : in event data port {0};\n'.format(dataType_req))
    aadlFile.write('\t\t\tdatabase_res : in event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tuser_response : out event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tdatabase_req : out event data port {0};\n'.format(dataType_req))
    # Define the flows of the sophos device
    aadlFile.write('\t\tflows\n')
    # Adding in the request/response flow SINK/SOURCE elements
    aadlFile.write('\t\t\tusr_req_sink : flow sink user_request;\n')
    aadlFile.write('\t\t\tdb_res_sink : flow sink database_res;\n')
    aadlFile.write('\t\t\tusr_res_src : flow source user_response;\n')
    aadlFile.write('\t\t\tdb_req_src : flow source database_req;\n')
    # Define the end of the sophos device
    aadlFile.write('\tend {0};\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic Sophos firewall device that uses request/response data for the AADL model file")

# Function for writing an implementation of the basic sophos firewall device with "request"/"response" IN/OUT data
def genFirewallDevice_sophos_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic Sophos firewall device that uses request/response type data for the AADL model file")
    deviceName = "sophos"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdevice implementation {0}.simple\n'.format(deviceName))
    aadlFile.write('\tend {0}.simple;\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implementation of a basic Sophos firewall device that users request/response type data for the AADL model file")

# Function for writing a basic SonicWall firewall device with "request"/"response" IN/OUT data
def genFirewallDevice_sonicwall_basic_reqResModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic SonicWall firewall device that uses request/response type data for the AADL model file")
    # Variables for use with deviceName, dataType
    deviceName = "sonicwall"
    dataType_res = "response"
    dataType_req = "request"
    aadlFile = open(outfile, "a")
    # Define the sonicwall device
    aadlFile.write('\tdevice {0}\n'.format(deviceName))
    # Define the features of the sonicwall device
    aadlFile.write('\t\tfeatures\n')
    # Adding in the request/response data IN/OUT event ports
    aadlFile.write('\t\t\tuser_request : in event data port {0};\n'.format(dataType_req))
    aadlFile.write('\t\t\tdatabase_res : in event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tuser_response : out event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tdatabase_req : out event data port {0};\n'.format(dataType_req))
    # Define the flows of the sonicwall device
    aadlFile.write('\t\tflows\n')
    # Adding in the request/response flow SINK/SOURCE elements
    aadlFile.write('\t\t\tusr_req_sink : flow sink user_request;\n')
    aadlFile.write('\t\t\tdb_res_sink : flow sink database_res;\n')
    aadlFile.write('\t\t\tusr_res_src : flow source user_response;\n')
    aadlFile.write('\t\t\tdb_req_src : flow source database_req;\n')
    # Define the end of the sonicwall device
    aadlFile.write('\tend {0};\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic SonicWall firewall device that uses request/response data for the AADL model file")

# Function for writing an implementation of the basic sonicwall firewall device with "request"/"response" IN/OUT data
def genFirewallDevice_sonicwall_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic SonicWall firewall device that uses request/response type data for the AADL model file")
    deviceName = "sonicwall"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdevice implementation {0}.simple\n'.format(deviceName))
    aadlFile.write('\tend {0}.simple;\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implementation of a basic SonicWall firewall device that users request/response type data for the AADL model file")

# Function for writing a basic user defined "firewall" device with "request"/"response" IN/OUT data
def genFirewallDevice_basic_user_defined_reqResModel(outfile, firewallType):
    if debugBit != 0:
        print("[*] Generating a basic {0} firewall device that uses request/response type data for the AADL model file".format(firewallType))
    # Variables for use with deviceName, dataType
    #deviceName = "firewall"
    deviceName = firewallType
    dataType_res = "response"
    dataType_req = "request"
    aadlFile = open(outfile, "a")
    # Define the firewall device
    aadlFile.write('\tdevice {0}\n'.format(deviceName))
    # Define the features of the firewall device
    aadlFile.write('\t\tfeatures\n')
    # Adding in the request/response data IN/OUT event ports
    aadlFile.write('\t\t\tuser_request : in event data port {0};\n'.format(dataType_req))
    aadlFile.write('\t\t\tdatabase_res : in event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tuser_response : out event data port {0};\n'.format(dataType_res))
    aadlFile.write('\t\t\tdatabase_req : out event data port {0};\n'.format(dataType_req))
    # Define the flows of the firewall device
    aadlFile.write('\t\tflows\n')
    # Adding in the request/response flow SINK/SOURCE elements
    aadlFile.write('\t\t\tusr_req_sink : flow sink user_request;\n')
    aadlFile.write('\t\t\tdb_res_sink : flow sink database_res;\n')
    aadlFile.write('\t\t\tusr_res_src : flow source user_response;\n')
    aadlFile.write('\t\t\tdb_req_src : flow source database_req;\n')
    # Define the end of the firewall device
    aadlFile.write('\tend {0};\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic {0} firewall device that uses request/response data for the AADL model file".format(firewallType))

# Function for writing an implementation of the basic "firewall" device with "request"/"response" IN/OUT data
def genFirewallDevice_basic_user_defined_reqResModel_implementation(outfile, firewallType):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic {0} firewall device that uses request/response type data for the AADL model file".format(firewallType))
    #deviceName = "firewall"
    deviceName = firewallType
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdevice implementation {0}.simple\n'.format(deviceName))
    aadlFile.write('\tend {0}.simple;\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implementation of a basic {0} firewall device that users request/response type data for the AADL model file".format(firewallType))


# Function for writing a basic "database" device with "request"/"response" IN/OUT data
def genDatabaseDevice_basic_reqResModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic database device that uses request/response type data for the AADL model file")
    deviceName = "database"
    dataType_res = "response"
    dataType_req = "request"
    aadlFile = open(outfile, "a")
    # Define the database device
    aadlFile.write('\tdevice {0}\n'.format(deviceName))
    # Define the features of the database device
    aadlFile.write('\t\tfeatures\n')
    # Adding in the request/response data IN/OUT event ports
    aadlFile.write('\t\t\tdatabase_request : in event data port {0};\n'.format(dataType_req))
    aadlFile.write('\t\t\tdatabase_response : out event data port {0};\n'.format(dataType_res))
    # Define the flows of the database device
    aadlFile.write('\t\tflows\n')
    # Adding in the request/response flow SINK/SOURCE elements
    aadlFile.write('\t\t\trequest_sink : flow sink database_request;\n')
    aadlFile.write('\t\t\tresponse_source : flow source database_response;\n')
    # Define the end of the firewall device
    aadlFile.write('\tend {0};\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic database device that uses request/response type data for the AADL model file")

# Function for writing an implementation of the basic "database" device with "request"/"response" IN/OUT data
def genDatabaseDevice_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic database device that uses request/response type data for the AADL model file")
    deviceName = "database"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdevice implementation {0}.simple\n'.format(deviceName))
    aadlFile.write('\tend {0}.simple;\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implementation of a basic database device that uses request/response type data for the AADL model file")

# Function for writing a basic "database" device with plaintext IN/OUT data
def genDatabaseDevice_basic_plaintextModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic database device that uses plaintext type data for the AADL model file")
    deviceName = "database"
    dataType_plaintext = "plaintext"
    aadlFile = open(outfile, "a")
    # Define the database device
    aadlFile.write('\tdevice {0}\n'.format(deviceName))
    # Define the features of the database device
    aadlFile.write('\t\tfeatures\n')
    # Adding in the plaintext data IN/OUT event ports
    aadlFile.write('\t\t\tdatabase_request : in event data port {0};\n'.format(dataType_plaintext))
    aadlFile.write('\t\t\tdatabase_response : out event data port {0};\n'.format(dataType_plaintext))
    # Define the flows of the database device
    aadlFile.write('\t\tflows\n')
    # Adding in the plaintext flow SINK/SOURCE elements
    aadlFile.write('\t\t\trequest_sink : flow sink database_request;\n')
    aadlFile.write('\t\t\tresponse_source : flow source database_response;\n')
    # Define the end of the database device
    aadlFile.write('\tend {0};\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic database device that uses plaintext type data for the AADL model file")

# Function for writing an implementation of a basic "database" device with plaintext IN/OUT data
def genDatabaseDevice_basic_plaintextModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic database device that uses plaintext type data for the AADL model file")
    deviceName = "database"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdevice implementation {0}.simple\n'.format(deviceName))
    aadlFile.write('\tend {0}.simple;\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implementaiton of a basic database device that uses plaintext type data for the AADL model file")

# Function for writing a basic "database" device with encrypted IN/OUT data
def genDatabaseDevice_basic_encryptedModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic database device that uses encrypted type data for the AADL model file")
    deviceName = "database"
    dataType_encrypted = "encrypted"
    aadlFile = open(outfile, "a")
    # Define the database device
    aadlFile.write('\tdevice {0}\n'.format(deviceName))
    # Define the features of the database device 
    aadlFile.write('\t\tfeatures\n')
    # Adding in the encrypted data IN/OUT event ports
    aadlFile.write('\t\t\tdatabase_request : in event data port {0};\n'.format(dataType_encrypted))
    aadlFile.write('\t\t\tdatabase_response : out event data port {0};\n'.format(dataType_encrypted))
    # Define the flows of the database device
    aadlFile.write('\t\tflows\n')
    # Adding in the encrypted flow SINK/SOURCE elements
    aadlFile.write('\t\t\trequest_sink : flow sink database_request;\n')
    aadlFile.write('\t\t\tresponse_source : flow source database_response;\n')
    # Define the end of the database device
    aadlFile.write('\tend {0};\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic database device that uses encrypted data for the AADL model file")

# Function for writing an implementation of a basic "database" with encrypted IN/OUT data
def genDatabaseDevice_basic_encryptedModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic database device that uses encrypted type data for the AADL model file")
    deviceName = "database"
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdevice implementation {0}.simple\n'.format(deviceName))
    aadlFile.write('\tend {0}.simple;\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implementation of a basic database device that uses encrypted type data for the AADL model file")

# Function for writing a basic user defined database type device with "request"/"response" IN/OUT data
def genDatabaseDevice_basic_user_defined_reqResModel(outfile, databaseType):
    if debugBit != 0:
        print("[*] Generating a basic {0} database device that uses request/response type data for the AADL model file".format(databaseType))
    #deviceName = "database"
    deviceName = databaseType
    dataType_res = "response"
    dataType_req = "request"
    aadlFile = open(outfile, "a")
    # Define the database device
    aadlFile.write('\tdevice {0}\n'.format(deviceName))
    # Define the features of the database device
    aadlFile.write('\t\tfeatures\n')
    # Adding in the request/response data IN/OUT event ports
    aadlFile.write('\t\t\tdatabase_request : in event data port {0};\n'.format(dataType_req))
    aadlFile.write('\t\t\tdatabase_response : out event data port {0};\n'.format(dataType_res))
    # Define the flows of the database device
    aadlFile.write('\t\tflows\n')
    # Adding in the request/response flow SINK/SOURCE elements
    aadlFile.write('\t\t\trequest_sink : flow sink database_request;\n')
    aadlFile.write('\t\t\tresponse_source : flow source database_response;\n')
    # Define the end of the firewall device
    aadlFile.write('\tend {0};\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic user defined {0} database device that uses request/response type data for the AADL model file".format(databaseType))

# Function for writing an implementation of the basic user defined database type device with "request"/"response" IN/OUT data
def genDatabaseDevice_basic_user_defined_reqResModel_implementation(outfile, databaseType):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic {0} database device that uses request/response type data for the AADL model file".format(databaseType))
    #deviceName = "database"
    deviceName = databaseType
    aadlFile = open(outfile, "a")
    aadlFile.write('\tdevice implementation {0}.simple\n'.format(deviceName))
    aadlFile.write('\tend {0}.simple;\n'.format(deviceName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implementation of a basic {0} database device that uses request/response type data for the AADL model file".format(databaseType))

## Functions for writing of the System Definitions of the AADL model file
# Function for writing a basic "databaseNetwork" system with request/response IN/OUT data
#   Note: This model makes use of two machines
def genDatabaseNetworkSystem_basic_reqResModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic database network system that uses request/response type data for the AADL model file")
    systemName = "databaseNetwork"
    dataType_req = "request"
    dataType_res = "response"
    aadlFile = open(outfile, "a")
    # Define the databaseNetwork system
    aadlFile.write('\tsystem {0}\n'.format(systemName))
    # Define the features of the databaseNetwork system
    aadlFile.write('\t\tfeatures\n')
    # Adding in the request/response data IN/OUT event ports
    aadlFile.write('\t\t\tuser_request : in event data port {0};\n'.format(dataType_req))
    aadlFile.write('\t\t\tuser_response : out event data port {0};\n'.format(dataType_res))
    # Define the flows of the databaseNetwork system
    aadlFile.write('\t\tflows\n')
    # Adding in the request/response flow SINK/SOURCE elements
    aadlFile.write('\t\t\tflow_request : flow sink user_request;\n')
    aadlFile.write('\t\t\tflow_response : flow source user_response;\n')
    # Define the end of the databaseNetwork system
    aadlFile.write('\tend {0};\n'.format(systemName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic database network system that uses request/response data for the AADL model file")

# Function for writing an implemtnation of a basic "databaseNetwork" with request/response IN/OUT data
#   Note: This model makes use of two machines
def genDatabaseNetworkSystem_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic database network system that uses request/response type data for the AADL model file")
    systemName = "databaseNetwork"
    deviceName_firewall = "firewall"
    deviceName_database = "database"
    aadlFile = open(outfile, "a")
    # Define the databaesNetwork system implementation
    aadlFile.write('\tsystem implementation {0}.simple\n'.format(systemName))
    # Define the subcomponents of the databaseNetwork system implementation
    aadlFile.write('\t\tsubcomponents\n')
    # Adding in the system element device implementations
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_database))
    # Define the connections of the databaseNetwork system implementation
    aadlFile.write('\t\tconnections\n')
    aadlFile.write('\t\t\t-- Logical Connections\n')
    # Adding in the Logical Connections between the databaseNetwork system elements
    # External Connections
    aadlFile.write('\t\t\tuser_req : port user_request -> system_{0}.user_request;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tuser_res : port system_{0}.user_response -> user_response;\n'.format(deviceName_firewall))
    # Internal Connections
    aadlFile.write('\t\t\tinternal_req : port system_{0}.database_req -> system_{1}.database_request;\n'.format(deviceName_firewall, deviceName_database))
    aadlFile.write('\t\t\tinternal_res : port system_{1}.database_response -> system_{0}.database_res;\n'.format(deviceName_firewall, deviceName_database))
    # Define the flows of the databaseNetwork system implementation
    aadlFile.write('\t\tflows\n')
    # Adding in the response/request flows between the databaseNetwork system elements
    aadlFile.write('\t\t\tflow_request : flow sink user_request -> user_req -> system_{0}.usr_req_sink;\n'.format(deviceName_firewall))     # Nota Bene: Because of AADL all these connected pieces must have DIFFERENT names??
    aadlFile.write('\t\t\tflow_response : flow source system_{0}.usr_res_src -> user_res -> user_response;\n'.format(deviceName_firewall))
    # Define the end of the databaseNetwork system
    aadlFile.write('\tend {0}.simple;\n'.format(systemName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implenentation of a basic database network system that uses request/response type data for the AADL model file")


# Function for writing an implemtnation of a basic "databaseNetwork" with request/response IN/OUT data
#   Note: This model makes use of two machines; using Cisco device
def genDatabaseNetworkSystem_cisco_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic database network system that uses request/response type data for the AADL model file")
    systemName = "databaseNetwork"
    deviceName_firewall = "cisco"
    deviceName_database = "database"
    aadlFile = open(outfile, "a")
    # Define the databaesNetwork system implementation
    aadlFile.write('\tsystem implementation {0}.simple\n'.format(systemName))
    # Define the subcomponents of the databaseNetwork system implementation
    aadlFile.write('\t\tsubcomponents\n')
    # Adding in the system element device implementations
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_database))
    # Define the connections of the databaseNetwork system implementation
    aadlFile.write('\t\tconnections\n')
    aadlFile.write('\t\t\t-- Logical Connections\n')
    # Adding in the Logical Connections between the databaseNetwork system elements
    # External Connections
    aadlFile.write('\t\t\tuser_req : port user_request -> system_{0}.user_request;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tuser_res : port system_{0}.user_response -> user_response;\n'.format(deviceName_firewall))
    # Internal Connections
    aadlFile.write('\t\t\tinternal_req : port system_{0}.database_req -> system_{1}.database_request;\n'.format(deviceName_firewall, deviceName_database))
    aadlFile.write('\t\t\tinternal_res : port system_{1}.database_response -> system_{0}.database_res;\n'.format(deviceName_firewall, deviceName_database))
    # Define the flows of the databaseNetwork system implementation
    aadlFile.write('\t\tflows\n')
    # Adding in the response/request flows between the databaseNetwork system elements
    aadlFile.write('\t\t\tflow_request : flow sink user_request -> user_req -> system_{0}.usr_req_sink;\n'.format(deviceName_firewall))     # Nota Bene: Because of AADL all these connected pieces must have DIFFERENT names??
    aadlFile.write('\t\t\tflow_response : flow source system_{0}.usr_res_src -> user_res -> user_response;\n'.format(deviceName_firewall))
    # Define the end of the databaseNetwork system
    aadlFile.write('\tend {0}.simple;\n'.format(systemName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implenentation of a basic Cisco database network system that uses request/response type data for the AADL model file")

# Function for writing an implemtnation of a basic "databaseNetwork" with request/response IN/OUT data
#   Note: This model makes use of two machines; using Barracuda device
def genDatabaseNetworkSystem_barracuda_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic database network system that uses request/response type data for the AADL model file")
    systemName = "databaseNetwork"
    deviceName_firewall = "barracuda"
    deviceName_database = "database"
    aadlFile = open(outfile, "a")
    # Define the databaesNetwork system implementation
    aadlFile.write('\tsystem implementation {0}.simple\n'.format(systemName))
    # Define the subcomponents of the databaseNetwork system implementation
    aadlFile.write('\t\tsubcomponents\n')
    # Adding in the system element device implementations
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_database))
    # Define the connections of the databaseNetwork system implementation
    aadlFile.write('\t\tconnections\n')
    aadlFile.write('\t\t\t-- Logical Connections\n')
    # Adding in the Logical Connections between the databaseNetwork system elements
    # External Connections
    aadlFile.write('\t\t\tuser_req : port user_request -> system_{0}.user_request;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tuser_res : port system_{0}.user_response -> user_response;\n'.format(deviceName_firewall))
    # Internal Connections
    aadlFile.write('\t\t\tinternal_req : port system_{0}.database_req -> system_{1}.database_request;\n'.format(deviceName_firewall, deviceName_database))
    aadlFile.write('\t\t\tinternal_res : port system_{1}.database_response -> system_{0}.database_res;\n'.format(deviceName_firewall, deviceName_database))
    # Define the flows of the databaseNetwork system implementation
    aadlFile.write('\t\tflows\n')
    # Adding in the response/request flows between the databaseNetwork system elements
    aadlFile.write('\t\t\tflow_request : flow sink user_request -> user_req -> system_{0}.usr_req_sink;\n'.format(deviceName_firewall))     # Nota Bene: Because of AADL all these connected pieces must have DIFFERENT names??
    aadlFile.write('\t\t\tflow_response : flow source system_{0}.usr_res_src -> user_res -> user_response;\n'.format(deviceName_firewall))
    # Define the end of the databaseNetwork system
    aadlFile.write('\tend {0}.simple;\n'.format(systemName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implenentation of a basic Barracuda database network system that uses request/response type data for the AADL model file")

# Function for writing an implemtnation of a basic "databaseNetwork" with request/response IN/OUT data
#   Note: This model makes use of two machines; using Fortinet device
def genDatabaseNetworkSystem_fortinet_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic database network system that uses request/response type data for the AADL model file")
    systemName = "databaseNetwork"
    deviceName_firewall = "fortinet"
    deviceName_database = "database"
    aadlFile = open(outfile, "a")
    # Define the databaesNetwork system implementation
    aadlFile.write('\tsystem implementation {0}.simple\n'.format(systemName))
    # Define the subcomponents of the databaseNetwork system implementation
    aadlFile.write('\t\tsubcomponents\n')
    # Adding in the system element device implementations
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_database))
    # Define the connections of the databaseNetwork system implementation
    aadlFile.write('\t\tconnections\n')
    aadlFile.write('\t\t\t-- Logical Connections\n')
    # Adding in the Logical Connections between the databaseNetwork system elements
    # External Connections
    aadlFile.write('\t\t\tuser_req : port user_request -> system_{0}.user_request;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tuser_res : port system_{0}.user_response -> user_response;\n'.format(deviceName_firewall))
    # Internal Connections
    aadlFile.write('\t\t\tinternal_req : port system_{0}.database_req -> system_{1}.database_request;\n'.format(deviceName_firewall, deviceName_database))
    aadlFile.write('\t\t\tinternal_res : port system_{1}.database_response -> system_{0}.database_res;\n'.format(deviceName_firewall, deviceName_database))
    # Define the flows of the databaseNetwork system implementation
    aadlFile.write('\t\tflows\n')
    # Adding in the response/request flows between the databaseNetwork system elements
    aadlFile.write('\t\t\tflow_request : flow sink user_request -> user_req -> system_{0}.usr_req_sink;\n'.format(deviceName_firewall))     # Nota Bene: Because of AADL all these connected pieces must have DIFFERENT names??
    aadlFile.write('\t\t\tflow_response : flow source system_{0}.usr_res_src -> user_res -> user_response;\n'.format(deviceName_firewall))
    # Define the end of the databaseNetwork system
    aadlFile.write('\tend {0}.simple;\n'.format(systemName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implenentation of a basic Fortinet database network system that uses request/response type data for the AADL model file")

# Function for writing an implemtnation of a basic "databaseNetwork" with request/response IN/OUT data
#   Note: This model makes use of two machines; using Juniper device
def genDatabaseNetworkSystem_juniper_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic database network system that uses request/response type data for the AADL model file")
    systemName = "databaseNetwork"
    deviceName_firewall = "juniper"
    deviceName_database = "database"
    aadlFile = open(outfile, "a")
    # Define the databaesNetwork system implementation
    aadlFile.write('\tsystem implementation {0}.simple\n'.format(systemName))
    # Define the subcomponents of the databaseNetwork system implementation
    aadlFile.write('\t\tsubcomponents\n')
    # Adding in the system element device implementations
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_database))
    # Define the connections of the databaseNetwork system implementation
    aadlFile.write('\t\tconnections\n')
    aadlFile.write('\t\t\t-- Logical Connections\n')
    # Adding in the Logical Connections between the databaseNetwork system elements
    # External Connections
    aadlFile.write('\t\t\tuser_req : port user_request -> system_{0}.user_request;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tuser_res : port system_{0}.user_response -> user_response;\n'.format(deviceName_firewall))
    # Internal Connections
    aadlFile.write('\t\t\tinternal_req : port system_{0}.database_req -> system_{1}.database_request;\n'.format(deviceName_firewall, deviceName_database))
    aadlFile.write('\t\t\tinternal_res : port system_{1}.database_response -> system_{0}.database_res;\n'.format(deviceName_firewall, deviceName_database))
    # Define the flows of the databaseNetwork system implementation
    aadlFile.write('\t\tflows\n')
    # Adding in the response/request flows between the databaseNetwork system elements
    aadlFile.write('\t\t\tflow_request : flow sink user_request -> user_req -> system_{0}.usr_req_sink;\n'.format(deviceName_firewall))     # Nota Bene: Because of AADL all these connected pieces must have DIFFERENT names??
    aadlFile.write('\t\t\tflow_response : flow source system_{0}.usr_res_src -> user_res -> user_response;\n'.format(deviceName_firewall))
    # Define the end of the databaseNetwork system
    aadlFile.write('\tend {0}.simple;\n'.format(systemName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implenentation of a basic Juniper database network system that uses request/response type data for the AADL model file")

# Function for writing an implemtnation of a basic "databaseNetwork" with request/response IN/OUT data
#   Note: This model makes use of two machines; using Meraki device
def genDatabaseNetworkSystem_meraki_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic database network system that uses request/response type data for the AADL model file")
    systemName = "databaseNetwork"
    deviceName_firewall = "meraki"
    deviceName_database = "database"
    aadlFile = open(outfile, "a")
    # Define the databaesNetwork system implementation
    aadlFile.write('\tsystem implementation {0}.simple\n'.format(systemName))
    # Define the subcomponents of the databaseNetwork system implementation
    aadlFile.write('\t\tsubcomponents\n')
    # Adding in the system element device implementations
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_database))
    # Define the connections of the databaseNetwork system implementation
    aadlFile.write('\t\tconnections\n')
    aadlFile.write('\t\t\t-- Logical Connections\n')
    # Adding in the Logical Connections between the databaseNetwork system elements
    # External Connections
    aadlFile.write('\t\t\tuser_req : port user_request -> system_{0}.user_request;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tuser_res : port system_{0}.user_response -> user_response;\n'.format(deviceName_firewall))
    # Internal Connections
    aadlFile.write('\t\t\tinternal_req : port system_{0}.database_req -> system_{1}.database_request;\n'.format(deviceName_firewall, deviceName_database))
    aadlFile.write('\t\t\tinternal_res : port system_{1}.database_response -> system_{0}.database_res;\n'.format(deviceName_firewall, deviceName_database))
    # Define the flows of the databaseNetwork system implementation
    aadlFile.write('\t\tflows\n')
    # Adding in the response/request flows between the databaseNetwork system elements
    aadlFile.write('\t\t\tflow_request : flow sink user_request -> user_req -> system_{0}.usr_req_sink;\n'.format(deviceName_firewall))     # Nota Bene: Because of AADL all these connected pieces must have DIFFERENT names??
    aadlFile.write('\t\t\tflow_response : flow source system_{0}.usr_res_src -> user_res -> user_response;\n'.format(deviceName_firewall))
    # Define the end of the databaseNetwork system
    aadlFile.write('\tend {0}.simple;\n'.format(systemName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implenentation of a basic Meraki database network system that uses request/response type data for the AADL model file")

# Function for writing an implemtnation of a basic "databaseNetwork" with request/response IN/OUT data
#   Note: This model makes use of two machines; using Fortinet device
def genDatabaseNetworkSystem_pfsense_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic database network system that uses request/response type data for the AADL model file")
    systemName = "databaseNetwork"
    deviceName_firewall = "pfsense"
    deviceName_database = "database"
    aadlFile = open(outfile, "a")
    # Define the databaesNetwork system implementation
    aadlFile.write('\tsystem implementation {0}.simple\n'.format(systemName))
    # Define the subcomponents of the databaseNetwork system implementation
    aadlFile.write('\t\tsubcomponents\n')
    # Adding in the system element device implementations
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_database))
    # Define the connections of the databaseNetwork system implementation
    aadlFile.write('\t\tconnections\n')
    aadlFile.write('\t\t\t-- Logical Connections\n')
    # Adding in the Logical Connections between the databaseNetwork system elements
    # External Connections
    aadlFile.write('\t\t\tuser_req : port user_request -> system_{0}.user_request;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tuser_res : port system_{0}.user_response -> user_response;\n'.format(deviceName_firewall))
    # Internal Connections
    aadlFile.write('\t\t\tinternal_req : port system_{0}.database_req -> system_{1}.database_request;\n'.format(deviceName_firewall, deviceName_database))
    aadlFile.write('\t\t\tinternal_res : port system_{1}.database_response -> system_{0}.database_res;\n'.format(deviceName_firewall, deviceName_database))
    # Define the flows of the databaseNetwork system implementation
    aadlFile.write('\t\tflows\n')
    # Adding in the response/request flows between the databaseNetwork system elements
    aadlFile.write('\t\t\tflow_request : flow sink user_request -> user_req -> system_{0}.usr_req_sink;\n'.format(deviceName_firewall))     # Nota Bene: Because of AADL all these connected pieces must have DIFFERENT names??
    aadlFile.write('\t\t\tflow_response : flow source system_{0}.usr_res_src -> user_res -> user_response;\n'.format(deviceName_firewall))
    # Define the end of the databaseNetwork system
    aadlFile.write('\tend {0}.simple;\n'.format(systemName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implenentation of a basic pfSense database network system that uses request/response type data for the AADL model file")

# Function for writing an implemtnation of a basic "databaseNetwork" with request/response IN/OUT data
#   Note: This model makes use of two machines; using Sophos device
def genDatabaseNetworkSystem_sophos_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic database network system that uses request/response type data for the AADL model file")
    systemName = "databaseNetwork"
    deviceName_firewall = "sophos"
    deviceName_database = "database"
    aadlFile = open(outfile, "a")
    # Define the databaesNetwork system implementation
    aadlFile.write('\tsystem implementation {0}.simple\n'.format(systemName))
    # Define the subcomponents of the databaseNetwork system implementation
    aadlFile.write('\t\tsubcomponents\n')
    # Adding in the system element device implementations
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_database))
    # Define the connections of the databaseNetwork system implementation
    aadlFile.write('\t\tconnections\n')
    aadlFile.write('\t\t\t-- Logical Connections\n')
    # Adding in the Logical Connections between the databaseNetwork system elements
    # External Connections
    aadlFile.write('\t\t\tuser_req : port user_request -> system_{0}.user_request;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tuser_res : port system_{0}.user_response -> user_response;\n'.format(deviceName_firewall))
    # Internal Connections
    aadlFile.write('\t\t\tinternal_req : port system_{0}.database_req -> system_{1}.database_request;\n'.format(deviceName_firewall, deviceName_database))
    aadlFile.write('\t\t\tinternal_res : port system_{1}.database_response -> system_{0}.database_res;\n'.format(deviceName_firewall, deviceName_database))
    # Define the flows of the databaseNetwork system implementation
    aadlFile.write('\t\tflows\n')
    # Adding in the response/request flows between the databaseNetwork system elements
    aadlFile.write('\t\t\tflow_request : flow sink user_request -> user_req -> system_{0}.usr_req_sink;\n'.format(deviceName_firewall))     # Nota Bene: Because of AADL all these connected pieces must have DIFFERENT names??
    aadlFile.write('\t\t\tflow_response : flow source system_{0}.usr_res_src -> user_res -> user_response;\n'.format(deviceName_firewall))
    # Define the end of the databaseNetwork system
    aadlFile.write('\tend {0}.simple;\n'.format(systemName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implenentation of a basic Sophos database network system that uses request/response type data for the AADL model file")

# Function for writing an implemtnation of a basic "databaseNetwork" with request/response IN/OUT data
#   Note: This model makes use of two machines; using SonicWall device
def genDatabaseNetworkSystem_sonicwall_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic database network system that uses request/response type data for the AADL model file")
    systemName = "databaseNetwork"
    deviceName_firewall = "sonicwall"
    deviceName_database = "database"
    aadlFile = open(outfile, "a")
    # Define the databaesNetwork system implementation
    aadlFile.write('\tsystem implementation {0}.simple\n'.format(systemName))
    # Define the subcomponents of the databaseNetwork system implementation
    aadlFile.write('\t\tsubcomponents\n')
    # Adding in the system element device implementations
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_database))
    # Define the connections of the databaseNetwork system implementation
    aadlFile.write('\t\tconnections\n')
    aadlFile.write('\t\t\t-- Logical Connections\n')
    # Adding in the Logical Connections between the databaseNetwork system elements
    # External Connections
    aadlFile.write('\t\t\tuser_req : port user_request -> system_{0}.user_request;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tuser_res : port system_{0}.user_response -> user_response;\n'.format(deviceName_firewall))
    # Internal Connections
    aadlFile.write('\t\t\tinternal_req : port system_{0}.database_req -> system_{1}.database_request;\n'.format(deviceName_firewall, deviceName_database))
    aadlFile.write('\t\t\tinternal_res : port system_{1}.database_response -> system_{0}.database_res;\n'.format(deviceName_firewall, deviceName_database))
    # Define the flows of the databaseNetwork system implementation
    aadlFile.write('\t\tflows\n')
    # Adding in the response/request flows between the databaseNetwork system elements
    aadlFile.write('\t\t\tflow_request : flow sink user_request -> user_req -> system_{0}.usr_req_sink;\n'.format(deviceName_firewall))     # Nota Bene: Because of AADL all these connected pieces must have DIFFERENT names??
    aadlFile.write('\t\t\tflow_response : flow source system_{0}.usr_res_src -> user_res -> user_response;\n'.format(deviceName_firewall))
    # Define the end of the databaseNetwork system
    aadlFile.write('\tend {0}.simple;\n'.format(systemName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implenentation of a basic SonicWall database network system that uses request/response type data for the AADL model file")

# Function for writing a basic "databaseNetwork" system with plaintext IN/OUT data
def genDatabaseNetworkSystem_basic_plaintextModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic database network system that uses plaintext type data for the AADL model file")
    systemName = "databaseNetwork"
    dataType_plaintext = "plaintext"
    aadlFile = open(outfile, "a")
    # Define the databaseNetwork system
    aadlFile.write('\tsystem {0}\n'.format(systemName))
    # Define the features of the databaseNetwork system
    aadlFile.write('\t\tfeatures\n')
    # Adding in the plaintext data IN/OUT event ports
    aadlFile.write('\t\t\tuser_request : in event data port {0};\n'.format(dataType_plaintext))
    aadlFile.write('\t\t\tuser_response : out event data port {0};\n'.format(dataType_plaintext))
    # Define the flows of the databaseNetwork system
    aadlFile.write('\t\tflows\n')
    # Adding in the plaintext flow SINK/SOURCE elements
    aadlFile.write('\t\t\tflow_request : flow sink user_request;\n')
    aadlFile.write('\t\t\tflow-response : flow source user_response;\n')
    # Define the end of the databaseNetwork system
    aadlFile.write('\tend {0};\n'.format(systemName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic database network system that uses plaintext type data for the AADL model file")

# Function for writing an implementation of a basic "databaseNetwork" with plaintext IN/OUT data
def genDatabaseNetworkSystem_basic_plaintextModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic database network system that uses plaintext type data for the AADL model file")
    systemName = "databaseNetwork"
    deviceName_firewall = "firewall"
    deviceName_database = "database"
    aadlFile = open(outfile, "a")
    # Define the databaesNetwork system implementation
    aadlFile.write('\tsystem implementation {0}.simple\n'.format(systemName))
    # Define the subcomponents of the databaseNetwork system implementation
    aadlFile.write('\t\tsubcomponents\n')
    # Adding in the system element device implementations
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_database))
    # Define the connections of the databaseNetwork system implementation
    aadlFile.write('\t\tconnections\n')
    aadlFile.write('\t\t\t-- Logical Connections\n')
    # Adding in the Logical Connections between the databaseNetwork system elements
    # External Connections
    aadlFile.write('\t\t\tuser_req : port user_request -> system_{0}.user_request;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tuser_res : port system_{0}.user_response -> user_response;\n'.format(deviceName_firewall))
    # Internal Connections
    aadlFile.write('\t\t\tinternal_req : port system_{0}.database_req -> system_{1}.database_request;\n'.format(deviceName_firewall, deviceName_database))
    aadlFile.write('\t\t\tinternal_res : port system_{1}.database_response -> system_{0}.database_res;\n'.format(deviceName_firewall, deviceName_database))
    # Define the flows of the databaseNetwork system implementation
    aadlFile.write('\t\tflows\n')
    # Adding in the response/request flows between the databaseNetwork system elements
    aadlFile.write('\t\t\tflow_request :  flow sink user_request -> user_req -> system_{0}.usr_req_sink;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tflow_response : flow source system_{0}.usr_res_src -> user_res -> user_response;\n'.format(deviceName_firewall))
    # Define the end of the databaseNetwork system
    aadlFile.write('\tend {0}.simple;\n'.format(systemName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implementation of a basic database network system that uses plaintext type data for the AADL model file")

# Function for writing a basic "databaseNetwork" system with encrypted IN/OUT data
def genDatabaseNetworkSystem_basic_encryptedModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic database network system that uses encrypted type data for the AADL model file")
    systemName = "databaseNetwork"
    dataType_encrypted = "encrypted"
    aadlFile = open(outfile, "a")
    # Define the databaseNetwork system
    aadlFile.write('\tsystem {0}\n'.format(systemName))
    # Define the features of the databaseNetwork system
    aadlFile.write('\t\tfeatures\n')
    # Adding in the encrypted data IN/OUT event ports
    aadlFile.write('\t\t\tuser_request : in event data port {0};\n'.format(dataType_encrypted))
    aadlFile.write('\t\t\tuser_response : out event data port {0};\n'.format(dataType_encrypted))
    # Define the flows of the databaseNetwork system
    aadlFile.write('\t\tflows\n')
    # Adding in the encrypted flow SINK/SOURCE elements
    aadlFile.write('\t\t\tflow_request : flow sink user_request;\n')
    aadlFile.write('\t\t\tflow_response : flow source user_response;\n')
    # Define the end of the databaseNetwork system
    aadlFile.write('\tend {0};\n'.format(systemName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating a basic database network system that uses encrypted type data for the AADL model file")

# Function for writing an implementation of a basic "databaesNetwork" with encrypted IN/OUT data
def genDatabaseNetworkSystem_basic_encryptedModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic database network system that uses encrypted type data for the AADL model file")
    systemName = "databaseNetwork"
    deviceName_firewall = "firewall"
    deviceName_database = "database"
    aadlFile = open(outfile, "a")
    # Define the databaesNetwork system implementation
    aadlFile.write('\tsystem implementation {0}.simple\n'.format(systemName))
    # Define the subcomponents of the databaseNetwork system implementation
    aadlFile.write('\t\tsubcomponents\n')
    # Adding in the system element device implementations
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_database))
    # Define the connections of the databaseNetwork system implementation
    aadlFile.write('\t\tconnections\n')
    aadlFile.write('\t\t\t-- Logical Connection\n')
    # Adding in the Logical Connections between the databaseNetwork system elements
    # External Connections
    aadlFile.write('\t\t\tuser_req : port user_request -> system_{0}.user_request;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tuser_res : port system_{0}.user_response -> user_response;\n'.format(deviceName_firewall))
    # Internal Connections
    aadlFile.write('\t\t\tinternal_req : port system_{0}.database_req -> system_{1}.database_request;\n'.format(deviceName_firewall, deviceName_database))
    aadlFile.write('\t\t\tinternal_res : port system_{1}.database_response -> system_{0}.database_res;\n'.format(deviceName_firewall, deviceName_database))
    # Define the flows of the databaseNetwork system implementation
    aadlFile.write('\t\tflows\n')
    # Adding in the response/request flows between the databaseNetwork system elements
    aadlFile.write('\t\t\tflow_request : flow sink user_request -> user_req -> system_{0}.usr_req_sink;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tflow_response : flow source system_{0}.usr_res_src -> user_res -> user_response;\n'.format(deviceName_firewall))
    # Define the end of the databaseNetwork system
    aadlFile.write('\tend {0}.simple;\n'.format(systemName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating an implementation of a basic database network system that uses encrypted type data for the AADL model file")

# Function for writing a basic "databaseServer" system with request/response IN/OUT data
#   Note: This model makes use of one machine                       || Nota Bene: Need to fix the below for a single machine system
def genDatabaseServerSystem_basic_reqResModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic database server system that uses request/response type data for the AADL model file")
    systemName = "databaseServer"
    dataType_req = "request"
    dataType_res = "response"
    aadlFile = open(outfile, "a")
    # Define the databaseServer system
    aadlFile.write('\tsystem {0}\n'.format(systemName))
    # Define the features of the databaseServer system
    aadlFile.write('\t\tfeatures\n')
    # Adding in the request/response data IN/OUT event ports
    aadlFile.write('\t\t\tuser_request : in event data port {0};\n'.format(dataType_req))
    aadlFile.write('\t\t\tuser_response : out event data port {0};\n'.format(dataType_res))
    # Define the flows of the databaseServer system
    aadlFile.write('\t\tflows\n')
    # Adding in the request/response flow SINK/SOURCE elements
    aadlFile.write('\t\t\tflow_request : flow sink user_request;\n')
    aadlFile.write('\t\t\tflow_response : flow source user_response;\n')
    # Define the end of the databaseServer system
    aadlFile.write('\tend {0};\n'.format(systemName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating a basic database server system that uses request/response type data for the AADL model file")

# Function for writing an implementation of a basic "databaseServer" system with request/response IN/OUT data
def genDatabaseServerSystem_basic_reqResModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic database server system that uses request/response type data for the AADL model file")
    systemName = "databaseServer"
    deviceName_firewall = "firewall"
    deviceName_database = "database"
    aadlFile = open(outfile, "a")
    # Define the databaesNetwork system implementation
    aadlFile.write('\tsystem implementation {0}.simple\n'.format(systemName))
    # Define the subcomponents of the databaseServer system implementation
    aadlFile.write('\t\tsubcomponents\n')
    # Adding in the system element device implementations
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tsystem_{0} : device {0}.simple;\n'.format(deviceName_database))
    # Define the connections of the databaseServer system implementation
    aadlFile.write('\t\tconnection\n')
    aadlFile.write('\t\t\t-- Logical Connection\n')
    # Adding in the Logical Connections between the databaseServer system elements
    # External Connections
    aadlFile.write('\t\t\tuser_req : port user_request -> system_{0}.user_request;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tuser_res : port system_{0}.user_response -> user_response;\n'.format(deviceName_firewall))
    # Internal Connections
    aadlFile.write('\t\t\tinternal_req : port system_{0}.database_req -> system_{1}.database_request;\n'.format(deviceName_firewall, deviceName_database))
    aadlFile.write('\t\t\tinternal_res : port system_{1}.database_response -> system_{0}.database_res;\n'.format(deviceName_firewall, deviceName_database))
    # Define the flows of the databaseServer system implementation
    aadlFile.write('\t\tflows\n')
    # Adding in the response/request flows between the databaseServer system elements
    aadlFile.write('\t\t\tflow_request : flow sink user_request -> user_req -> system_{0}.usr_req_sink;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tflow_response : flow source system_{0}.usr_res_src -> user_res -> user_response;\n'.format(deviceName_firewall))
    # Define the end of the databaseServer system
    aadlFile.write('\tend {0}.simple;\n'.format(systemName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating an implementation of a basic database server system that uses request/response type data for the AADL model file")

# Function for writing a basic "databaseServer" system with plaintext IN/OUT data
def genDatabaseServerSystem_basic_plaintextModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic database server system that uses plaintext type data for the AADL model file")
    systemName = "databaseServer"
    dataType_plaintext = "plaintext"
    aadlFile = open(outfile, "a")
    # Define the databaseServer system

    # Define the features of the databaseServer system

    # Adding in the plaintext data IN/OUT event ports

    # Define the flows of the databaseServer system

    # Adding in the plaintext flow SINK/SOURCE elements

    # Define the end of the databaseServer system

    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating a basic database server system that uses plaintext type data for the AADL model file")

# Function for writing an implemtnation of a basic "databaseServer" system with plaintext IN/OUT data
def genDatabaseServerSystem_basic_plaintextModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic database server system that uses plaintext type data for the AADL model file")
    systemName = "databaseServer"
    deviceName_firewall = "firewall"
    deviceName_database = "database"
    aadlFile = open(outfile, "a")
    # Define the databaesNetwork system implementation

    # Define the subcomponents of the databaseServer system implementation

    # Adding in the system element device implementations

    # Define the connections of the databaseServer system implementation

    # Adding in the Logical Connections between the databaseServer system elements

    # Define the flows of the databaseServer system implementation

    # Adding in the response/request flows between the databaseServer system elements

    # Define the end of the databaseServer system

    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating an implementation of a basic database server system that uses plaintext type data for the AADL model file")

# Function for writing a basic "databaseServer" system with encrypted IN/OUT data
def genDatabserServerSystem_basic_encryptedModel(outfile):
    if debugBit != 0:
        print("[*] Generating a basic database server system that uses encrypted type data for the AADL model file")
    systemName = "databaseServer"
    dataType_encrypted = "encrypted"
    aadlFile = open(outfile, "a")
    # Define the databaseServer system

    # Define the features of the databaseServer system

    # Adding in the encrypted data IN/OUT event ports

    # Define the flows of the databaseServer system

    # Adding in the encrypted flow SINK/SOURCE elements

    # Define the end of the databaseServer system

    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating a basic database server system that uses encrypted type data for the AADL model file")

# Function for writing an implementation of a basic "databaseServer" system with encrypted IN/OUT data
def genDatabserServerSystem_basic_encryptedModel_implementation(outfile):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic database server system that uses encrypted type data for the AADL model file")
    systemName = "databaseServer"
    deviceName_firewall = "firewall"
    deviceName_database = "database"
    aadlFile = open(outfile, "a")
    # Define the databaesNetwork system implementation

    # Define the subcomponents of the databaseServer system implementation

    # Adding in the system element device implementations

    # Define the connections of the databaseServer system implementation

    # Adding in the Logical Connections between the databaseServer system elements

    # Define the flows of the databaseServer system implementation

    # Adding in the response/request flows between the databaseServer system elements

    # Define the end of the databaseServer system

    aadlFile.close()
    if debugBit != 0:
        print("[+] Completeld generating an implementation of a basic databser server system that uses encrypted type data for the AADL model file")

# Function for writing a basic user defined database type "databaseNetwork" system with request/response IN/OUT data
#   Note: This model makes use of two machines
def genDatabaseNetworkSystem_basic_user_defined_reqResModel(outfile, databaseType):
    if debugBit != 0:
        print("[*] Generating a basic {0} database network system that uses request/response type data for the AADL model file".format(databaseType))
    systemName = "databaseNetwork"
    dataType_req = "request"
    dataType_res = "response"
    aadlFile = open(outfile, "a")
    # Define the databaseNetwork system
    aadlFile.write('\tsystem {0}\n'.format(systemName))
    # Define the features of the databaseNetwork system
    aadlFile.write('\t\tfeatures\n')
    # Adding in the request/response data IN/OUT event ports
    aadlFile.write('\t\t\tuser_request : in event data port {0};\n'.format(dataType_req))
    aadlFile.write('\t\t\tuser_response : out event data port {0};\n'.format(dataType_res))
    # Define the flows of the databaseNetwork system
    aadlFile.write('\t\tflows\n')
    # Adding in the request/response flow SINK/SOURCE elements
    aadlFile.write('\t\t\tflow_request : flow sink user_request;\n')
    aadlFile.write('\t\t\tflow_response : flow source user_response;\n')
    # Define the end of the databaseNetwork system
    aadlFile.write('\tend {0};\n'.format(systemName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating basic {0} database network system that uses request/response data for the AADL model file".format(databaseType))

# Function for writing an implemtnation of a basic user defined database type "databaseNetwork" with request/response IN/OUT data; added firewall type
#   Note: This model makes use of two machines
def genDatabaseNetworkSystem_basic_user_defined_reqResModel_implementation(outfile, databaseType, firewallType):
    if debugBit != 0:
        print("[*] Generating an implementation of a basic {0} database network system with {1} firewall that uses request/response type data for the AADL model file".format(databaseType, firewallType))
    systemName = "databaseNetwork"
    deviceName_firewall = "firewall"
    deviceName_database = "database"
    #deviceName_database = databaseType
    aadlFile = open(outfile, "a")
    # Define the databaesNetwork system implementation
    aadlFile.write('\tsystem implementation {0}.simple\n'.format(systemName))
    # Define the subcomponents of the databaseNetwork system implementation
    aadlFile.write('\t\tsubcomponents\n')
    # Adding in the system element device implementations
    aadlFile.write('\t\t\tsystem_{0} : device {1}.simple;\n'.format(deviceName_firewall, firewallType))
    aadlFile.write('\t\t\tsystem_{0} : device {1}.simple;\n'.format(deviceName_database, databaseType))
    # Define the connections of the databaseNetwork system implementation
    aadlFile.write('\t\tconnections\n')
    aadlFile.write('\t\t\t-- Logical Connections\n')
    # Adding in the Logical Connections between the databaseNetwork system elements
    # External Connections
    aadlFile.write('\t\t\tuser_req : port user_request -> system_{0}.user_request;\n'.format(deviceName_firewall))
    aadlFile.write('\t\t\tuser_res : port system_{0}.user_response -> user_response;\n'.format(deviceName_firewall))
    # Internal Connections
    aadlFile.write('\t\t\tinternal_req : port system_{0}.database_req -> system_{1}.database_request;\n'.format(deviceName_firewall, deviceName_database))
    aadlFile.write('\t\t\tinternal_res : port system_{1}.database_response -> system_{0}.database_res;\n'.format(deviceName_firewall, deviceName_database))
    # Define the flows of the databaseNetwork system implementation
    aadlFile.write('\t\tflows\n')
    # Adding in the response/request flows between the databaseNetwork system elements
    aadlFile.write('\t\t\tflow_request : flow sink user_request -> user_req -> system_{0}.usr_req_sink;\n'.format(deviceName_firewall))     # Nota Bene: Because of AADL all these connected pieces must have DIFFERENT names??
    aadlFile.write('\t\t\tflow_response : flow source system_{0}.usr_res_src -> user_res -> user_response;\n'.format(deviceName_firewall))
    # Define the end of the databaseNetwork system
    aadlFile.write('\tend {0}.simple;\n'.format(systemName))
    aadlFile.close()
    if debugBit != 0:
        print("[+] Completed generating implenentation of a basic {0} database network system with {1} firewall that uses request/response type data for the AADL model file".format(databaseType, firewallType))

## Functions for writing of general complete AADL model files
# Function for generating a generic basic Request/Response firewall and database AADL model file
def generic_basic_requestResponse_firewall_database_system_genAADLmodel(aadlFilename):
    if debugBit != 0:
        print("[*] Running function for test genreation of a basic AADL model file")
    #aadlFilename = "testModel.aadl"
    packageName = "testmodel"
    # Start of the AADL model file
    genOpenHeader(packageName, aadlFilename)
    # Other inner parts of the AADL model file
    addEmptyLine(aadlFilename)
    # Add in comment line
    aadlFile = open(aadlFilename, "a")
    aadlFile.write('\t-- Bus and Data Definitions\n')
    aadlFile.close()
    # Bus and Data Definitions
    genWirelessMedium_basic(aadlFilename)
    genEthernetMedium_basic(aadlFilename)
    genRequestData_basic(aadlFilename)
    genResponseData_basic(aadlFilename)
    addEmptyLine(aadlFilename)
    # Add in comment line
    aadlFile = open(aadlFilename, "a")
    aadlFile.write('\t-- Definition of devices\n')
    aadlFile.close()
    # Device definitions
    genFirewallDevice_basic_reqResModel(aadlFilename)
    addEmptyLine(aadlFilename)
    genFirewallDevice_basic_reqResModel_implementation(aadlFilename)
    addEmptyLine(aadlFilename)
    genDatabaseDevice_basic_reqResModel(aadlFilename)
    addEmptyLine(aadlFilename)
    genDatabaseDevice_basic_reqResModel_implementation(aadlFilename)
    addEmptyLine(aadlFilename)
    # Add in comment line
    aadlFile = open(aadlFilename, "a")
    aadlFile.write('\t-- Definition of system\n')
    aadlFile.close()
    # System definitions
    genDatabaseNetworkSystem_basic_reqResModel(aadlFilename)
    addEmptyLine(aadlFilename)
    # Add in comment line
    aadlFile = open(aadlFilename, "a")
    aadlFile.write('\t-- Definition of system implementation\n')
    aadlFile.close()
    # System implementation definition
    genDatabaseNetworkSystem_basic_reqResModel_implementation(aadlFilename)
    # End of the AADL model file
    genEndHeader(packageName, aadlFilename)
    if debugBit != 0:
        print("[+] Completed the generation of the test AADL model file")

# Function for generating a test AADL file; Note: Same basic structure as will be used for all later AADL model generation
def testGenAADLmodel():
    if debugBit != 0:
        print("[*] Running function for test genreation of a basic AADL model file")
    aadlFilename = "testModel.aadl"
    packageName = "testmodel"
    # Start of the AADL model file
    genOpenHeader(packageName, aadlFilename)
    # Other inner parts of the AADL model file
    addEmptyLine(aadlFilename)
    # Add in comment line
    aadlFile = open(aadlFilename, "a")
    aadlFile.write('\t-- Bus and Data Definitions\n')
    aadlFile.close()
    # Bus and Data Definitions
    genWirelessMedium_basic(aadlFilename)
    genEthernetMedium_basic(aadlFilename)
    genRequestData_basic(aadlFilename)
    genResponseData_basic(aadlFilename)
    addEmptyLine(aadlFilename)
    # Add in comment line
    aadlFile = open(aadlFilename, "a")
    aadlFile.write('\t-- Definition of devices\n')
    aadlFile.close()
    # Device definitions
    genFirewallDevice_basic_reqResModel(aadlFilename)
    addEmptyLine(aadlFilename)
    genFirewallDevice_basic_reqResModel_implementation(aadlFilename)
    addEmptyLine(aadlFilename)
    genDatabaseDevice_basic_reqResModel(aadlFilename)
    addEmptyLine(aadlFilename)
    genDatabaseDevice_basic_reqResModel_implementation(aadlFilename)
    addEmptyLine(aadlFilename)
    # Add in comment line
    aadlFile = open(aadlFilename, "a")
    aadlFile.write('\t-- Definition of system\n')
    aadlFile.close()
    # System definitions
    genDatabaseNetworkSystem_basic_reqResModel(aadlFilename)
    addEmptyLine(aadlFilename)
    # Add in comment line
    aadlFile = open(aadlFilename, "a")
    aadlFile.write('\t-- Definition of system implementation\n')
    aadlFile.close()
    # System implementation definition
    genDatabaseNetworkSystem_basic_reqResModel_implementation(aadlFilename)
    # End of the AADL model file
    genEndHeader(packageName, aadlFilename)
    if debugBit != 0:
        print("[+] Completed the generation of the test AADL model file")

## Functions for generating AADL model files based on variable user input
# Function for generating a user defined basic Request/Response firewall and database AADL model file       [ Complete Model ]
def generic_basic_user_defined_requestResponse_firewall_database_system_genAADLmodel(aadlFilename, databaseType, firewallType, packageName):
    if debugBit != 0:
        print("[*] Running function for {0} genreation of a basic {1} firewall database system AADL model file".format(databaseType, firewallType))
    #aadlFilename = "testModel.aadl"
    #packageName = "testmodel"
    #databaseType = "database"
    # Start of the AADL model file
    genOpenHeader(packageName, aadlFilename)
    # Other inner parts of the AADL model file
    addEmptyLine(aadlFilename)
    # Add in comment line
    aadlFile = open(aadlFilename, "a")
    aadlFile.write('\t-- Bus and Data Definitions\n')
    aadlFile.close()
    # Bus and Data Definitions
    genWirelessMedium_basic(aadlFilename)
    genEthernetMedium_basic(aadlFilename)
    genRequestData_basic(aadlFilename)
    genResponseData_basic(aadlFilename)
    addEmptyLine(aadlFilename)
    # Add in comment line
    aadlFile = open(aadlFilename, "a")
    aadlFile.write('\t-- Definition of devices\n')
    aadlFile.close()
    # Device definitions
    genFirewallDevice_basic_user_defined_reqResModel(aadlFilename, firewallType)
    addEmptyLine(aadlFilename)
    genFirewallDevice_basic_user_defined_reqResModel_implementation(aadlFilename, firewallType)
    addEmptyLine(aadlFilename)
    genDatabaseDevice_basic_user_defined_reqResModel(aadlFilename, databaseType)
    addEmptyLine(aadlFilename)
    genDatabaseDevice_basic_user_defined_reqResModel_implementation(aadlFilename, databaseType)
    addEmptyLine(aadlFilename)
    # Add in comment line
    aadlFile = open(aadlFilename, "a")
    aadlFile.write('\t-- Definition of system\n')
    aadlFile.close()
    # System definitions
    genDatabaseNetworkSystem_basic_user_defined_reqResModel(aadlFilename, databaseType)
    addEmptyLine(aadlFilename)
    # Add in comment line
    aadlFile = open(aadlFilename, "a")
    aadlFile.write('\t-- Definition of system implementation\n')
    aadlFile.close()
    # System implementation definition
    genDatabaseNetworkSystem_basic_user_defined_reqResModel_implementation(aadlFilename, databaseType, firewallType)
    # End of the AADL model file
    genEndHeader(packageName, aadlFilename)
    if debugBit != 0:
        print("[+] Completed the generation of the {0} + {1} AADL model file".format(databaseType, firewallType))

# Function for generating the MOST BASIC firewall-to-database AADL Model
def generate_firewall_to_database_aadl_models():
    print("[*] GAM is generating the most basic AADL model (firewall-to-database)")
    array_of_database_types = ["database", "mysql", "mongodb", "couchdb"]
    array_of_firewall_types = ["firewall", "cisco", "barracuda", "fortinet", "juniper", "pfsense", "sophos", "sonicwall"]
    default_package_name = "test_package"
    for database_type in array_of_database_types:
        for firewall_type in array_of_firewall_types:
            if debugBit != 0:
                print("[*] Generating AADL Model using {0} + {1} implementation".format(database_type, firewall_type))
            databaseType = database_type
            #firewallType = "firewall"
            firewallType = firewall_type
            if debugBit != 0:
                print("[+] Set the implementation/solution to be used in this model generation")
            packageName = default_package_name
            if debugBit != 0:
                print("[+] Set the default package name for the generated AADL model")
            #model_filename = "{0}_firewall.aadl".format(databaseType)
            model_filename = "{0}_{1}.aadl".format(databaseType, firewallType)
            if debugBit != 0:
                print("[+] Output of model to the {0} filename".format(model_filename))
            # Generate the user definied datbase type AADL database + firewall model file
            generic_basic_user_defined_requestResponse_firewall_database_system_genAADLmodel(model_filename, databaseType, firewallType, packageName)
    print("[+] GAM has finished generating the most basic AADL model (firewall-to-database)")

## Functions for the Smart Home AADL model generation

# Function for generating the custom Smart Home device
def generate_smart_home_aadl_custom_device(aadlFilename, device_name, io_list, bus_connections):
    if debugBit != 0:
        print("[*] Generating the custom Smart Home device {0}".format(device_name))
    # Variables used for ensuring proper output
    #io_list = ['http', 'ssh', 'smb', 'sql']
    #bus_connections = ['ethernet', 'zigbee']
    io_direction = "in out"         # Defaulting this for now, but can be used to providing directions for conncetions / graph
    event = "event"             #   \
    data = "data"               #   |--  All these variables relate to the definition for ports (if it is an event port, if it is a data port, if it is a port feature)
    port = "port"               #   /
    requires = "requires bus access"
    aadlFile = open(aadlFilename, "a")
    aadlFile.write('\tdevice {0}\n'.format(device_name))
    aadlFile.write('\t\t-- Definition of {0}\n'.format(device_name.capitalize()))
    aadlFile.write('\t\tfeatures\n')
    aadlFile.write('\t\t\t-- Data Ports\n')
    # For loop for adding in all the device Data Port features
    for io_port in io_list:
        if debugBit != 0:
            print('\tAdding I/O port [ {0} ]'.format(io_port))
        aadlFile.write('\t\t\t{0}_io\t\t\t:\t\t\t{1} {2} {3} {4} {0};\n'.format(io_port, io_direction, event, data, port))
    # For loop for adding in all the device Bus Connection features
    aadlFile.write('\t\t\t-- Bus Connections\n')
    for bus_connection in bus_connections:
        if debugBit != 0:
            print('\tAdding Bus Connection [ {0} ]'.format(bus_connection))
        # NOTE: Assuming a default of ALWAYS having a "require bus access" definition
        aadlFile.write('\t\t\t{0}_bus\t\t:\t\t\t{1} {0};\n'.format(bus_connection, requires))
    aadlFile.write('\tend {0};\n'.format(device_name))
    aadlFile.close()

# Function for generating the custom Smart Home device custom implementation
def generate_smart_home_aadl_custom_device_custom_implementation(aadlFilename, device_name, implementation_name):
    if debugBit != 0:
        print("[*] Generating the custom Smart Home {0} device {1} implementation".format(device_name, implementation_name))
    aadlFile = open(aadlFilename, "a")
    aadlFile.write('\tdevice implementation {0}.{1}\n'.format(device_name, implementation_name))
    aadlFile.write('\tend {0}.{1};\n'.format(device_name, implementation_name))
    aadlFile.close()

# Function for generating the Smart Home Server Device
def generate_smart_home_aadl_server_device(aadlFilename):
    print("[*] Generating the Smart Home server device")
    deviceName = 'server'
    data_port_array = ['http', 'ssh', 'smb', 'sql']
    bus_array = ['ethernet', 'zigbee']
    direction = 'in out'
    event = 'event'
    data = 'data'
    port = 'port'
    requires_access = 'requires bus access'
    aadlFile = open(aadlFilename, "a")
    aadlFile.write('\tdevice {0}\n'.format(deviceName))
    aadlFile.write('\t\t-- Definition of {0}\n'.format(deviceName))
    aadlFile.write('\t\tfeatures\n')
    # Write the Data Ports information
    aadlFile.write('\t\t\t-- Data Ports\n')
    for data_port in data_port_array:
        aadlFile.write('\t\t\t{0}_io\t\t\t:\t\t\t{1} {2} {3} {4} {0};\n'.format(data_port, direction, event, data, port))
    # Write the Bus Connections information
    aadlFile.write('\t\t\t-- Bus Connections\n')
    for bus in bus_array:
        aadlFile.write('\t\t\t{0}_bus\t\t:\t\t\t{1} {0};\n'.format(bus, requires_access))
    aadlFile.write('\tend {0};\n'.format(deviceName))
    aadlFile.close()

# Function for generating the Smart Home server simple device implementaiton
def generate_smart_home_server_device_simple_implementation(aadlFilename):
    print("[*] Generating the Smart Home server simple device implementaiton")
    deviceName = 'server'
    implementation = 'simple'
    aadlFile = open(aadlFilename, "a")
    aadlFile.write('\tdevice implementation {0}.{1}\n'.format(deviceName, implementation))
    aadlFile.write('\tend {0}.{1};\n'.format(deviceName, implementation))
    aadlFile.close()

# Function for generating the Smart Home database device
def generate_smart_home_aadl_database_device(aadlFilename):
    print("[*] Generating the Smart Home database device")

# Function for generating the Smart Home database simple device implementaiton
def generate_smart_home_database_device_simple_implementation(outfile):
    print("[*] Generating the Smart Home database simple device implementation")

# Function for generating the Smart Home application device
def generate_smart_home_aadl_application_device(outfile):
    print("[*] Generating the Smart Home application device")

# Function for generating the Smart Home application simple device implementation
def generate_smart_home_application_device_simple_implementation(outfile):
    print("[*] Generating the Smart Home application simple device implementation")

# Function for generating the Smart Home graphical user interface device
def generate_smart_home_aadl_gui_device(outfile):
    print("[*] Generating the Smart Home gui device")

# Function for generating the Smart Home graphical user interface simple device implementaiton
def generate_smart_home_gui_device_simple_implementation(outfile):
    print("[*] Generating the Smart Home gui simple device implementaiton")

# Function for generating the Smart Home generic sensor device
def generate_smart_home_aadl_generic_sensor_device(outfile):
    print("[*] Generating the Smart Home generic sensor device")

# Function for generating the Smart Home generic sensor simple device implementation
def generate_smart_home_generic_sensor_device_simple_implementation(outfile):
    print("[*] Generating the Smart Home generic sensor simple device implementation")

# Function for returning matching elements of TWO provided sets of data
def return_matching_elements_between_lists(set_one, set_two):
    return set(set_one).intersection(set_two)

# Function for generating the Smart Home network system
#   - TODO: Have this function take in the input of the system_IO_map
#   - NOTE: There is the expectation that the Smart Home System will need three Input/Outputs (internet based I/O, sensors based I/O, and API based I/O)
def generate_smart_home_aadl_network_system(aadlFilename, system_io_map):
    print("[*] Generating the Smart Home network system")
    system_name = 'smart_home_network'      # Old place holder; replaced below with 'system_model' (which comes from the system_io_map)
    direction = 'in out'
    event = 'event'
    data = 'data'
    port = 'port'
    # Example of the system_io_map that should be passed into this function
    '''
    system_io_map = {
            'smart_home_network' : {
                'io_list' : ['http', 'smb']
                }
            }
    How can we leveage the above information with the rest of what is needed to modularize the building of a system description?
        - Note: The 'system_io_map' contains a list of the Inputs and Outputs that the system model should have
        - One can have a series of IF statements to check if certain I/O points should be included in the Smart Home Model
            - Ex:   HTTP for (1) Internet and (2) Sensor information, SMB for (1) API communication
    '''
    aadlFile = open(aadlFilename, "a")
    # Logic for going through the system_io_map to add the description for each system_model
    #   - NOTE: Later nested in this loop is the decision logic for adding the appropriate I/O features
    for system_model in system_io_map:
        print("\tDescribing the [ {0} ] system model".format(system_model))
        aadlFile.write('\tsystem {0}\n'.format(system_model))
        aadlFile.write('\t\t-- Definition of {0}\n'.format(" ".join(w.capitalize() for w in system_model.split('_'))))           # Note: Expects '_' to be the separator in the system_name variable (now the system_model variables)
        # Add in the features to the system definition
        #   - NOTE: This represents the set of Entry/Exit points that exist within the larger system model
        aadlFile.write('\t\tfeatures\n')
        # Logic for determining which I/O features need to be added into the generated AADL model file
        #   - IF Statement nested in a for loop that generates the IO for the model based on the provided io_list
        for io_type in system_io_map[system_model]['io_list']:
            if debugBit != 0:
                print("\tChecking for addition of the I/O type [ {0} ]".format(io_type))
            # Check if there should be HTTP I/O in the system model
            if io_type == 'http': 
                if debugBit != 0:
                    print("\tAdding I/O port [ {0} ]".format(io_type))
                aadlFile.write('\t\t\tinternet_{0}_io\t\t\t:\t\t\t{1} {2} {3} {4} {0};\n'.format(io_type, direction, event, data, port))        # Addition of Internet HTTP I/O
                aadlFile.write('\t\t\tsensor_{0}_io\t\t\t:\t\t\t{1} {2} {3} {4} {0};\n'.format(io_type, direction, event, data, port))          # Addition of Sensor HTTP I/O
            # Check if there should be SMB I/O in the system model
            elif io_type == 'smb':
                if debugBit != 0:
                    print("\tAdding I/O port [ {0} ]".format(io_type))
                aadlFile.write('\t\t\tapi_{0}_io\t\t\t:\t\t\t{1} {2} {3} {4} {0};\n'.format(io_type, direction, event, data, port))               # Addition of API SMB I/O
            else:
                print("[!] ERROR: I/O Type passed for System Model is UNKNOWN\t\t[ {0} ]".format(io_type))
        aadlFile.write('\tend {0};\n'.format(system_model))
    # Extra line space to add at the end of the system model description?
    aadlFile.close()

# Function for generating the Smart Home network system - Ethernet Only Implementation
#   - Note: sensor_element variable allows passing of custom elements to the implementation
#   - TODO: Have this function intake the system_implementation_map as an input and use that to build the model
def generate_smart_home_network_system_ethernet_only_implementation(aadlFilename, sensor_element='generic_sensor', server_element='server', database_element='database'):     # , scenario=0):
    print("[*] Generating the Smart Home network ethernet only system implementaiton")
    system_name = 'smart_home_network'
    implementation = 'ethernet_only'
    device = 'device'
    bus = 'bus'
    sensor_medium = 'zigbee'        # Default assumption
    #subcomponent_array = ['graphical_user_interface', 'application', 'server', 'database', sensor_element]
    subcomponent_array = ['graphical_user_interface', 'application', server_element, database_element, sensor_element]
    # Check to see if the BreeZ Sensor implmentation is being generated and THEREFORE will need to replace Zigbee aspects with BreeZ protocol
    if sensor_element == 'breez_sensor':
        sensor_medium = 'breez'
    '''
    if scenario == 0:
        subcomponent_array = ['graphical_user_interface', 'application', 'server', 'database', 'generic_sensor']
    elif scenario == 1:
        subcomponent_array = ['graphical_user_interface', 'application', 'server', 'database', 'breez_sensor']
    '''
    ## ORIGINAL AADL System Implementation Generation logic for creating a Smart Home Model
    print("[????] Checking variables inside function()\n\tAADL Filename:\t\t{0}\n\tSensor Element:\t\t{1}\n\tServer Element:\t\t{2}\n\tDatabase Element:\t\t{3}".format(aadlFilename, sensor_element, server_element, database_element))
    subcomponent_implementation = 'simple'
    bus_access = 'bus access'
    port = 'port'
    connection_direction = '<->'
    aadlFile = open(aadlFilename, "a")
    aadlFile.write('\tsystem implementation {0}.{1}\n'.format(system_name, implementation))
    aadlFile.write('\t\t-- Implementation Definition of {0} - {1}\n'.format(" ".join(w.capitalize() for w in system_name.split('_')), " ".join(w.capitalize() for w in implementation.split('_'))))
    # Add in the subcomponent information to the system implementation definition
    aadlFile.write('\t\tsubcomponents\n')
    for subcomponent in subcomponent_array:
        aadlFile.write('\t\t\tsmart_home_{0}\t\t\t:\t\t\t{1} {0}.{2};\n'.format(subcomponent, device, subcomponent_implementation))
    # Add in the bus elements that are part of the three_path model
    #   - TODO: Add a case/switch to check which / if any bus elements should be added into the model
    aadlFile.write('\t\t\tinternal_{0}\t\t\t:\t\t\tbus {0};\n'.format('ethernet'))
    aadlFile.write('\t\t\tinternet_connection\t\t\t:\t\t\tbus {0};\n'.format('ethernet'))
    aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\tbus {2};\n'.format('sensors', server_element, sensor_medium))
    #aadlFile.write('\t\t\tsmart_home_{0}\t\t\t:\t\t\t{1} {0}.{2};\n'.format('application', device, subcomponent_implementation))
    # Add in the connections information to the system implementation definition
    #   - TODO: Add a case/switch to check which / if any bus/data connections should be added to the model
    aadlFile.write('\t\tconnections\n')
    # Add in the bus connections
    aadlFile.write('\t\t\t-- Bus Connections\n')
    aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\t{2} smart_home_{0}.{1}_bus {3} internal_{1};\n'.format(server_element, 'ethernet', bus_access, connection_direction))
    aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\t{2} smart_home_{0}.{1}_bus {3} internal_{1};\n'.format(database_element, 'ethernet', bus_access, connection_direction))
    aadlFile.write('\t\t\tsensors_to_{1}\t\t\t:\t\t\t{2} smart_home_{0}.{1}_bus {3} sensors_to_{4};\n'.format(sensor_element, sensor_medium, bus_access, connection_direction, server_element))
    aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\t{2} smart_home_{0}.{1}_bus {3} {4}_to_{0};\n'.format(server_element, sensor_medium, bus_access, connection_direction, 'sensors'))
    aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\t{2} smart_home_{0}.{1}_bus {3} internal_{1};\n'.format('application', 'ethernet', bus_access, connection_direction))
    aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\t{2} smart_home_{0}.{1}_bus {3} internal_{1};\n'.format('graphical_user_interface', 'ethernet', bus_access, connection_direction))
    # Add in the data connections
    aadlFile.write('\t\t\t-- Data Connections\n')
    # Server to Database connections
    aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{0}.{2}_io {4} smart_home_{1}.{2}_io;\n'.format(server_element, database_element, 'smb', port, connection_direction))
    aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{0}.{2}_io {4} smart_home_{1}.{2}_io;\n'.format(server_element, database_element, 'sql', port, connection_direction))
    # Server to Sensor connections
    aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{1}.{2}_io {4} smart_home_{0}.{2}_io;\n'.format(server_element, sensor_element, 'ssh', port, connection_direction))
    aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{1}.{2}_io {4} smart_home_{0}.{2}_io;\n'.format(server_element, sensor_element, 'http', port, connection_direction))
    # Server to Application connections
    aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{1}.{2}_io {4} smart_home_{0}.{2}_io;\n'.format(server_element, 'application', 'http', port, connection_direction))
    aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{1}.{2}_io {4} smart_home_{0}.{2}_io;\n'.format(server_element, 'application', 'ssh', port, connection_direction))
    aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{1}.{2}_io {4} smart_home_{0}.{2}_io;\n'.format(server_element, 'application', 'smb', port, connection_direction))
    # Application to GUI connections
    aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{1}.{2}_io {4} smart_home_{0}.{2}_io;\n'.format('application', 'graphical_user_interface', 'http', port, connection_direction))
    aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{1}.{2}_io {4} smart_home_{0}.{2}_io;\n'.format('application', 'graphical_user_interface', 'smb', port, connection_direction))
    # External to Internal connections (i.e. Entry/Exit points)
    aadlFile.write('\t\t\tinternet_to_{0}_{1}\t\t\t:\t\t\t{2} internet_{1}_io {3} smart_home_{0}.{1}_io;\n'.format('graphical_user_interface', 'http', port, connection_direction))
    #aadlFile.write('\t\t\tinternet_to_{0}_{1}\t\t\t:\t\t\t{2} {0}_{1}_io {3} smart_home_{0}.{1}_io;\n'.format('generic_sensor', 'http', port, connection_direction))
    aadlFile.write('\t\t\tinternet_to_{0}_{1}\t\t\t:\t\t\t{2} sensor_{1}_io {3} smart_home_{0}.{1}_io;\n'.format(sensor_element, 'http', port, connection_direction))
    aadlFile.write('\t\t\tinternet_to_{0}_{1}\t\t\t:\t\t\t{2} api_{1}_io {3} smart_home_{0}.{1}_io;\n'.format('application', 'smb', port, connection_direction))
    aadlFile.write('\tend {0}.{1};\n'.format(system_name, implementation))
    aadlFile.close()

# Function for generating the Smart Home network system - Ethernet Only Implementation
#   - Note: sensor_element variable allows passing of custom elements to the implementation
#   - NOTE: This function takes in the 'device_io_map' so that it can align the system_io_list and device_io_list(s) when generating connections
def generate_smart_home_network_system_implementations(aadlFilename, system_implementation_map, device_io_map):    #, sensor_element='generic_sensor', server_element='server', database_element='database', graphical_user_interface_element='graphical_user_interface', application_element='application', bus_array=['ethernet', 'zigbee']):     # , scenario=0):
    print("[*] Generating the Smart Home network ethernet only system implementaiton")
    # Defaults to use for the system model implementaiton initial description
    system_name = 'smart_home_network'
    implementation = 'ethernet_only'
    #subcomponent_array = ['graphical_user_interface', 'application', 'server', 'database', sensor_element]
    # TODO: Prepare the following array by doing some initial analysis of the 'subcomponent' information to
    #       (1)     Create the 'subcomponent_array' that is used later on for 'subcomponent' description
    #       (2)     Determine SPECIFIC 'subcomponent' items for later SPECIFIC description of Bus and Data Connections
    #subcomponent_array = ['graphical_user_interface', 'application', server_element, database_element, sensor_element]
    # TODO: Prepare the necessary data structures to
    #       (3)     Create an array of 'bus' elements that is used later on for 'subcomponent' description
    #       (4)     Determine SPECIFIC 'subcomponent' items for later SPECIFIC description of Bus and Data Connection
    #bus_array = ['ethernet', 'zigbee']
    # Defaults used for the generation of the system implementation internals
    device = 'device'
    bus = 'bus'
    subcomponent_implementation = 'simple'
    bus_access = 'bus access'
    port = 'port'
    connection_direction = '<->'
    ## NEW AADL System Implementation Generation logic for creating a Smart Home Model
    # For loop through the system_model items in the system_implementation_map
    for system_model in system_implementation_map:
        if debugBit != 0:
            print("\tDescribing the [ {0} ] system_model".format(system_model))
        # For loop through the system_model_implementation items under the current system_model item
        for system_model_implementation in system_implementation_map[system_model]:
            if debugBit != 0:
                print("\tDescribing the [ {0} ] implementation for system model [ {1} ]".format(system_model_implementation, system_model))
            # Clear / Reset the subcomponent_array variable to be empty for each system implementation
            subcomponent_array = []
            # Clear / Reset the sensor_medium variable to be empty for each system implmentation    |   Used to ensure that a sensor_medium is detected by the system implmentation generation logic
            sensor_medium = ''
            aadlFile = open(aadlFilename, "a")
            aadlFile.write('\tsystem implementation {0}.{1}\n'.format(system_model, system_model_implementation))
            aadlFile.write('\t\t-- Implementation Definition of {0} - {1}\n'.format(" ".join(w.capitalize() for w in system_model.split('_')), " ".join(w.capitalize() for w in system_model_implementation.split('_'))))
            ## Generation of the:
            #       (1)         subcomponent_array      -       Used to generate the subcomponents of the system model implementation
            #       (2)         individual elements     -       Set specific variables for each of the individual system implementaiton models
            #       (3)         bus_array               -       Used to generate the subcomponent buses of the system model implementation
            for subcomponent_item in system_implementation_map[system_model][system_model_implementation]['subcomponents']:
                if debugBit != 0:
                    print("\tSubcomponent Item:\t{0}\n\t\tConents:\t{1}".format(subcomponent_item, system_implementation_map[system_model][system_model_implementation]['subcomponents'][subcomponent_item]))
                # Add the devices to the subcomponent_array; ONLY if NOT the 'bus_array' element                                        (1)
                subcomponent_array.append(system_implementation_map[system_model][system_model_implementation]['subcomponents'][subcomponent_item]) 
                # IF statements for setting the individual elements
                if subcomponent_item == 'gui_element':                                  # Add the graphical_user_interface_element      (2)
                    graphical_user_interface_element = system_implementation_map[system_model][system_model_implementation]['subcomponents'][subcomponent_item]
                elif subcomponent_item == 'application_element':                        # Add the application_element                   (2)
                    application_element = system_implementation_map[system_model][system_model_implementation]['subcomponents'][subcomponent_item]
                elif subcomponent_item == 'server_element':                             # Add the server_element                        (2)
                    server_element = system_implementation_map[system_model][system_model_implementation]['subcomponents'][subcomponent_item]
                elif subcomponent_item == 'database_element':                           # Add the database_element                      (2)
                    database_element = system_implementation_map[system_model][system_model_implementation]['subcomponents'][subcomponent_item]
                elif subcomponent_item == 'sensor_element':                             # Add the sensor_element                        (2)
                    sensor_element = system_implementation_map[system_model][system_model_implementation]['subcomponents'][subcomponent_item]
                else:
                    print("[!] ERROR: UNKNOWN subcomponent_item [ {0} ]".format(subcomponent_item))
            ## TODO: Dissection and Generation of the AADL model's Connections information for generation of the:
            #       (4)         Bus Connections         -       Used to set the bus connections between buses and the model elements
            #       (5)         Data Connections        -       Used to set the data connections between model element protocol ports
            #       (6)         Entry/Exit Connections  -       Used to set the data connections between the Entry/Exit points and the model element protocol ports
            for connection_item in system_implementation_map[system_model][system_model_implementation]['connections']:
                if debugBit != 0:
                    print("\tConnections Item:\t{0}\n\t\tContents:\t{1}".format(connection_item, system_implementation_map[system_model][system_model_implementation]['connections'][connection_item]))
                # IF statement for setting the connection elements
                if connection_item == 'bus_array':
                    bus_array = system_implementation_map[system_model][system_model_implementation]['connections'][connection_item]
            ## Writing in the 'subcomponents' information of the AADL model
            # Add in the subcomponent information to the system implementation definition
            aadlFile.write('\t\tsubcomponents\n')
            for subcomponent in subcomponent_array:
                aadlFile.write('\t\t\tsmart_home_{0}\t\t\t:\t\t\t{1} {0}.{2};\n'.format(subcomponent, device, subcomponent_implementation))
            # Use SAME IF statement check done for the system_model description function
            # Add in the bus elements that are part of the three_path model
            #   - TODO: Add a case/switch to check which / if any bus elements should be added into the model
            #   - NOTE: The 'sensor_medium' variable is set under each bus_type check done below
            for bus_type in bus_array:      # TODO: Change this to use a NEW bus_array that contains the necessary Bus I/O subcomponents
                if debugBit != 0:
                    print("\tChecking for addition of the I/O type [ {0} ]".format(bus_type))
                # Check if there should be HTTP I/O in the system model
                if bus_type == 'ethernet': 
                    if debugBit != 0:
                        print("\tAdding Bus I/O subcomponent [ {0} ]".format(bus_type))
                    sensor_medium = bus_type
                    aadlFile.write('\t\t\tinternal_{0}\t\t\t:\t\t\tbus {0};\n'.format(bus_type))                                      # Addition of Internal Ethernet Bus     (internal bus)
                    aadlFile.write('\t\t\tinternet_connection\t\t\t:\t\t\tbus {0};\n'.format(bus_type))                               # Addition of Internet Ethernet Bus     (external bus)

                # Check if there should be SMB I/O in the system model
                elif bus_type == 'zigbee':
                    if debugBit != 0:
                        print("\tAdding Bus I/O subcomponent [ {0} ]".format(bus_type))
                    sensor_medium = bus_type
                    # NOTE: Having an issue where the use of 'bus_type' below causes subcomponent to be named 'bus_type'_to_<server> INSTEAD of sensor_to_<server>
                    #aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\tbus {2};\n'.format(bus_type, server_element, sensor_medium))          # Addition of Internal Zigbee Bus   (server_element to sensor_element)
                    #aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\tbus {2};\n'.format('sensors', server_element, sensor_medium))          # Addition of Internal Zigbee Bus   (server_element to sensor_element)
                    aadlFile.write('\t\t\t{0}_{1}\t\t\t:\t\t\tbus {1};\n'.format('internal', sensor_medium))          # Addition of Internal Zigbee Bus   (server_element to sensor_element)
                elif bus_type == 'breez':
                    if debugBit != 0:
                        print("\tAdding Bus I/O subcomponent [ {0} ]".format(bus_type))
                    sensor_medium = bus_type        # Should be good? But MAY NEED to change this to specific hardcoded values
                    #aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\tbus {2};\n'.format(bus_type, server_element, sensor_medium))          # Addition of Internal BreeZ Bus    (server_element to sensor_element)
                    #aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\tbus {2};\n'.format('sensors', server_element, sensor_medium))          # Addition of Internal BreeZ Bus    (server_element to sensor_element)
                    aadlFile.write('\t\t\t{0}_{1}\t\t\t:\t\t\tbus {1};\n'.format('internal', sensor_medium))          # Addition of Internal BreeZ Bus    (server_element to sensor_element)
                else:
                    print("[!] ERROR: Bus I/O subcomponent passed for System Model [ {1} ] implementation [ {2} ] is UNKNOWN\t\t[ {0} ]".format(bus_type, system_model, system_model_implementation))

            ## Writing in the 'connections' information of the AADL model
            aadlFile.write('\t\tconnections\n')
            # Add in the bus connections
            aadlFile.write('\t\t\t-- Bus Connections\n')
            # Connections of elements to the internal ethernet bus
            # Have an IF statement to confirm that the necessary information is present so that the Smart Home AADL model CAN be generated correctly
            if 'ethernet' in bus_array:
                print("\tAdding ETHERNET Bus Connections to the AADL model")
                '''
                aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\t{2} smart_home_{0}.{1}_bus {3} internal_{1};\n'.format(server_element, 'ethernet', bus_access, connection_direction))
                aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\t{2} smart_home_{0}.{1}_bus {3} internal_{1};\n'.format(database_element, 'ethernet', bus_access, connection_direction))
                aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\t{2} smart_home_{0}.{1}_bus {3} internal_{1};\n'.format(application_element, 'ethernet', bus_access, connection_direction))
                aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\t{2} smart_home_{0}.{1}_bus {3} internal_{1};\n'.format(graphical_user_interface_element, 'ethernet', bus_access, connection_direction))
                '''
                ## TODO: Rewrite the above as logic....
                #   Steps:
                #   1)      Check to see which devices have an 'ethernet_bus' bus mediums associated to them
                #   2)      Connect each (in turn) to the internal ethernet bus (system implementation subcomponent)
                for device_element in subcomponent_array:
                    print("\t\tChecking element [ {0} ] for an ethernet bus".format(device_element))
                    print("\t\tValue Check:\n\t\t\tI/O List:\t{0}\n\t\t\tBus List:\t{1}".format(device_io_map[device_element]['io_list'], device_io_map[device_element]['bus_connections']))
                    if 'ethernet' in device_io_map[device_element]['bus_connections']:
                        print("\t\tDevice [ {0} ] has an ethernet bus in its bus_connections < {1} >".format(device_element, device_io_map[device_element]['bus_connections']))
                        aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\t{2} smart_home_{0}.{1}_bus {3} internal_{1};\n'.format(device_element, 'ethernet', bus_access, connection_direction))
            else:
                print("[!] ERROR: Missing internal ETHERNET Bus.... UNEXPECTED; Unable to generate accurate Smart Home AADL model")
            # Connectiosn of elements to the internal sensor bus
            # Have an IF statement to confirm that the necessary SENSOR BUS is present so that the Smart Home AADL model CAN be generated correctly
            if not sensor_medium:           # sensor_medium variable is empty (i.e. has not been set by earlier code logic)
                print("[!] ERROR: Missing internal SENSOR Bus [ {0} ].... UNEXPECTED; Unable to generate accurate Smart Home AADL model".format(sensor_medium))
            else:
                print("\tAdding SENSOR Bus Connections to the AADL model\t\t-\t\tUsing sensor_medium [ {0} ]".format(sensor_medium))
                '''
                aadlFile.write('\t\t\tsensors_to_{1}\t\t\t:\t\t\t{2} smart_home_{0}.{1}_bus {3} sensors_to_{4};\n'.format(sensor_element, sensor_medium, bus_access, connection_direction, server_element))
                aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\t{2} smart_home_{0}.{1}_bus {3} {4}_to_{0};\n'.format(server_element, sensor_medium, bus_access, connection_direction, 'sensors'))
                '''
                ## TODO: Rewrite the above as logic...
                #   Steps:
                #   1)      Check to see which devices have a matching sensor_medium bus medium (e.g. Zigbee, BreeZ)
                #   2)      Connect each (in turn) to the internal bus_medium bus (system implementation subcomponent)
                for device_element in subcomponent_array:
                    print("\t\tChecking element [ {0} ] for an ethernet bus".format(device_element))
                    print("\t\tValue Check:\n\t\t\tI/O List:\t{0}\n\t\t\tBus List:\t{1}".format(device_io_map[device_element]['io_list'], device_io_map[device_element]['bus_connections']))
                    if sensor_medium in device_io_map[device_element]['bus_connections']:
                        print("\t\tDevice [ {0} ] has an ethernet bus in its bus_connections < {1} >".format(device_element, device_io_map[device_element]['bus_connections']))
                        aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\t{2} smart_home_{0}.{1}_bus {3} internal_{1};\n'.format(device_element, sensor_medium, bus_access, connection_direction, device_element))
            ## Add in the data connections
            aadlFile.write('\t\t\t-- Data Connections\n')
            ## TODO: Have a way to encode data connections AND their respective protocols between model elements
            #   - Can have each of the below connections aspects be a separate function that can generate connections between elements
            #   - NOTE: This information should be dissected from the system_implementation_map's 'connections' element
            #   - NOTE: Code should be able to determine the correct values from I/O and Bus lists attached to each device AND how they connect to system I/O and bus lists
            '''
            # Server to Database data connections
            aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{0}.{2}_io {4} smart_home_{1}.{2}_io;\n'.format(server_element, database_element, 'smb', port, connection_direction))
            aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{0}.{2}_io {4} smart_home_{1}.{2}_io;\n'.format(server_element, database_element, 'sql', port, connection_direction))
            # Server to Sensor data connections
            aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{1}.{2}_io {4} smart_home_{0}.{2}_io;\n'.format(server_element, sensor_element, 'ssh', port, connection_direction))
            aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{1}.{2}_io {4} smart_home_{0}.{2}_io;\n'.format(server_element, sensor_element, 'http', port, connection_direction))
            # Server to Application connections
            aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{1}.{2}_io {4} smart_home_{0}.{2}_io;\n'.format(server_element, 'application', 'http', port, connection_direction))
            aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{1}.{2}_io {4} smart_home_{0}.{2}_io;\n'.format(server_element, 'application', 'ssh', port, connection_direction))
            aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{1}.{2}_io {4} smart_home_{0}.{2}_io;\n'.format(server_element, 'application', 'smb', port, connection_direction))
            # Application to GUI connections
            aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{1}.{2}_io {4} smart_home_{0}.{2}_io;\n'.format('application', 'graphical_user_interface', 'http', port, connection_direction))
            aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{1}.{2}_io {4} smart_home_{0}.{2}_io;\n'.format('application', 'graphical_user_interface', 'smb', port, connection_direction))
            '''
            ## TODO: Rewrite the above as logic...
            #   Steps:
            #   1)      Determine which devices are neightbors to each other (e.g. use the connection map? need a way to represent this)                                            <---- Can come for the system_implementation_map    | ASSUME KNOWN
            #   2)      Determine which devices have the same port types (e.g. SMB, SQL, HTTP)
            #   3)      Connect each of the ports using in-out (non-directed) 
            # Server to Database data connections
            matching_io_ports = return_matching_elements_between_lists(device_io_map[server_element]['io_list'], device_io_map[database_element]['io_list'])
            #print("\t[!?!?!?!] Set of matching I/O between [ {0} ] and [ {1} ] elements:\t\t< {2} >".format(server_element, database_element, matching_io_ports))
            for io_port in matching_io_ports:
                aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{0}.{2}_io {4} smart_home_{1}.{2}_io;\n'.format(server_element, database_element, io_port, port, connection_direction))
            # Server to Sensor data connections
            matching_io_ports = return_matching_elements_between_lists(device_io_map[server_element]['io_list'], device_io_map[sensor_element]['io_list'])
            for io_port in matching_io_ports:
                aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{0}.{2}_io {4} smart_home_{1}.{2}_io;\n'.format(server_element, sensor_element, io_port, port, connection_direction))
            # Server to Application data connections
            matching_io_ports = return_matching_elements_between_lists(device_io_map[server_element]['io_list'], device_io_map[application_element]['io_list'])
            for io_port in matching_io_ports:
                aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{0}.{2}_io {4} smart_home_{1}.{2}_io;\n'.format(server_element, application_element, io_port, port, connection_direction))
            # Applicaiton to GUI data connections
            matching_io_ports = return_matching_elements_between_lists(device_io_map[graphical_user_interface_element]['io_list'], device_io_map[application_element]['io_list'])
            for io_port in matching_io_ports:
                aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{0}.{2}_io {4} smart_home_{1}.{2}_io;\n'.format(graphical_user_interface_element, application_element, io_port, port, connection_direction))
            ## External to Internal connections (i.e. Entry/Exit points)
            aadlFile.write('\t\t\tinternet_to_{0}_{1}\t\t\t:\t\t\t{2} internet_{1}_io {3} smart_home_{0}.{1}_io;\n'.format('graphical_user_interface', 'http', port, connection_direction))
            #aadlFile.write('\t\t\tinternet_to_{0}_{1}\t\t\t:\t\t\t{2} {0}_{1}_io {3} smart_home_{0}.{1}_io;\n'.format('generic_sensor', 'http', port, connection_direction))
            aadlFile.write('\t\t\tinternet_to_{0}_{1}\t\t\t:\t\t\t{2} sensor_{1}_io {3} smart_home_{0}.{1}_io;\n'.format(sensor_element, 'http', port, connection_direction))
            aadlFile.write('\t\t\tinternet_to_{0}_{1}\t\t\t:\t\t\t{2} api_{1}_io {3} smart_home_{0}.{1}_io;\n'.format('application', 'smb', port, connection_direction))
            ## TODO: Rewrite the above as logic...
            #   Steps:
            #   1)      Determine which devices are neighbors to the external connections of the system definition (e.g. use an entry / exit map? need a way to represent this)     <----- Can come from the system_implementation_map  | ASSUME KNOWN
            #   2)      Determine which devices have the same port types as the external system ports (e.g. HTTP, SMB)
            #   3)      Connect each of the necessary ports for devices to external facing ports (e.g. system definition ports)
            #       -> NOTE: This will require determining where the ``software'' Entry / Exit points are within the model
            #   - NOTE: This part is far tricker due to needing to know any restrictions of the system description outputs
            #   -> It does seems that TAMSAT can handle all this with minimal problems
            #       - TODO: Need to find a way to map the system description to the system implementation map
            # Graphical User Interface to the Outside
            matching_io_ports = return_matching_elements_between_lists(device_io_map[graphical_user_interface_element]['io_list'], system_implementation_map[system_model][system_model_implementation]['connections']['external_ports'])
            for io_port in matching_io_ports:
                #aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{0}.{2}_io {4} smart_home_{1}.{2}_io;\n'.format(graphical_user_interface_element, application_element, io_port, port, connection_direction))
                aadlFile.write('\t\t\tinternet_to_{0}_{1}\t\t\t:\t\t\t{2} internet_{1}_io {3} smart_home_{0}.{1}_io;\n'.format(graphical_user_interface_element, io_port, port, connection_direction))

            # Sensors to the Outside
            matching_io_ports = return_matching_elements_between_lists(device_io_map[sensor_element]['io_list'], system_implementation_map[system_model][system_model_implementation]['connections']['external_ports'])
            for io_port in matching_io_ports:
                #aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{0}.{2}_io {4} smart_home_{1}.{2}_io;\n'.format(graphical_user_interface_element, application_element, io_port, port, connection_direction))
                aadlFile.write('\t\t\tinternet_to_{0}_{1}\t\t\t:\t\t\t{2} sensor_{1}_io {3} smart_home_{0}.{1}_io;\n'.format(sensor_element, io_port, port, connection_direction))

            # Applicaiton to the Outside
            matching_io_ports = return_matching_elements_between_lists(device_io_map[application_element]['io_list'], system_implementation_map[system_model][system_model_implementation]['connections']['external_ports'])
            for io_port in matching_io_ports:
                #aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{0}.{2}_io {4} smart_home_{1}.{2}_io;\n'.format(graphical_user_interface_element, application_element, io_port, port, connection_direction))
                aadlFile.write('\t\t\tinternet_to_{0}_{1}\t\t\t:\t\t\t{2} api_{1}_io {3} smart_home_{0}.{1}_io;\n'.format(application_element, io_port, port, connection_direction))


            '''
            ### Testing contents of the system_implementation_map (???)
            # For loop through the system_model_implementation_subcomponent items under the current system_model_implementaiton item
            for system_model_implementation_subcomponent in system_implementation_map[system_model][system_model_implementation]['subcomponents']:
                print("\tDescribing the [ {0} ] subcomponent for the system_model_implementation [ {1} ] of the system_model [ {2} ]".format(system_model_implementation_subcomponent, system_model_implementation, system_model))
            # For loop through the system_model_implementation_connection items under the current system_model_implementation item
            for system_model_implementation_connection in system_implementation_map[system_model][system_model_implementation]['connections']:
                print("\tDescribing the [ {0} ] subcomponent for the system_model_implementation [ {1} ] of the system_model [ {2} ]".format(system_model_implementation_connection, system_model_implementation, system_model))
            '''
            aadlFile.write('\tend {0}.{1};\n'.format(system_model, system_model_implementation))
            aadlFile.close()


# Function for generating the "One Path" Smart Home AADL model
def generate_smart_home_aadl_model_one_path(outfile):
    print("[*] Generating the One Path Smart Home model")

# Function for generating the "Two Path" Smart Home AADL model
def generate_smart_home_aadl_model_two_path(outfile):
    print("[*] Generating the Two Path Smart Home model")

# Function for generating the "Three Path" Smart Home AADL model
#   - NOTE: This is the generic Smart Home model
def generate_smart_home_aadl_model_three_path(aadlFilename, packageName):
    print("[*] Generating the Three Path Smart Home model")
    ### Setting the variables to be used in the generation of the Smart Home AADL model
    ## Setting the Basic Model information 
    bus_array = ['ethernet', 'wireless', 'bluetooth', 'zigbee', 'nfc', 'usb', 'hardware_pins']
    data_array = ['http', 'ssh', 'rdp', 'smb', 'ldap', 'sql', 'no_sql', 'uart', 'jtag']
    ## Setting the Device Model information
    # Setting the GUI device specifics
    graphical_user_interface_element = 'graphical_user_interface'
    graphical_user_interface_io_list = ['http', 'smb']
    graphical_user_interface_bus_list = ['ethernet']
    # Setting the Application device specifics
    application_element = 'application'
    application_io_list = ['http', 'ssh', 'smb']
    application_bus_list = ['ethernet']
    # Setting the Server device specifics
    server_element = 'server'
    server_io_list = ['http', 'ssh', 'smb', 'sql']
    server_bus_list = ['ethernet', 'zigbee']
    # Setting the Database device specifics
    database_element = 'database'
    database_io_list = ['smb', 'sql']
    database_bus_list = ['ethernet']
    # Setting the Sensor device specifics
    sensor_element = 'generic_sensor'
    sensor_io_list = ['ssh', 'http', 'ldap']
    sensor_bus_list = ['zigbee']
    # Setting the default implementation name for each device model implementation
    implementation_name = 'simple'
    ## Setting the System Model information
    system_bus_array = ['ethernet', 'zigbee']            # NOTE: While different arrays, this should match the 'server_bus_list' for the Smart Home AADL model
    system_io_list = ['http', 'smb']
    # Variables that are used in producing all the variations within the Smart Home model
    #   - TODO: Further variablize each device's io_list and other contents to provide a more modular and easily changable model
    device_io_map = {
            server_element : {
                'io_list' : server_io_list,
                'bus_connections' : server_bus_list                # Note: Have to set the protocol type here as well
                },
            database_element : {
                'io_list' : database_io_list,
                'bus_connections' : database_bus_list
                },
            application_element : {
                'io_list' : application_io_list,
                'bus_connections' : application_bus_list
                },
            graphical_user_interface_element : {
                'io_list' : graphical_user_interface_io_list,
                'bus_connections' : graphical_user_interface_bus_list 
                },
            sensor_element : {
                'io_list' : sensor_io_list,
                'bus_connections' : sensor_bus_list                 # Note: Have to set the protocol type here as well
                }
            }
    system_io_map = {
            'smart_home_network' : {
                'io_list' : system_io_list
                }
            }
    # TODO: Need to figure out the best way to populate this map to help automate connection of components
    system_implementation_map = {
            'smart_home_network' : {
                'ethernet_only' : {
                    'subcomponents' : {
                        'gui_element' : graphical_user_interface_element,
                        'application_element' : application_element,
                        'server_element' : server_element,
                        'database_element' : database_element,
                        'sensor_element' : sensor_element
                    },
                    'connections' : {
                        'bus_array' : system_bus_array,                     ## Internal system implementation buses
                        'external_ports': system_io_list                    ## system_external_ports_array       ## Same as the system_io_list???
                        }
                    }
                }
            }
    ## Function Call for Creating the package header for the AADL file
    # Start of the AADL model file
    genOpenHeader(packageName, aadlFilename)
    # Other inner parts of the AADL model file
    addEmptyLine(aadlFilename)
    # Bus and Data Definitions
    commentContent = 'Bus and Data Definitions'
    generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
    addEmptyLine(aadlFilename)
    generate_aadl_comment(aadlFilename, 'Bus Types', indentLevel=1)
    addEmptyLine(aadlFilename)
    ## Function Call for Creating the "Bus and Data Definitions" of the AADL file
    # Adding Bus Definitions
    for bus_type in bus_array:
        commentContent = '{0} Medium'.format(bus_type)
        generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
        generate_bus_medium_basic(aadlFilename, bus_type)
    addEmptyLine(aadlFilename)
    generate_aadl_comment(aadlFilename, 'Data Types', indentLevel=1)
    addEmptyLine(aadlFilename)
    # Adding Data Definitions
    for data_type in data_array:
        commentContent = '{0} Data Type'.format(data_type)
        generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
        generate_data_basic(aadlFilename, data_type)
    addEmptyLine(aadlFilename)
    # Function Call for Creating the "Device Definitions" of the AADL file
    generate_aadl_comment(aadlFilename, 'Definition of Devices', indentLevel=1)
    addEmptyLine(aadlFilename)
    #device_array = ['server', 'database', 'application', 'graphical_user_interface', 'generic_sensor']
    # TODO: Use the above array to populate a variety of devices
    #generate_smart_home_aadl_server_device(aadlFilename)
    #addEmptyLine(aadlFilename)
    #generate_smart_home_server_device_simple_implementation(aadlFilename)
    #addEmptyLine(aadlFilename)
    for device_element in device_io_map:
        generate_smart_home_aadl_custom_device(aadlFilename, device_element, device_io_map[device_element]['io_list'], device_io_map[device_element]['bus_connections'])
        addEmptyLine(aadlFilename)
        generate_smart_home_aadl_custom_device_custom_implementation(aadlFilename, device_element, implementation_name)
        addEmptyLine(aadlFilename)
    # Function Call for Creating the "Sysmte Definitions" of the AADL file
    generate_aadl_comment(aadlFilename, 'Definition of Systems', indentLevel=1)
    addEmptyLine(aadlFilename)
    #system_array = ['smart_home_network']
    generate_smart_home_aadl_network_system(aadlFilename, system_io_map)
    addEmptyLine(aadlFilename)
    #generate_smart_home_network_system_ethernet_only_implementation(aadlFilename, system_implementation_map)
    generate_smart_home_network_system_implementations(aadlFilename, system_implementation_map, device_io_map)
    addEmptyLine(aadlFilename)
    # Closing of the AADL mode file
    genEndHeader(packageName, aadlFilename)
    ## Testing custom device function call
    #generate_smart_home_aadl_custom_device(aadlFilename, device_name, io_list, bus_connections)
    #addEmptyLine(aadlFilename)
    #generate_smart_home_aadl_custom_device_custom_implementation(aadlFilename, device_name, implementation_name)
    #addEmptyLine(aadlFilename)
    #device_name = 'database'
    #print("[?] Testing device_io_map\n\tMap:\t{0}\n\tdevice_name:\t{1}\n\tSub Map:\t{2}\n\tSub IO List:\t{3}\n\tSub Bus List:\t{4}".format(device_io_map, device_name, device_io_map[device_name], device_io_map[device_name]['io_list'], device_io_map[device_name]['bus_connections']))
    #generate_smart_home_aadl_custom_device(aadlFilename, device_name, device_io_map[device_name]['io_list'], device_io_map[device_name]['bus_connections'])

# Function for generating the "Three Path" Smart Home AADL model - Scenario #1 - Smart Home with BreeZ Protocol Sensor
#   - Note: Ensure use of BreeZ Protocol Sensor
#       - [ ] Add in assocaited vulnerabilities into TAMSAT and SMART databases
def generate_smart_home_aadl_model_three_path_scenario_breez_sensor(aadlFilename, packageName):
    print("[*] Generating the Three Path Smart Home model")
    ### Setting the variables to be used in the generation of the Smart Home AADL model
    ## Setting the Basic Model information 
    bus_array = ['ethernet', 'wireless', 'bluetooth', 'nfc', 'usb', 'hardware_pins', 'breez']
    data_array = ['http', 'ssh', 'rdp', 'smb', 'ldap', 'sql', 'no_sql', 'uart', 'jtag']
    ## Setting the Device Model information
    # Setting the GUI device specifics
    graphical_user_interface_element = 'graphical_user_interface'
    graphical_user_interface_io_list = ['http', 'smb']
    graphical_user_interface_bus_list = ['ethernet']
    # Setting the Application device specifics
    application_element = 'application'
    application_io_list = ['http', 'ssh', 'smb']
    application_bus_list = ['ethernet']
    # Setting the Server device specifics
    server_element = 'server'
    server_io_list = ['http', 'ssh', 'smb', 'sql']
    server_bus_list = ['ethernet', 'breez']
    # Setting the Database device specifics
    database_element = 'database'
    database_io_list = ['smb', 'sql']
    database_bus_list = ['ethernet']
    # Setting the Sensor device specifics
    sensor_element = 'breez_sensor'
    sensor_io_list = ['ssh', 'http', 'ldap']
    sensor_bus_list = ['breez']
    # Setting the default implementation name for each device model implementation
    implementation_name = 'simple'
    ## Setting the System Model information
    system_bus_array = ['ethernet', 'breez']            # NOTE: While different arrays, this should match the 'server_bus_list' for the Smart Home AADL model
    system_io_list = ['http', 'smb']
    # Variables that are used in producing all the variations within the Smart Home model
    #   - TODO: Further variablize each device's io_list and other contents to provide a more modular and easily changable model
    device_io_map = {
            server_element : {
                'io_list' : server_io_list,
                'bus_connections' : server_bus_list                # Note: Have to set the protocol type here as well
                },
            database_element : {
                'io_list' : database_io_list,
                'bus_connections' : database_bus_list
                },
            application_element : {
                'io_list' : application_io_list,
                'bus_connections' : application_bus_list
                },
            graphical_user_interface_element : {
                'io_list' : graphical_user_interface_io_list,
                'bus_connections' : graphical_user_interface_bus_list 
                },
            sensor_element : {
                'io_list' : sensor_io_list,
                'bus_connections' : sensor_bus_list                 # Note: Have to set the protocol type here as well
                }
            }
    system_io_map = {
            'smart_home_network' : {
                'io_list' : system_io_list
                }
            }
    # TODO: Need to figure out the best way to populate this map to help automate connection of components
    system_implementation_map = {
            'smart_home_network' : {
                'ethernet_only' : {
                    'subcomponents' : {
                        'gui_element' : graphical_user_interface_element,
                        'application_element' : application_element,
                        'server_element' : server_element,
                        'database_element' : database_element,
                        'sensor_element' : sensor_element
                    },
                    'connections' : {
                        'bus_array' : system_bus_array,                     ## Internal system implementation buses
                        'external_ports': system_io_list                    ## system_external_ports_array       ## Same as the system_io_list???
                        }
                    }
                }
            }
    ## Function Call for Creating the package header for the AADL file
    # Start of the AADL model file
    genOpenHeader(packageName, aadlFilename)
    # Other inner parts of the AADL model file
    addEmptyLine(aadlFilename)
    # Bus and Data Definitions
    commentContent = 'Bus and Data Definitions'
    generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
    addEmptyLine(aadlFilename)
    generate_aadl_comment(aadlFilename, 'Bus Types', indentLevel=1)
    addEmptyLine(aadlFilename)
    ## Function Call for Creating the "Bus and Data Definitions" of the AADL file
    # Adding Bus Definitions
    for bus_type in bus_array:
        commentContent = '{0} Medium'.format(bus_type)
        generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
        generate_bus_medium_basic(aadlFilename, bus_type)
    addEmptyLine(aadlFilename)
    generate_aadl_comment(aadlFilename, 'Data Types', indentLevel=1)
    addEmptyLine(aadlFilename)
    # Adding Data Definitions
    for data_type in data_array:
        commentContent = '{0} Data Type'.format(data_type)
        generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
        generate_data_basic(aadlFilename, data_type)
    addEmptyLine(aadlFilename)
    # Function Call for Creating the "Device Definitions" of the AADL file
    generate_aadl_comment(aadlFilename, 'Definition of Devices', indentLevel=1)
    addEmptyLine(aadlFilename)
    #device_array = ['server', 'database', 'application', 'graphical_user_interface', 'breez_sensor']
    #device_array = ['server', 'database', 'application', 'graphical_user_interface', sensor_element]
    # TODO: Use the above array to populate a variety of devices
    #generate_smart_home_aadl_server_device(aadlFilename)
    #addEmptyLine(aadlFilename)
    #generate_smart_home_server_device_simple_implementation(aadlFilename)
    #addEmptyLine(aadlFilename)
    for device_element in device_io_map:
        generate_smart_home_aadl_custom_device(aadlFilename, device_element, device_io_map[device_element]['io_list'], device_io_map[device_element]['bus_connections'])
        addEmptyLine(aadlFilename)
        generate_smart_home_aadl_custom_device_custom_implementation(aadlFilename, device_element, implementation_name)
        addEmptyLine(aadlFilename)
    # Function Call for Creating the "Sysmte Definitions" of the AADL file
    generate_aadl_comment(aadlFilename, 'Definition of Systems', indentLevel=1)
    addEmptyLine(aadlFilename)
    #system_array = ['smart_home_network']
    generate_smart_home_aadl_network_system(aadlFilename, system_io_map)
    addEmptyLine(aadlFilename)
    #generate_smart_home_network_system_ethernet_only_implementation(aadlFilename, sensor_element, server_element, database_element)    # Note: Use of '1' here for BreeZ implementation   |   Changed to passing custom element names
    generate_smart_home_network_system_implementations(aadlFilename, system_implementation_map, device_io_map)
    addEmptyLine(aadlFilename)
    # Closing of the AADL mode file
    genEndHeader(packageName, aadlFilename)

# Function for generating the "Three Path" Smart Home AADL model - Scenario #2 - Smart Home with Oracle MySQL Server
#   - Note: Ensure use of Oracle MySQL Server Database
#       - [ ] Add in assocaited vulnerabilities into TAMSAT and SMART databases
def generate_smart_home_aadl_model_three_path_scenario_oracle_mysql_server(aadlFilename, packageName):
    print("[*] Generating the Three Path Smart Home model")
    ### Setting the variables to be used in the generation of the Smart Home AADL model
    ## Setting the Basic Model information 
    bus_array = ['ethernet', 'wireless', 'bluetooth', 'zigbee', 'nfc', 'usb', 'hardware_pins']
    data_array = ['http', 'ssh', 'rdp', 'smb', 'ldap', 'sql', 'no_sql', 'uart', 'jtag']
    ## Setting the Device Model information
    # Setting the GUI device specifics
    graphical_user_interface_element = 'graphical_user_interface'
    graphical_user_interface_io_list = ['http', 'smb']
    graphical_user_interface_bus_list = ['ethernet']
    # Setting the Application device specifics
    application_element = 'application'
    application_io_list = ['http', 'ssh', 'smb']
    application_bus_list = ['ethernet']
    # Setting the Server device specifics
    server_element = 'server'
    server_io_list = ['http', 'ssh', 'smb', 'sql']
    server_bus_list = ['ethernet', 'zigbee']
    # Setting the Database device specifics
    database_element = 'oracle_database'
    database_io_list = ['smb', 'sql']
    database_bus_list = ['ethernet']
    # Setting the Sensor device specifics
    sensor_element = 'generic_sensor'
    sensor_io_list = ['ssh', 'http', 'ldap']
    sensor_bus_list = ['zigbee']
    # Setting the default implementation name for each device model implementation
    implementation_name = 'simple'
    ## Setting the System Model information
    system_bus_array = ['ethernet', 'zigbee']            # NOTE: While different arrays, this should match the 'server_bus_list' for the Smart Home AADL model
    system_io_list = ['http', 'smb']
    # Variables that are used in producing all the variations within the Smart Home model
    #   - TODO: Further variablize each device's io_list and other contents to provide a more modular and easily changable model
    device_io_map = {
            server_element : {
                'io_list' : server_io_list,
                'bus_connections' : server_bus_list                # Note: Have to set the protocol type here as well
                },
            database_element : {
                'io_list' : database_io_list,
                'bus_connections' : database_bus_list
                },
            application_element : {
                'io_list' : application_io_list,
                'bus_connections' : application_bus_list
                },
            graphical_user_interface_element : {
                'io_list' : graphical_user_interface_io_list,
                'bus_connections' : graphical_user_interface_bus_list 
                },
            sensor_element : {
                'io_list' : sensor_io_list,
                'bus_connections' : sensor_bus_list                 # Note: Have to set the protocol type here as well
                }
            }
    system_io_map = {
            'smart_home_network' : {
                'io_list' : system_io_list
                }
            }
    # TODO: Need to figure out the best way to populate this map to help automate connection of components
    system_implementation_map = {
            'smart_home_network' : {
                'ethernet_only' : {
                    'subcomponents' : {
                        'gui_element' : graphical_user_interface_element,
                        'application_element' : application_element,
                        'server_element' : server_element,
                        'database_element' : database_element,
                        'sensor_element' : sensor_element
                    },
                    'connections' : {
                        'bus_array' : system_bus_array,                     ## Internal system implementation buses
                        'external_ports': system_io_list                    ## system_external_ports_array       ## Same as the system_io_list???
                        }
                    }
                }
            }
    ## Function Call for Creating the package header for the AADL file
    # Start of the AADL model file
    genOpenHeader(packageName, aadlFilename)
    # Other inner parts of the AADL model file
    addEmptyLine(aadlFilename)
    # Bus and Data Definitions
    commentContent = 'Bus and Data Definitions'
    generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
    addEmptyLine(aadlFilename)
    generate_aadl_comment(aadlFilename, 'Bus Types', indentLevel=1)
    addEmptyLine(aadlFilename)
    ## Function Call for Creating the "Bus and Data Definitions" of the AADL file
    # Adding Bus Definitions
    for bus_type in bus_array:
        commentContent = '{0} Medium'.format(bus_type)
        generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
        generate_bus_medium_basic(aadlFilename, bus_type)
    addEmptyLine(aadlFilename)
    generate_aadl_comment(aadlFilename, 'Data Types', indentLevel=1)
    addEmptyLine(aadlFilename)
    # Adding Data Definitions
    for data_type in data_array:
        commentContent = '{0} Data Type'.format(data_type)
        generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
        generate_data_basic(aadlFilename, data_type)
    addEmptyLine(aadlFilename)
    # Function Call for Creating the "Device Definitions" of the AADL file
    generate_aadl_comment(aadlFilename, 'Definition of Devices', indentLevel=1)
    addEmptyLine(aadlFilename)
    #device_array = ['server', 'database', 'application', 'graphical_user_interface', 'breez_sensor']
    #device_array = [server_element, database_element, 'application', 'graphical_user_interface', sensor_element]
    # TODO: Use the above array to populate a variety of devices
    #generate_smart_home_aadl_server_device(aadlFilename)
    #addEmptyLine(aadlFilename)
    #generate_smart_home_server_device_simple_implementation(aadlFilename)
    #addEmptyLine(aadlFilename)
    for device_element in device_io_map:
        generate_smart_home_aadl_custom_device(aadlFilename, device_element, device_io_map[device_element]['io_list'], device_io_map[device_element]['bus_connections'])
        addEmptyLine(aadlFilename)
        generate_smart_home_aadl_custom_device_custom_implementation(aadlFilename, device_element, implementation_name)
        addEmptyLine(aadlFilename)
    # Function Call for Creating the "Sysmte Definitions" of the AADL file
    generate_aadl_comment(aadlFilename, 'Definition of Systems', indentLevel=1)
    addEmptyLine(aadlFilename)
    #system_array = ['smart_home_network']
    generate_smart_home_aadl_network_system(aadlFilename, system_io_map)
    addEmptyLine(aadlFilename)
    print("[????] Checking variables before function()\n\tAADL Filename:\t\t{0}\n\tSensor Element:\t\t{1}\n\tServer Element:\t\t{2}\n\tDatabase Element:\t\t{3}".format(aadlFilename, sensor_element, server_element, database_element))
    #generate_smart_home_network_system_ethernet_only_implementation(aadlFilename, sensor_element, server_element, database_element)    # Note: Use of '1' here for BreeZ implementation   |   Changed to passing custom element names
    generate_smart_home_network_system_implementations(aadlFilename, system_implementation_map, device_io_map)
    addEmptyLine(aadlFilename)
    # Closing of the AADL mode file
    genEndHeader(packageName, aadlFilename)

# Function for generating the "Three Path" Smart Home AADL model - Scenario #3 - Smart Home with Intel Xeon Processor Server
#   - Note: Ensure use of Intel Server
#       - [ ] Add in assocaited vulnerabilities into TAMSAT and SMART databases
def generate_smart_home_aadl_model_three_path_scenario_intel_xeon_processor_server(aadlFilename, packageName):
    print("[*] Generating the Three Path Smart Home model")
    ### Setting the variables to be used in the generation of the Smart Home AADL model
    ## Setting the Basic Model information 
    bus_array = ['ethernet', 'wireless', 'bluetooth', 'zigbee', 'nfc', 'usb', 'hardware_pins']
    data_array = ['http', 'ssh', 'rdp', 'smb', 'ldap', 'sql', 'no_sql', 'uart', 'jtag']
    ## Setting the Device Model information
    # Setting the GUI device specifics
    graphical_user_interface_element = 'graphical_user_interface'
    graphical_user_interface_io_list = ['http', 'smb']
    graphical_user_interface_bus_list = ['ethernet']
    # Setting the Application device specifics
    application_element = 'application'
    application_io_list = ['http', 'ssh', 'smb']
    application_bus_list = ['ethernet']
    # Setting the Server device specifics
    server_element = 'intel_server'
    server_io_list = ['http', 'ssh', 'smb', 'sql']
    server_bus_list = ['ethernet', 'zigbee']
    # Setting the Database device specifics
    database_element = 'database'
    database_io_list = ['smb', 'sql']
    database_bus_list = ['ethernet']
    # Setting the Sensor device specifics
    sensor_element = 'generic_sensor'
    sensor_io_list = ['ssh', 'http', 'ldap']
    sensor_bus_list = ['zigbee']
    # Setting the default implementation name for each device model implementation
    implementation_name = 'simple'
    ## Setting the System Model information
    system_bus_array = ['ethernet', 'zigbee']            # NOTE: While different arrays, this should match the 'server_bus_list' for the Smart Home AADL model
    system_io_list = ['http', 'smb']
    # Variables that are used in producing all the variations within the Smart Home model
    #   - TODO: Further variablize each device's io_list and other contents to provide a more modular and easily changable model
    device_io_map = {
            server_element : {
                'io_list' : server_io_list,
                'bus_connections' : server_bus_list                # Note: Have to set the protocol type here as well
                },
            database_element : {
                'io_list' : database_io_list,
                'bus_connections' : database_bus_list
                },
            application_element : {
                'io_list' : application_io_list,
                'bus_connections' : application_bus_list
                },
            graphical_user_interface_element : {
                'io_list' : graphical_user_interface_io_list,
                'bus_connections' : graphical_user_interface_bus_list 
                },
            sensor_element : {
                'io_list' : sensor_io_list,
                'bus_connections' : sensor_bus_list                 # Note: Have to set the protocol type here as well
                }
            }
    system_io_map = {
            'smart_home_network' : {
                'io_list' : system_io_list
                }
            }
    # TODO: Need to figure out the best way to populate this map to help automate connection of components
    system_implementation_map = {
            'smart_home_network' : {
                'ethernet_only' : {
                    'subcomponents' : {
                        'gui_element' : graphical_user_interface_element,
                        'application_element' : application_element,
                        'server_element' : server_element,
                        'database_element' : database_element,
                        'sensor_element' : sensor_element
                    },
                    'connections' : {
                        'bus_array' : system_bus_array,                     ## Internal system implementation buses
                        'external_ports': system_io_list                    ## system_external_ports_array       ## Same as the system_io_list???
                        }
                    }
                }
            }
    ## Function Call for Creating the package header for the AADL file
    # Start of the AADL model file
    genOpenHeader(packageName, aadlFilename)
    # Other inner parts of the AADL model file
    addEmptyLine(aadlFilename)
    # Bus and Data Definitions
    commentContent = 'Bus and Data Definitions'
    generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
    addEmptyLine(aadlFilename)
    generate_aadl_comment(aadlFilename, 'Bus Types', indentLevel=1)
    addEmptyLine(aadlFilename)
    ## Function Call for Creating the "Bus and Data Definitions" of the AADL file
    # Adding Bus Definitions
    for bus_type in bus_array:
        commentContent = '{0} Medium'.format(bus_type)
        generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
        generate_bus_medium_basic(aadlFilename, bus_type)
    addEmptyLine(aadlFilename)
    generate_aadl_comment(aadlFilename, 'Data Types', indentLevel=1)
    addEmptyLine(aadlFilename)
    # Adding Data Definitions
    for data_type in data_array:
        commentContent = '{0} Data Type'.format(data_type)
        generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
        generate_data_basic(aadlFilename, data_type)
    addEmptyLine(aadlFilename)
    # Function Call for Creating the "Device Definitions" of the AADL file
    generate_aadl_comment(aadlFilename, 'Definition of Devices', indentLevel=1)
    addEmptyLine(aadlFilename)
    #device_array = ['server', 'database', 'application', 'graphical_user_interface', 'breez_sensor']
    #device_array = [server_element, database_element, 'application', 'graphical_user_interface', sensor_element]
    # TODO: Use the above array to populate a variety of devices
    #generate_smart_home_aadl_server_device(aadlFilename)
    #addEmptyLine(aadlFilename)
    #generate_smart_home_server_device_simple_implementation(aadlFilename)
    #addEmptyLine(aadlFilename)
    for device_element in device_io_map:
        generate_smart_home_aadl_custom_device(aadlFilename, device_element, device_io_map[device_element]['io_list'], device_io_map[device_element]['bus_connections'])
        addEmptyLine(aadlFilename)
        generate_smart_home_aadl_custom_device_custom_implementation(aadlFilename, device_element, implementation_name)
        addEmptyLine(aadlFilename)
    # Function Call for Creating the "Sysmte Definitions" of the AADL file
    generate_aadl_comment(aadlFilename, 'Definition of Systems', indentLevel=1)
    addEmptyLine(aadlFilename)
    #system_array = ['smart_home_network']
    generate_smart_home_aadl_network_system(aadlFilename, system_io_map)
    addEmptyLine(aadlFilename)
    #generate_smart_home_network_system_ethernet_only_implementation(aadlFilename, sensor_element, server_element, database_element)    # Note: Use of '1' here for BreeZ implementation   |   Changed to passing custom element names
    generate_smart_home_network_system_implementations(aadlFilename, system_implementation_map, device_io_map)
    addEmptyLine(aadlFilename)
    # Closing of the AADL mode file
    genEndHeader(packageName, aadlFilename)

# Function for generating the "Three Path" Smart Home AADL model - Scenario #4 - Smart Home with ASPEED Server
#   - Note: Ensure use of ASPEED Server
#       - [ ] Add in assocaited vulnerabilities into TAMSAT and SMART databases
def generate_smart_home_aadl_model_three_path_scenario_aspeed_ast_server(aadlFilename, packageName):
    print("[*] Generating the Three Path Smart Home model")
    ### Setting the variables to be used in the generation of the Smart Home AADL model
    ## Setting the Basic Model information 
    bus_array = ['ethernet', 'wireless', 'bluetooth', 'zigbee', 'nfc', 'usb', 'hardware_pins']
    data_array = ['http', 'ssh', 'rdp', 'smb', 'ldap', 'sql', 'no_sql', 'uart', 'jtag']
    ## Setting the Device Model information
    # Setting the GUI device specifics
    graphical_user_interface_element = 'graphical_user_interface'
    graphical_user_interface_io_list = ['http', 'smb']
    graphical_user_interface_bus_list = ['ethernet']
    # Setting the Application device specifics
    application_element = 'application'
    application_io_list = ['http', 'ssh', 'smb']
    application_bus_list = ['ethernet']
    # Setting the Server device specifics
    server_element = 'aspeed_server'
    server_io_list = ['http', 'ssh', 'smb', 'sql']
    server_bus_list = ['ethernet', 'zigbee', 'uart']
    # Setting the Database device specifics
    database_element = 'database'
    database_io_list = ['smb', 'sql']
    database_bus_list = ['ethernet']
    # Setting the Sensor device specifics
    sensor_element = 'generic_sensor'
    sensor_io_list = ['ssh', 'http', 'ldap']
    sensor_bus_list = ['zigbee']
    # Setting the default implementation name for each device model implementation
    implementation_name = 'simple'
    ## Setting the System Model information
    system_bus_array = ['ethernet', 'zigbee']            # NOTE: While different arrays, this should match the 'server_bus_list' for the Smart Home AADL model
    system_io_list = ['http', 'smb']
    # Variables that are used in producing all the variations within the Smart Home model
    #   - TODO: Further variablize each device's io_list and other contents to provide a more modular and easily changable model
    device_io_map = {
            server_element : {
                'io_list' : server_io_list,
                'bus_connections' : server_bus_list                # Note: Have to set the protocol type here as well
                },
            database_element : {
                'io_list' : database_io_list,
                'bus_connections' : database_bus_list
                },
            application_element : {
                'io_list' : application_io_list,
                'bus_connections' : application_bus_list
                },
            graphical_user_interface_element : {
                'io_list' : graphical_user_interface_io_list,
                'bus_connections' : graphical_user_interface_bus_list 
                },
            sensor_element : {
                'io_list' : sensor_io_list,
                'bus_connections' : sensor_bus_list                 # Note: Have to set the protocol type here as well
                }
            }
    system_io_map = {
            'smart_home_network' : {
                'io_list' : system_io_list
                }
            }
    # TODO: Need to figure out the best way to populate this map to help automate connection of components
    system_implementation_map = {
            'smart_home_network' : {
                'ethernet_only' : {
                    'subcomponents' : {
                        'gui_element' : graphical_user_interface_element,
                        'application_element' : application_element,
                        'server_element' : server_element,
                        'database_element' : database_element,
                        'sensor_element' : sensor_element
                    },
                    'connections' : {
                        'bus_array' : system_bus_array,                     ## Internal system implementation buses
                        'external_ports': system_io_list                    ## system_external_ports_array       ## Same as the system_io_list???
                        }
                    }
                }
            }
    ## Function Call for Creating the package header for the AADL file
    # Start of the AADL model file
    genOpenHeader(packageName, aadlFilename)
    # Other inner parts of the AADL model file
    addEmptyLine(aadlFilename)
    # Bus and Data Definitions
    commentContent = 'Bus and Data Definitions'
    generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
    addEmptyLine(aadlFilename)
    generate_aadl_comment(aadlFilename, 'Bus Types', indentLevel=1)
    addEmptyLine(aadlFilename)
    ## Function Call for Creating the "Bus and Data Definitions" of the AADL file
    # Adding Bus Definitions
    for bus_type in bus_array:
        commentContent = '{0} Medium'.format(bus_type)
        generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
        generate_bus_medium_basic(aadlFilename, bus_type)
    addEmptyLine(aadlFilename)
    generate_aadl_comment(aadlFilename, 'Data Types', indentLevel=1)
    addEmptyLine(aadlFilename)
    # Adding Data Definitions
    for data_type in data_array:
        commentContent = '{0} Data Type'.format(data_type)
        generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
        generate_data_basic(aadlFilename, data_type)
    addEmptyLine(aadlFilename)
    # Function Call for Creating the "Device Definitions" of the AADL file
    generate_aadl_comment(aadlFilename, 'Definition of Devices', indentLevel=1)
    addEmptyLine(aadlFilename)
    #device_array = ['server', 'database', 'application', 'graphical_user_interface', 'breez_sensor']
    #device_array = [server_element, database_element, 'application', 'graphical_user_interface', sensor_element]
    # TODO: Use the above array to populate a variety of devices
    #generate_smart_home_aadl_server_device(aadlFilename)
    #addEmptyLine(aadlFilename)
    #generate_smart_home_server_device_simple_implementation(aadlFilename)
    #addEmptyLine(aadlFilename)
    for device_element in device_io_map:
        generate_smart_home_aadl_custom_device(aadlFilename, device_element, device_io_map[device_element]['io_list'], device_io_map[device_element]['bus_connections'])
        addEmptyLine(aadlFilename)
        generate_smart_home_aadl_custom_device_custom_implementation(aadlFilename, device_element, implementation_name)
        addEmptyLine(aadlFilename)
    # Function Call for Creating the "Sysmte Definitions" of the AADL file
    generate_aadl_comment(aadlFilename, 'Definition of Systems', indentLevel=1)
    addEmptyLine(aadlFilename)
    #system_array = ['smart_home_network']
    generate_smart_home_aadl_network_system(aadlFilename, system_io_map)
    addEmptyLine(aadlFilename)
    #generate_smart_home_network_system_ethernet_only_implementation(aadlFilename, sensor_element, server_element, database_element)    # Note: Use of '1' here for BreeZ implementation   |   Changed to passing custom element names
    generate_smart_home_network_system_implementations(aadlFilename, system_implementation_map, device_io_map)
    addEmptyLine(aadlFilename)
    # Closing of the AADL mode file
    genEndHeader(packageName, aadlFilename)

# Function for generating the "Three Path" Smart Home AADL model - Scenario #5 - Smart Home with Oracle Database, Intel Server, and BreeZ Sensor
#   - Note: Ensure use of Oracle MySQL Database Server
#   - Note: Ensure use of Intel Server
#   - Note: Ensure use of BreeZ Sensor
#       - [ ] Add in assocaited vulnerabilities into TAMSAT and SMART databases
def generate_smart_home_aadl_model_three_path_scenario_breez_oracle_mysql_intel_xeon_model(aadlFilename, packageName):
    print("[*] Generating the Three Path Smart Home model")
    ### Setting the variables to be used in the generation of the Smart Home AADL model
    ## Setting the Basic Model information 
    bus_array = ['ethernet', 'wireless', 'bluetooth', 'breez', 'nfc', 'usb', 'hardware_pins']      # NOTE: Changed 'zigbee' here for 'breez'
    data_array = ['http', 'ssh', 'rdp', 'smb', 'ldap', 'sql', 'no_sql', 'uart', 'jtag']
    ## Setting the Device Model information
    # Setting the GUI device specifics
    graphical_user_interface_element = 'graphical_user_interface'
    graphical_user_interface_io_list = ['http', 'smb']
    graphical_user_interface_bus_list = ['ethernet']
    # Setting the Application device specifics
    application_element = 'application'
    application_io_list = ['http', 'ssh', 'smb']
    application_bus_list = ['ethernet']
    # Setting the Server device specifics
    server_element = 'intel_server'
    server_io_list = ['http', 'ssh', 'smb', 'sql']
    server_bus_list = ['ethernet', 'breez']
    # Setting the Database device specifics
    database_element = 'oracle_database'
    database_io_list = ['smb', 'sql']
    database_bus_list = ['ethernet']
    # Setting the Sensor device specifics
    sensor_element = 'breez_sensor'
    sensor_io_list = ['ssh', 'http', 'ldap']
    sensor_bus_list = ['breez']
    # Setting the default implementation name for each device model implementation
    implementation_name = 'simple'
    ## Setting the System Model information
    system_bus_array = ['ethernet', 'breez']            # NOTE: While different arrays, this should match the 'server_bus_list' for the Smart Home AADL model
    system_io_list = ['http', 'smb']
    # Variables that are used in producing all the variations within the Smart Home model
    #   - TODO: Further variablize each device's io_list and other contents to provide a more modular and easily changable model
    device_io_map = {
            server_element : {
                'io_list' : server_io_list,
                'bus_connections' : server_bus_list                # Note: Have to set the protocol type here as well
                },
            database_element : {
                'io_list' : database_io_list,
                'bus_connections' : database_bus_list
                },
            application_element : {
                'io_list' : application_io_list,
                'bus_connections' : application_bus_list
                },
            graphical_user_interface_element : {
                'io_list' : graphical_user_interface_io_list,
                'bus_connections' : graphical_user_interface_bus_list 
                },
            sensor_element : {
                'io_list' : sensor_io_list,
                'bus_connections' : sensor_bus_list                 # Note: Have to set the protocol type here as well
                }
            }
    system_io_map = {
            'smart_home_network' : {
                'io_list' : system_io_list
                }
            }
    # TODO: Need to figure out the best way to populate this map to help automate connection of components
    system_implementation_map = {
            'smart_home_network' : {
                'ethernet_only' : {
                    'subcomponents' : {
                        'gui_element' : graphical_user_interface_element,
                        'application_element' : application_element,
                        'server_element' : server_element,
                        'database_element' : database_element,
                        'sensor_element' : sensor_element
                    },
                    'connections' : {
                        'bus_array' : system_bus_array,                     ## Internal system implementation buses
                        'external_ports': system_io_list                    ## system_external_ports_array       ## Same as the system_io_list???
                        }
                    }
                }
            }
    ## Function Call for Creating the package header for the AADL file
    # Start of the AADL model file
    genOpenHeader(packageName, aadlFilename)
    # Other inner parts of the AADL model file
    addEmptyLine(aadlFilename)
    # Bus and Data Definitions
    commentContent = 'Bus and Data Definitions'
    generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
    addEmptyLine(aadlFilename)
    generate_aadl_comment(aadlFilename, 'Bus Types', indentLevel=1)
    addEmptyLine(aadlFilename)
    ## Function Call for Creating the "Bus and Data Definitions" of the AADL file
    # Adding Bus Definitions
    for bus_type in bus_array:
        commentContent = '{0} Medium'.format(bus_type)
        generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
        generate_bus_medium_basic(aadlFilename, bus_type)
    addEmptyLine(aadlFilename)
    generate_aadl_comment(aadlFilename, 'Data Types', indentLevel=1)
    addEmptyLine(aadlFilename)
    # Adding Data Definitions
    for data_type in data_array:
        commentContent = '{0} Data Type'.format(data_type)
        generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
        generate_data_basic(aadlFilename, data_type)
    addEmptyLine(aadlFilename)
    # Function Call for Creating the "Device Definitions" of the AADL file
    generate_aadl_comment(aadlFilename, 'Definition of Devices', indentLevel=1)
    addEmptyLine(aadlFilename)
    #device_array = ['server', 'database', 'application', 'graphical_user_interface', 'breez_sensor']
    device_array = [server_element, database_element, 'application', 'graphical_user_interface', sensor_element]
    # TODO: Use the above array to populate a variety of devices
    #generate_smart_home_aadl_server_device(aadlFilename)
    #addEmptyLine(aadlFilename)
    #generate_smart_home_server_device_simple_implementation(aadlFilename)
    #addEmptyLine(aadlFilename)
    for device_element in device_io_map:
        generate_smart_home_aadl_custom_device(aadlFilename, device_element, device_io_map[device_element]['io_list'], device_io_map[device_element]['bus_connections'])
        addEmptyLine(aadlFilename)
        generate_smart_home_aadl_custom_device_custom_implementation(aadlFilename, device_element, implementation_name)
        addEmptyLine(aadlFilename)
    # Function Call for Creating the "Sysmte Definitions" of the AADL file
    generate_aadl_comment(aadlFilename, 'Definition of Systems', indentLevel=1)
    addEmptyLine(aadlFilename)
    system_array = ['smart_home_network']
    generate_smart_home_aadl_network_system(aadlFilename, system_io_map)
    addEmptyLine(aadlFilename)
    #generate_smart_home_network_system_ethernet_only_implementation(aadlFilename, sensor_element, server_element, database_element)    # Note: Use of '1' here for BreeZ implementation   |   Changed to passing custom element names
    generate_smart_home_network_system_implementations(aadlFilename, system_implementation_map, device_io_map)
    addEmptyLine(aadlFilename)
    # Closing of the AADL mode file
    genEndHeader(packageName, aadlFilename)

# Function for generating the "Three Path" Smart Home AADL model - Scenario #6 - Smart Home with Oracle Database, ASPEED Server, and BreeZ Sensor
#   - Note: Ensure use of Oracle MySQL Database Server
#   - Note: Ensure use of ASPEED Server
#   - Note: Ensure use of BreeZ Sensor
#       - [ ] Add in assocaited vulnerabilities into TAMSAT and SMART databases
def generate_smart_home_aadl_model_three_path_scenario_breez_oracle_mysql_aspeed_model(aadlFilename, packageName):
    print("[*] Generating the Three Path Smart Home model")
    ### Setting the variables to be used in the generation of the Smart Home AADL model
    ## Setting the Basic Model information 
    bus_array = ['ethernet', 'wireless', 'bluetooth', 'zigbee', 'nfc', 'usb', 'hardware_pins', 'breez']      # Replace 'zigbee' or just add 'breez'
    data_array = ['http', 'ssh', 'rdp', 'smb', 'ldap', 'sql', 'no_sql', 'uart', 'jtag']
    ## Setting the Device Model information
    # Setting the GUI device specifics
    graphical_user_interface_element = 'graphical_user_interface'
    graphical_user_interface_io_list = ['http', 'smb']
    graphical_user_interface_bus_list = ['ethernet']
    # Setting the Application device specifics
    application_element = 'application'
    application_io_list = ['http', 'ssh', 'smb']
    application_bus_list = ['ethernet']
    # Setting the Server device specifics
    server_element = 'aspeed_server'
    server_io_list = ['http', 'ssh', 'smb', 'sql']
    server_bus_list = ['ethernet', 'breez', 'uart']
    # Setting the Database device specifics
    database_element = 'oracle_database'
    database_io_list = ['smb', 'sql']
    database_bus_list = ['ethernet']
    # Setting the Sensor device specifics
    sensor_element = 'breez_sensor'
    sensor_io_list = ['ssh', 'http', 'ldap']
    sensor_bus_list = ['breez']
    # Setting the default implementation name for each device model implementation
    implementation_name = 'simple'
    ## Setting the System Model information
    system_bus_array = ['ethernet', 'breez']            # NOTE: While different arrays, this should match the 'server_bus_list' for the Smart Home AADL model
    system_io_list = ['http', 'smb']
    # Variables that are used in producing all the variations within the Smart Home model
    #   - TODO: Further variablize each device's io_list and other contents to provide a more modular and easily changable model
    device_io_map = {
            server_element : {
                'io_list' : server_io_list,
                'bus_connections' : server_bus_list                # Note: Have to set the protocol type here as well
                },
            database_element : {
                'io_list' : database_io_list,
                'bus_connections' : database_bus_list
                },
            application_element : {
                'io_list' : application_io_list,
                'bus_connections' : application_bus_list
                },
            graphical_user_interface_element : {
                'io_list' : graphical_user_interface_io_list,
                'bus_connections' : graphical_user_interface_bus_list 
                },
            sensor_element : {
                'io_list' : sensor_io_list,
                'bus_connections' : sensor_bus_list                 # Note: Have to set the protocol type here as well
                }
            }
    system_io_map = {
            'smart_home_network' : {
                'io_list' : system_io_list
                }
            }
    # TODO: Need to figure out the best way to populate this map to help automate connection of components
    system_implementation_map = {
            'smart_home_network' : {
                'ethernet_only' : {
                    'subcomponents' : {
                        'gui_element' : graphical_user_interface_element,
                        'application_element' : application_element,
                        'server_element' : server_element,
                        'database_element' : database_element,
                        'sensor_element' : sensor_element
                    },
                    'connections' : {
                        'bus_array' : system_bus_array,                     ## Internal system implementation buses
                        'external_ports': system_io_list                    ## system_external_ports_array       ## Same as the system_io_list???
                        }
                    }
                }
            }
    ## Function Call for Creating the package header for the AADL file
    # Start of the AADL model file
    genOpenHeader(packageName, aadlFilename)
    # Other inner parts of the AADL model file
    addEmptyLine(aadlFilename)
    # Bus and Data Definitions
    commentContent = 'Bus and Data Definitions'
    generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
    addEmptyLine(aadlFilename)
    generate_aadl_comment(aadlFilename, 'Bus Types', indentLevel=1)
    addEmptyLine(aadlFilename)
    ## Function Call for Creating the "Bus and Data Definitions" of the AADL file
    # Adding Bus Definitions
    for bus_type in bus_array:
        commentContent = '{0} Medium'.format(bus_type)
        generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
        generate_bus_medium_basic(aadlFilename, bus_type)
    addEmptyLine(aadlFilename)
    generate_aadl_comment(aadlFilename, 'Data Types', indentLevel=1)
    addEmptyLine(aadlFilename)
    # Adding Data Definitions
    for data_type in data_array:
        commentContent = '{0} Data Type'.format(data_type)
        generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
        generate_data_basic(aadlFilename, data_type)
    addEmptyLine(aadlFilename)
    # Function Call for Creating the "Device Definitions" of the AADL file
    generate_aadl_comment(aadlFilename, 'Definition of Devices', indentLevel=1)
    addEmptyLine(aadlFilename)
    #device_array = ['server', 'database', 'application', 'graphical_user_interface', 'breez_sensor']
    #device_array = [server_element, database_element, 'application', 'graphical_user_interface', sensor_element]
    # TODO: Use the above array to populate a variety of devices
    #generate_smart_home_aadl_server_device(aadlFilename)
    #addEmptyLine(aadlFilename)
    #generate_smart_home_server_device_simple_implementation(aadlFilename)
    #addEmptyLine(aadlFilename)
    # Use the device_io_map for iteration INSTEAD of the OLDER device_array
    for device_element in device_io_map:
        generate_smart_home_aadl_custom_device(aadlFilename, device_element, device_io_map[device_element]['io_list'], device_io_map[device_element]['bus_connections'])
        addEmptyLine(aadlFilename)
        generate_smart_home_aadl_custom_device_custom_implementation(aadlFilename, device_element, implementation_name)
        addEmptyLine(aadlFilename)
    # Function Call for Creating the "Sysmte Definitions" of the AADL file
    generate_aadl_comment(aadlFilename, 'Definition of Systems', indentLevel=1)
    addEmptyLine(aadlFilename)
    #system_array = ['smart_home_network']
    generate_smart_home_aadl_network_system(aadlFilename, system_io_map)
    addEmptyLine(aadlFilename)
    #generate_smart_home_network_system_ethernet_only_implementation(aadlFilename, sensor_element, server_element, database_element)    # Note: Use of '1' here for BreeZ implementation   |   Changed to passing custom element names
    generate_smart_home_network_system_implementations(aadlFilename, system_implementation_map, device_io_map)
    addEmptyLine(aadlFilename)
    # Closing of the AADL mode file
    genEndHeader(packageName, aadlFilename)

# Function for generating the "Three Path" Smart Home AADL model based on provided:
#   device_io_map
#   system_io_map
#   system_implementation_map
#   bus_array
#   data_array
def generate_smart_home_aadl_model_three_path_scenario_model(aadlFilename, packageName, bus_array, data_array, device_io_map, system_io_map, system_implementation_map):
    print("[*] Generating the Three Path Smart Home model")
    # Setting the default implementation name for each device model implementation
    implementation_name = 'simple'
    ## Function Call for Creating the package header for the AADL file
    # Start of the AADL model file
    genOpenHeader(packageName, aadlFilename)
    # Other inner parts of the AADL model file
    addEmptyLine(aadlFilename)
    # Bus and Data Definitions
    commentContent = 'Bus and Data Definitions'
    generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
    addEmptyLine(aadlFilename)
    generate_aadl_comment(aadlFilename, 'Bus Types', indentLevel=1)
    addEmptyLine(aadlFilename)
    ## Function Call for Creating the "Bus and Data Definitions" of the AADL file
    # Adding Bus Definitions
    for bus_type in bus_array:
        commentContent = '{0} Medium'.format(bus_type)
        generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
        generate_bus_medium_basic(aadlFilename, bus_type)
    addEmptyLine(aadlFilename)
    generate_aadl_comment(aadlFilename, 'Data Types', indentLevel=1)
    addEmptyLine(aadlFilename)
    # Adding Data Definitions
    for data_type in data_array:
        commentContent = '{0} Data Type'.format(data_type)
        generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
        generate_data_basic(aadlFilename, data_type)
    addEmptyLine(aadlFilename)
    # Function Call for Creating the "Device Definitions" of the AADL file
    generate_aadl_comment(aadlFilename, 'Definition of Devices', indentLevel=1)
    addEmptyLine(aadlFilename)
    #device_array = ['server', 'database', 'application', 'graphical_user_interface', 'breez_sensor']
    #device_array = [server_element, database_element, 'application', 'graphical_user_interface', sensor_element]
    # TODO: Use the above array to populate a variety of devices
    #generate_smart_home_aadl_server_device(aadlFilename)
    #addEmptyLine(aadlFilename)
    #generate_smart_home_server_device_simple_implementation(aadlFilename)
    #addEmptyLine(aadlFilename)
    # Use the device_io_map for iteration INSTEAD of the OLDER device_array
    for device_element in device_io_map:
        generate_smart_home_aadl_custom_device(aadlFilename, device_element, device_io_map[device_element]['io_list'], device_io_map[device_element]['bus_connections'])
        addEmptyLine(aadlFilename)
        generate_smart_home_aadl_custom_device_custom_implementation(aadlFilename, device_element, implementation_name)
        addEmptyLine(aadlFilename)
    # Function Call for Creating the "Sysmte Definitions" of the AADL file
    generate_aadl_comment(aadlFilename, 'Definition of Systems', indentLevel=1)
    addEmptyLine(aadlFilename)
    #system_array = ['smart_home_network']
    generate_smart_home_aadl_network_system(aadlFilename, system_io_map)
    addEmptyLine(aadlFilename)
    #generate_smart_home_network_system_ethernet_only_implementation(aadlFilename, sensor_element, server_element, database_element)    # Note: Use of '1' here for BreeZ implementation   |   Changed to passing custom element names
    generate_smart_home_network_system_implementations(aadlFilename, system_implementation_map, device_io_map)
    addEmptyLine(aadlFilename)
    # Closing of the AADL mode file
    genEndHeader(packageName, aadlFilename)

# Function for generating the "Three Path" Smart Home AADL model - Scenario #7 - Smart Home with MySQL Database, ASPEED Server, and BreeZ Sensor
#   - Note: Ensure use of MySQL Database Server     |       NOTE: More generic than ORACLE MYSQL Database
#   - Note: Ensure use of ASPEED Server
#   - Note: Ensure use of BreeZ Sensor
def generate_smart_home_aadl_model_three_path_scenario_breez_mysql_aspeed_model(aadlFilename, packageName):
    print("[*] Generating the Three Path Smart Home model")
    ### Setting the variables to be used in the generation of the Smart Home AADL model
    ## Setting the Basic Model information 
    bus_array = ['ethernet', 'wireless', 'bluetooth', 'zigbee', 'nfc', 'usb', 'hardware_pins', 'breez']      # Replace 'zigbee' or just add 'breez'
    data_array = ['http', 'ssh', 'rdp', 'smb', 'ldap', 'sql', 'no_sql', 'uart', 'jtag']
    ## Setting the Device Model information
    # Setting the GUI device specifics
    graphical_user_interface_element = 'graphical_user_interface'
    graphical_user_interface_io_list = ['http', 'smb']
    graphical_user_interface_bus_list = ['ethernet']
    # Setting the Application device specifics
    application_element = 'application'
    application_io_list = ['http', 'ssh', 'smb']
    application_bus_list = ['ethernet']
    # Setting the Server device specifics
    server_element = 'aspeed_server'
    server_io_list = ['http', 'ssh', 'smb', 'sql']
    server_bus_list = ['ethernet', 'breez', 'uart']
    # Setting the Database device specifics
    database_element = 'mysql_database'
    database_io_list = ['smb', 'sql']
    database_bus_list = ['ethernet']
    # Setting the Sensor device specifics
    sensor_element = 'breez_sensor'
    sensor_io_list = ['ssh', 'http', 'ldap']
    sensor_bus_list = ['breez']
    # Setting the default implementation name for each device model implementation
    implementation_name = 'simple'
    ## Setting the System Model information
    system_bus_array = ['ethernet', 'breez']            # NOTE: While different arrays, this should match the 'server_bus_list' for the Smart Home AADL model
    system_io_list = ['http', 'smb']
    # Variables that are used in producing all the variations within the Smart Home model
    #   - TODO: Further variablize each device's io_list and other contents to provide a more modular and easily changable model
    device_io_map = {
            server_element : {
                'io_list' : server_io_list,
                'bus_connections' : server_bus_list                # Note: Have to set the protocol type here as well
                },
            database_element : {
                'io_list' : database_io_list,
                'bus_connections' : database_bus_list
                },
            application_element : {
                'io_list' : application_io_list,
                'bus_connections' : application_bus_list
                },
            graphical_user_interface_element : {
                'io_list' : graphical_user_interface_io_list,
                'bus_connections' : graphical_user_interface_bus_list 
                },
            sensor_element : {
                'io_list' : sensor_io_list,
                'bus_connections' : sensor_bus_list                 # Note: Have to set the protocol type here as well
                }
            }
    system_io_map = {
            'smart_home_network' : {
                'io_list' : system_io_list
                }
            }
    # TODO: Need to figure out the best way to populate this map to help automate connection of components
    system_implementation_map = {
            'smart_home_network' : {
                'ethernet_only' : {
                    'subcomponents' : {
                        'gui_element' : graphical_user_interface_element,
                        'application_element' : application_element,
                        'server_element' : server_element,
                        'database_element' : database_element,
                        'sensor_element' : sensor_element
                    },
                    'connections' : {
                        'bus_array' : system_bus_array,                     ## Internal system implementation buses
                        'external_ports': system_io_list                    ## system_external_ports_array       ## Same as the system_io_list???
                        }
                    }
                }
            }
    ## Function Call for Creating the Smart Home Model AADL file
    generate_smart_home_aadl_model_three_path_scenario_model(aadlFilename, packageName, bus_array, data_array, device_io_map, system_io_map, system_implementation_map)

# Function for generating the SMART HOME AADL Model
def generate_smart_home_aadl_models():
    print("[*] GAM is generating the Smart Home AADL model")
    # Arrays that contains variation variable arrays for the Smart Home model generation
    #aadlFilename = "/tmp/test_model.aadl"
    aadlFilename = "smart_home.aadl"
    default_package_name = "test_package"
    packageName = default_package_name
    if debugBit != 0:
        print("[+] Set the default package name for the generated AADL model")
    #model_filename = "{0}_firewall.aadl".format(databaseType)
    #model_filename = "{0}_{1}.aadl".format(databaseType, firewallType)
    model_filename = "smart_home_model.aadl"
    model_filename_placeholder = 'smart_home_model_scenario_{0}.aadl'
    model_filename_array = []
    max_model_scenario = 6 + 1 + 1
    for num in range(1, max_model_scenario + 1):
        model_filename_array.append(model_filename_placeholder.format(num))
    print("[?] Model name aarray:\n\tModel Names:\t{0}".format(model_filename_array))
    if debugBit != 0:
        print("[+] Output of model to the {0} filename".format(model_filename))
    # Function Call for generating the Three Path Smart Home model  (most basic form) - Scenario #7 (???) Lack of Hardware Vulnerabe elements
    modelFilename = model_filename_array[0]
    print("\tProcessing Scenario #01 - Generic AADL Model\n\t\tFile:\t{0}".format(modelFilename))
    aadlFilename = modelFilename
    generate_smart_home_aadl_model_three_path(aadlFilename, packageName)
    print("[+] GAM has finished generated the Smart Home AADL model")
    # Function Call for generating the Three Path Smart Home model - Scenario #1
    #   - Scenario #1:  Has BreeZ protocol using Sensor Wireless I/O modules
    modelFilename = model_filename_array[1]
    print("\tProcessing Scenario #02 - BreeZ Sensor\n\t\tFile:\t{0}".format(modelFilename))
    aadlFilename = modelFilename
    generate_smart_home_aadl_model_three_path_scenario_breez_sensor(aadlFilename, packageName)
    # Function Call for generating the Three Path Smart Home model - Scenario #2
    #   - Scenario #2:  Has Database implementing Oracle MySQL Server
    modelFilename = model_filename_array[2]
    print("\tProcessing Scenario #03 - Oracle MySQL Server\n\t\tFile:\t{0}".format(modelFilename))
    aadlFilename = modelFilename
    generate_smart_home_aadl_model_three_path_scenario_oracle_mysql_server(aadlFilename, packageName)
    # Function Call for generating the Three Path Smart Home model - Scenario #3
    #   - Scenario #3:  Has Server implmenting hardware that uses an Intel Xeon processor
    modelFilename = model_filename_array[3]
    print("\tProcessing Scenario #04 - Intel Xeon Processor\n\t\tFile:\t{0}".format(modelFilename))
    aadlFilename = modelFilename
    generate_smart_home_aadl_model_three_path_scenario_intel_xeon_processor_server(aadlFilename, packageName)
    # Function Call for generating the Three Path Smart Home model - Scenario #4
    #   - Scenario #4:  Has Server implementing hardware that uses an ASPEED ast2400 OR ast2500 server solution
    modelFilename = model_filename_array[4]
    print("\tProcessing Scenario #05 - ASPEED Server\n\t\tFile:\t{0}".format(modelFilename))
    aadlFilename = modelFilename
    generate_smart_home_aadl_model_three_path_scenario_aspeed_ast_server(aadlFilename, packageName)
    # Function Call for generating the Three Path Smart Home model - Scenario #5
    #   - Scenario #5:  Has the implementations of Scenarios I + II + III
    modelFilename = model_filename_array[5]
    print("\tProcessing Scenario #06 - BreeZ, Oracle, Intel\n\t\tFile:\t{0}".format(modelFilename))
    aadlFilename = modelFilename
    generate_smart_home_aadl_model_three_path_scenario_breez_oracle_mysql_intel_xeon_model(aadlFilename, packageName)
    # Function Call for generating the Three Path Smart Home model - Scenario #6
    #   - Scenario #6:  Has the implementation of Scenarions I + II + IV
    modelFilename = model_filename_array[6]
    print("\tProcessing Scenario #07 - BreeZ, Oracle, ASPEED\n\t\tFile:\t{0}".format(modelFilename))
    aadlFilename = modelFilename
    generate_smart_home_aadl_model_three_path_scenario_breez_oracle_mysql_aspeed_model(aadlFilename, packageName)
    # Function Call for generating the Three Path Smart Home model - Scenario #7
    #   - Scenario #6:  Has the implementation of Scenarions I + IV + MySQL Database
    modelFilename = model_filename_array[7]
    print("\tProcessing Scenario #08 - BreeZ, MySQL, ASPEED\n\t\tFile:\t{0}".format(modelFilename))
    aadlFilename = modelFilename
    generate_smart_home_aadl_model_three_path_scenario_breez_mysql_aspeed_model(aadlFilename, packageName)

### Intelligent Generation of AADL Models Code

## Function for Generating any [ DEVICE ] element
def generate_aadl_custom_device(aadlFilename, device_name, io_list, bus_connections):
    if debugBit != 0:
        print("[*] Generating the custom device [ {0} ]".format(device_name))
    # Variables used for ensuring proper output
    #io_list = ['http', 'ssh', 'smb', 'sql']
    #bus_connections = ['ethernet', 'zigbee']
    io_direction = "in out"         # Defaulting this for now, but can be used to providing directions for conncetions / graph
    event = "event"             #   \
    data = "data"               #   |--  All these variables relate to the definition for ports (if it is an event port, if it is a data port, if it is a port feature)
    port = "port"               #   /
    requires = "requires bus access"
    aadlFile = open(aadlFilename, "a")
    aadlFile.write('\tdevice {0}\n'.format(device_name))
    aadlFile.write('\t\t-- Definition of {0}\n'.format(device_name.capitalize()))
    aadlFile.write('\t\tfeatures\n')
    aadlFile.write('\t\t\t-- Data Ports\n')
    # For loop for adding in all the device Data Port features
    for io_port in io_list:
        if debugBit != 0:
            print('\tAdding I/O port [ {0} ]'.format(io_port))
        aadlFile.write('\t\t\t{0}_io\t\t\t:\t\t\t{1} {2} {3} {4} {0};\n'.format(io_port, io_direction, event, data, port))
    # For loop for adding in all the device Bus Connection features
    aadlFile.write('\t\t\t-- Bus Connections\n')
    for bus_connection in bus_connections:
        if debugBit != 0:
            print('\tAdding Bus Connection [ {0} ]'.format(bus_connection))
        # NOTE: Assuming a default of ALWAYS having a "require bus access" definition
        aadlFile.write('\t\t\t{0}_bus\t\t:\t\t\t{1} {0};\n'.format(bus_connection, requires))
    aadlFile.write('\tend {0};\n'.format(device_name))
    aadlFile.close()

## Function for Generating any [ DEVICE IMPLEMENTATION ] description
def generate_aadl_custom_device_custom_implementation(aadlFilename, device_name, implementation_name):
    if debugBit != 0:
        print("[*] Generating the custom [ {0} ] device [ {1} ] implementation".format(device_name, implementation_name))
    aadlFile = open(aadlFilename, "a")
    aadlFile.write('\tdevice implementation {0}.{1}\n'.format(device_name, implementation_name))
    aadlFile.write('\tend {0}.{1};\n'.format(device_name, implementation_name))
    aadlFile.close()

## Function for Generating any [ SYSTEM ] element
#   - TODO: Have this function take in the input of the system_IO_map
#   - NOTE: There is the expectation that the System will need Input/Outputs (e.g. internet based I/O, sensors based I/O, and API based I/O)
#       -> This is passed as an "external_ports" array of information.... somehow
def generate_aadl_networked_system(aadlFilename, system_model_name, system_io_map):
    print("[*] Generating the {0} networked system".format(system_model_name))        ## Bad assumption?
    #system_name = 'smart_home_network'      # Old place holder; replaced below with 'system_model' (which comes from the system_io_map)
    #system_name = system_io_map[0]
    system_name = system_model_name
    direction = 'in out'
    event = 'event'
    data = 'data'
    port = 'port'
    # Example of the system_io_map that should be passed into this function
    '''
    system_io_map = {
            'smart_home_network' : {
                'io_list' : ['http', 'smb']
                }
            }
    How can we leveage the above information with the rest of what is needed to modularize the building of a system description?
        - Note: The 'system_io_map' contains a list of the Inputs and Outputs that the system model should have
        - One can have a series of IF statements to check if certain I/O points should be included in the Smart Home Model
            - Ex:   HTTP for (1) Internet and (2) Sensor information, SMB for (1) API communication
    '''
    aadlFile = open(aadlFilename, "a")
    # Logic for going through the system_io_map to add the description for each system_model
    #   - NOTE: Later nested in this loop is the decision logic for adding the appropriate I/O features
    for system_model in system_io_map:
        print("\tDescribing the [ {0} ] system model".format(system_model))
        aadlFile.write('\tsystem {0}\n'.format(system_model))
        aadlFile.write('\t\t-- Definition of {0}\n'.format(" ".join(w.capitalize() for w in system_model.split('_'))))           # Note: Expects '_' to be the separator in the system_name variable (now the system_model variables)
        # Add in the features to the system definition
        #   - NOTE: This represents the set of Entry/Exit points that exist within the larger system model
        aadlFile.write('\t\tfeatures\n')
        # Logic for determining which I/O features need to be added into the generated AADL model file
        #   - IF Statement nested in a for loop that generates the IO for the model based on the provided io_list
        for io_type in system_io_map[system_model]['io_list']:
            if debugBit != 0:
                print("\tChecking for addition of the I/O type [ {0} ]".format(io_type))
            '''
            # Check if there should be HTTP I/O in the system model
            if io_type == 'http': 
                print("\tAdding I/O port [ {0} ]".format(io_type))
                aadlFile.write('\t\t\tinternet_{0}_io\t\t\t:\t\t\t{1} {2} {3} {4} {0};\n'.format(io_type, direction, event, data, port))        # Addition of Internet HTTP I/O
                aadlFile.write('\t\t\tsensor_{0}_io\t\t\t:\t\t\t{1} {2} {3} {4} {0};\n'.format(io_type, direction, event, data, port))          # Addition of Sensor HTTP I/O
            # Check if there should be SMB I/O in the system model
            elif io_type == 'smb':
                print("\tAdding I/O port [ {0} ]".format(io_type))
                aadlFile.write('\t\t\tapi_{0}_io\t\t\t:\t\t\t{1} {2} {3} {4} {0};\n'.format(io_type, direction, event, data, port))               # Addition of API SMB I/O
            else:
                print("[!] ERROR: I/O Type passed for System Model is UNKNOWN\t\t[ {0} ]".format(io_type))
            '''
            ## Just for a system outward facing I/O for each io_type in the system model's io_list?
            aadlFile.write('\t\t\texternal_{0}_io\t\t\t:\t\t\t{1} {2} {3} {4} {0};\n'.format(io_type, direction, event, data, port))
            # NOTE: Do I need the three separate exits?
        aadlFile.write('\tend {0};\n'.format(system_model))
    ## TODO: Fix the above logic to generate the system model description based on user provided information
    # Extra line space to add at the end of the system model description?
    aadlFile.close()

## Function for Generating any [ SYSTEM IMPLEMENTATION ] description
#   - Note: sensor_element variable allows passing of custom elements to the implementation
#   - NOTE: This function takes in the 'device_io_map' so that it can align the system_io_list and device_io_list(s) when generating connections
def generate_aadl_networked_system_implementations(aadlFilename, system_model_name, system_model_implementation_name, system_implementation_map, device_io_map, system_connections_list, system_edge_devices_array):    #, sensor_element='generic_sensor', server_element='server', database_element='database', graphical_user_interface_element='graphical_user_interface', application_element='application', bus_array=['ethernet', 'zigbee']):     # , scenario=0):
    print("[*] Generating the [ {0} ] networked system implementaiton".format(system_model_name))
    # Defaults to use for the system model implementaiton initial description
    #system_name = 'smart_home_network'
    system_name = system_model_name
    #implementation = 'ethernet_only'
    implementation = system_model_implementation_name
    #subcomponent_array = ['graphical_user_interface', 'application', 'server', 'database', sensor_element]
    # TODO: Prepare the following array by doing some initial analysis of the 'subcomponent' information to
    #       (1)     Create the 'subcomponent_array' that is used later on for 'subcomponent' description
    #       (2)     Determine SPECIFIC 'subcomponent' items for later SPECIFIC description of Bus and Data Connections
    #subcomponent_array = ['graphical_user_interface', 'application', server_element, database_element, sensor_element]
    # TODO: Prepare the necessary data structures to
    #       (3)     Create an array of 'bus' elements that is used later on for 'subcomponent' description
    #       (4)     Determine SPECIFIC 'subcomponent' items for later SPECIFIC description of Bus and Data Connection
    #bus_array = ['ethernet', 'zigbee']
    # Defaults used for the generation of the system implementation internals
    device = 'device'
    bus = 'bus'
    subcomponent_implementation = 'simple'
    bus_access = 'bus access'
    port = 'port'
    connection_direction = '<->'
    internal_system = 'internal'
    ## NEW AADL System Implementation Generation logic for creating an adaptive AADL Model
    # For loop through the system_model items in the system_implementation_map
    for system_model in system_implementation_map:
        if debugBit != 0:
            print("\tDescribing the [ {0} ] system_model".format(system_model))
        # For loop through the system_model_implementation items under the current system_model item
        for system_model_implementation in system_implementation_map[system_model]:
            if debugBit != 0:
                print("\tDescribing the [ {0} ] implementation for system model [ {1} ]".format(system_model_implementation, system_model))
            # Clear / Reset the subcomponent_array variable to be empty for each system implementation
            subcomponent_array = []
            # Clear / Reset the sensor_medium variable to be empty for each system implmentation    |   Used to ensure that a sensor_medium is detected by the system implmentation generation logic
            sensor_medium = ''
            aadlFile = open(aadlFilename, "a")
            aadlFile.write('\tsystem implementation {0}.{1}\n'.format(system_model, system_model_implementation))
            aadlFile.write('\t\t-- Implementation Definition of {0} - {1}\n'.format(" ".join(w.capitalize() for w in system_model.split('_')), " ".join(w.capitalize() for w in system_model_implementation.split('_'))))
            ## Generation of the:
            #       (1)         subcomponent_array      -       Used to generate the subcomponents of the system model implementation
            #               - NOTE: In the new version it should not matter what the device_class is called (e.g. subcompoent element)
            #                   - Should just produce the intended result
            #       (2)         individual elements     -       Set specific variables for each of the individual system implementaiton models
            #       (3)         bus_array               -       Used to generate the subcomponent buses of the system model implementation
            for subcomponent_item in system_implementation_map[system_model][system_model_implementation]['subcomponents']:
                if debugBit != 0:
                    print("\tSubcomponent Item:\t{0}\n\t\tConents:\t{1}".format(subcomponent_item, system_implementation_map[system_model][system_model_implementation]['subcomponents'][subcomponent_item]))
                # Add the devices to the subcomponent_array; ONLY if NOT the 'bus_array' element                                        (1)
                subcomponent_array.append(system_implementation_map[system_model][system_model_implementation]['subcomponents'][subcomponent_item]) 
                '''
                # IF statements for setting the individual elements
                if subcomponent_item == 'gui_element':                                  # Add the graphical_user_interface_element      (2)
                    graphical_user_interface_element = system_implementation_map[system_model][system_model_implementation]['subcomponents'][subcomponent_item]
                elif subcomponent_item == 'application_element':                        # Add the application_element                   (2)
                    application_element = system_implementation_map[system_model][system_model_implementation]['subcomponents'][subcomponent_item]
                elif subcomponent_item == 'server_element':                             # Add the server_element                        (2)
                    server_element = system_implementation_map[system_model][system_model_implementation]['subcomponents'][subcomponent_item]
                elif subcomponent_item == 'database_element':                           # Add the database_element                      (2)
                    database_element = system_implementation_map[system_model][system_model_implementation]['subcomponents'][subcomponent_item]
                elif subcomponent_item == 'sensor_element':                             # Add the sensor_element                        (2)
                    sensor_element = system_implementation_map[system_model][system_model_implementation]['subcomponents'][subcomponent_item]
                else:
                    print("[!] ERROR: UNKNOWN subcomponent_item [ {0} ]".format(subcomponent_item))
                '''
                ## TODO: Replace the above set of if statements
                #   -> NOTE: The only purpose of the above if statement is to act as a series of assignements.... should be able to replace this
            ## TODO: Dissection and Generation of the AADL model's Connections information for generation of the:
            #       (4)         Bus Connections         -       Used to set the bus connections between buses and the model elements
            #       (5)         Data Connections        -       Used to set the data connections between model element protocol ports
            #       (6)         Entry/Exit Connections  -       Used to set the data connections between the Entry/Exit points and the model element protocol ports
            for connection_item in system_implementation_map[system_model][system_model_implementation]['connections']:
                if debugBit != 0:
                    print("\tConnections Item:\t{0}\n\t\tContents:\t{1}".format(connection_item, system_implementation_map[system_model][system_model_implementation]['connections'][connection_item]))
                # IF statement for setting the connection elements
                if connection_item == 'bus_array':
                    bus_array = system_implementation_map[system_model][system_model_implementation]['connections'][connection_item]
            ## Writing in the 'subcomponents' information of the AADL model
            # Add in the subcomponent information to the system implementation definition
            aadlFile.write('\t\tsubcomponents\n')
            for subcomponent in subcomponent_array:
                # Ensure that the leading name to the subcomponents reflects the system model name
                aadlFile.write('\t\t\t{3}_{0}\t\t\t:\t\t\t{1} {0}.{2};\n'.format(subcomponent, device, subcomponent_implementation, system_model))
            # Use SAME IF statement check done for the system_model description function
            # Add in the bus elements that are part of the three_path model
            #   - TODO: Add a case/switch to check which / if any bus elements should be added into the model
            #   - NOTE: The 'sensor_medium' variable is set under each bus_type check done below
            for bus_type in bus_array:      # TODO: Change this to use a NEW bus_array that contains the necessary Bus I/O subcomponents
                if debugBit != 0:
                    print("\tChecking for addition of the I/O type [ {0} ]".format(bus_type))
                '''
                # Check if there should be HTTP I/O in the system model
                if bus_type == 'ethernet': 
                    print("\tAdding Bus I/O subcomponent [ {0} ]".format(bus_type))
                    sensor_medium = bus_type
                    aadlFile.write('\t\t\tinternal_{0}\t\t\t:\t\t\tbus {0};\n'.format(bus_type))                                      # Addition of Internal Ethernet Bus     (internal bus)
                    aadlFile.write('\t\t\tinternet_connection\t\t\t:\t\t\tbus {0};\n'.format(bus_type))                               # Addition of Internet Ethernet Bus     (external bus)

                # Check if there should be SMB I/O in the system model
                elif bus_type == 'zigbee':
                    print("\tAdding Bus I/O subcomponent [ {0} ]".format(bus_type))
                    sensor_medium = bus_type
                    # NOTE: Having an issue where the use of 'bus_type' below causes subcomponent to be named 'bus_type'_to_<server> INSTEAD of sensor_to_<server>
                    #aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\tbus {2};\n'.format(bus_type, server_element, sensor_medium))          # Addition of Internal Zigbee Bus   (server_element to sensor_element)
                    #aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\tbus {2};\n'.format('sensors', server_element, sensor_medium))          # Addition of Internal Zigbee Bus   (server_element to sensor_element)
                    aadlFile.write('\t\t\t{0}_{1}\t\t\t:\t\t\tbus {1};\n'.format('internal', sensor_medium))          # Addition of Internal Zigbee Bus   (server_element to sensor_element)
                elif bus_type == 'breez':
                    print("\tAdding Bus I/O subcomponent [ {0} ]".format(bus_type))
                    sensor_medium = bus_type        # Should be good? But MAY NEED to change this to specific hardcoded values
                    #aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\tbus {2};\n'.format(bus_type, server_element, sensor_medium))          # Addition of Internal BreeZ Bus    (server_element to sensor_element)
                    #aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\tbus {2};\n'.format('sensors', server_element, sensor_medium))          # Addition of Internal BreeZ Bus    (server_element to sensor_element)
                    aadlFile.write('\t\t\t{0}_{1}\t\t\t:\t\t\tbus {1};\n'.format('internal', sensor_medium))          # Addition of Internal BreeZ Bus    (server_element to sensor_element)
                else:
                    print("[!] ERROR: Bus I/O subcomponent passed for System Model [ {1} ] implementation [ {2} ] is UNKNOWN\t\t[ {0} ]".format(bus_type, system_model, system_model_implementation))
                '''
                aadlFile.write('\t\t\t{0}_{1}\t\t\t:\t\t\tbus {1};\n'.format(internal_system, bus_type))
            ## TODO: Fix the above logic to create ANY bus elements desired
            ## Writing in the 'connections' information of the AADL model
            aadlFile.write('\t\tconnections\n')
            # Add in the bus connections
            aadlFile.write('\t\t\t-- Bus Connections\n')
            # Connections of elements to the internal ethernet bus
            '''
            # Have an IF statement to confirm that the necessary information is present so that the AADL model CAN be generated correctly
            if 'ethernet' in bus_array:
                print("\tAdding ETHERNET Bus Connections to the AADL model")
                ## TODO: Rewrite the above as logic....
                #   Steps:
                #   1)      Check to see which devices have an 'ethernet_bus' bus mediums associated to them
                #   2)      Connect each (in turn) to the internal ethernet bus (system implementation subcomponent)
                for device_element in subcomponent_array:
                    print("\t\tChecking element [ {0} ] for an ethernet bus".format(device_element))
                    print("\t\tValue Check:\n\t\t\tI/O List:\t{0}\n\t\t\tBus List:\t{1}".format(device_io_map[device_element]['io_list'], device_io_map[device_element]['bus_connections']))
                    if 'ethernet' in device_io_map[device_element]['bus_connections']:
                        print("\t\tDevice [ {0} ] has an ethernet bus in its bus_connections < {1} >".format(device_element, device_io_map[device_element]['bus_connections']))
                        aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\t{2} smart_home_{0}.{1}_bus {3} internal_{1};\n'.format(device_element, 'ethernet', bus_access, connection_direction))
            else:
                print("[!] ERROR: Missing internal ETHERNET Bus.... UNEXPECTED; Unable to generate accurate adaptive AADL model")
            # Connectiosn of elements to the internal sensor bus
            # Have an IF statement to confirm that the necessary SENSOR BUS is present so that the AADL model CAN be generated correctly
            if not sensor_medium:           # sensor_medium variable is empty (i.e. has not been set by earlier code logic)
                print("[!] ERROR: Missing internal SENSOR Bus [ {0} ].... UNEXPECTED; Unable to generate accurate adaptive AADL model".format(sensor_medium))
            else:
                print("\tAdding SENSOR Bus Connections to the AADL model\t\t-\t\tUsing sensor_medium [ {0} ]".format(sensor_medium))
                ## TODO: Rewrite the above as logic...
                #   Steps:
                #   1)      Check to see which devices have a matching sensor_medium bus medium (e.g. Zigbee, BreeZ)
                #   2)      Connect each (in turn) to the internal bus_medium bus (system implementation subcomponent)
                for device_element in subcomponent_array:
                    print("\t\tChecking element [ {0} ] for an ethernet bus".format(device_element))
                    print("\t\tValue Check:\n\t\t\tI/O List:\t{0}\n\t\t\tBus List:\t{1}".format(device_io_map[device_element]['io_list'], device_io_map[device_element]['bus_connections']))
                    if sensor_medium in device_io_map[device_element]['bus_connections']:
                        print("\t\tDevice [ {0} ] has an ethernet bus in its bus_connections < {1} >".format(device_element, device_io_map[device_element]['bus_connections']))
                        aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\t{2} smart_home_{0}.{1}_bus {3} internal_{1};\n'.format(device_element, sensor_medium, bus_access, connection_direction, device_element))
            '''
            ## Loop through the devices in the subcomponent_array to:
            for device_element in subcomponent_array:
                for bus_type in device_io_map[device_element]['bus_connections']:
                    aadlFile.write('\t\t\t{0}_to_{1}\t\t\t:\t\t\t{2} {4}_{0}.{1}_bus {3} {5}_{1};\n'.format(device_element, bus_type, bus_access, connection_direction, system_model, internal_system))
            ## TODO: Re-write the above code to include ALL the bus connections.... currently only doing the ethernet ones 
            ## Add in the data connections
            aadlFile.write('\t\t\t-- Data Connections\n')
            ## TODO: Have a way to encode data connections AND their respective protocols between model elements
            #   - Can have each of the below connections aspects be a separate function that can generate connections between elements
            #   - NOTE: This information should be dissected from the system_implementation_map's 'connections' element
            #   - NOTE: Code should be able to determine the correct values from I/O and Bus lists attached to each device AND how they connect to system I/O and bus lists
            #   Steps:
            #   1)      Determine which devices are neightbors to each other (e.g. use the connection map? need a way to represent this)                                            <---- Can come for the system_implementation_map    | ASSUME KNOWN
            #   2)      Determine which devices have the same port types (e.g. SMB, SQL, HTTP)
            #   3)      Connect each of the ports using in-out (non-directed) 
            if debugBit != 0:   # ~!~
                print("[?] VARIABLE CHECK:\n\tSubcomponent Array:\t{0}\n\tSystem Connections List:\t{1}".format(subcomponent_array, system_connections_list))
            '''
            # Server to Database data connections
            matching_io_ports = return_matching_elements_between_lists(device_io_map[server_element]['io_list'], device_io_map[database_element]['io_list'])
            #print("\t[!?!?!?!] Set of matching I/O between [ {0} ] and [ {1} ] elements:\t\t< {2} >".format(server_element, database_element, matching_io_ports))
            for io_port in matching_io_ports:
                aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{0}.{2}_io {4} smart_home_{1}.{2}_io;\n'.format(server_element, database_element, io_port, port, connection_direction))
            # Server to Sensor data connections
            matching_io_ports = return_matching_elements_between_lists(device_io_map[server_element]['io_list'], device_io_map[sensor_element]['io_list'])
            for io_port in matching_io_ports:
                aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{0}.{2}_io {4} smart_home_{1}.{2}_io;\n'.format(server_element, sensor_element, io_port, port, connection_direction))
            # Server to Application data connections
            matching_io_ports = return_matching_elements_between_lists(device_io_map[server_element]['io_list'], device_io_map[application_element]['io_list'])
            for io_port in matching_io_ports:
                aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{0}.{2}_io {4} smart_home_{1}.{2}_io;\n'.format(server_element, application_element, io_port, port, connection_direction))
            # Applicaiton to GUI data connections
            matching_io_ports = return_matching_elements_between_lists(device_io_map[graphical_user_interface_element]['io_list'], device_io_map[application_element]['io_list'])
            for io_port in matching_io_ports:
                aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{0}.{2}_io {4} smart_home_{1}.{2}_io;\n'.format(graphical_user_interface_element, application_element, io_port, port, connection_direction))
            '''
            ## TODO: Replace the above set of loops with a single loop that:
            #   [x] Loops through all the devices in the subcomponent_array
            #       [x] Generates the io_port connections for the AADL model between connected elements (NOTE: Will need to pass forward the 'system_connections_list' from earlier in the GAM frontend code)
            for connection_set in system_connections_list:
                # Now go through the respecitve 'io_lists' for the two devices and write the AADL model connections between them
                device_pattern_1 = connection_set[0]
                device_pattern_2 = connection_set[1]
                device_1_match = [device_element for device_element in subcomponent_array if re.search(device_pattern_1, device_element, re.IGNORECASE)]
                device_2_match = [device_element for device_element in subcomponent_array if re.search(device_pattern_2, device_element, re.IGNORECASE)]
                # Now have to .pop() the match, otherwise dealing with nested lists
                device_1_name = device_1_match.pop()
                device_2_name = device_2_match.pop()
                if debugBit != 0:   # ~!~
                    print("\tDevice 1:\t{1}\n\tDevice 2:\t{2}\n\tDevice IO Map:\t{0}".format(device_io_map, device_1_name, device_2_name))
                    print("\tVariable Check:\n\t\tDevice 1 Match IO Map:\t{0}\n\t\tDevice 2 Match IO Map:\t{1}".format(device_io_map[device_1_name]['io_list'], device_io_map[device_2_name]['io_list']))
                # Find the matching io_ports between the two elements
                matching_io_ports = return_matching_elements_between_lists(device_io_map[device_1_name]['io_list'], device_io_map[device_2_name]['io_list'])
                # Now write the AADL file decriptions for the connections
                for io_port in matching_io_ports:
                    aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} {5}_{0}.{2}_io {4} {5}_{1}.{2}_io;\n'.format(device_1_name, device_2_name, io_port, port, connection_direction, system_model))
            ## External to Internal connections (i.e. Entry/Exit points)
            #system_edge_devices_array = ["graphical_user_interface", "sensor", "application"]
            for edge_device in system_edge_devices_array:
                # Now find the respective device that matches this device class
                device_match = [device_element for device_element in subcomponent_array if re.search(edge_device, device_element, re.IGNORECASE)]
                device_name = device_match.pop()        # Pull out the name of the device from the returned match list
                # Find the matching ports
                matching_io_ports = return_matching_elements_between_lists(device_io_map[device_name]['io_list'], system_implementation_map[system_model][system_model_implementation]['connections']['external_ports'])
                if debugBit != 0:   # ~!~
                    print("\tVar Check - Matching Ports:\t{0}\n\tEdge Device:\t{1}".format(matching_io_ports, edge_device))
                # Write the connections between the edges devices and the external ports
                for io_port in matching_io_ports:
                    aadlFile.write('\t\t\texternal_to_{0}_{1}\t\t\t:\t\t\t{2} external_{1}_io {3} {4}_{0}.{1}_io;\n'.format(device_name, io_port, port, connection_direction, system_model))
                    ## NOTE: For some reason the above code is NOT creating BOTH the smb and http connection, even thorugh the # of entries is correct....
            '''
            ## OLD WRITING
            aadlFile.write('\t\t\tinternet_to_{0}_{1}\t\t\t:\t\t\t{2} internet_{1}_io {3} smart_home_{0}.{1}_io;\n'.format('graphical_user_interface', 'http', port, connection_direction))
            #aadlFile.write('\t\t\tinternet_to_{0}_{1}\t\t\t:\t\t\t{2} {0}_{1}_io {3} smart_home_{0}.{1}_io;\n'.format('generic_sensor', 'http', port, connection_direction))
            aadlFile.write('\t\t\tinternet_to_{0}_{1}\t\t\t:\t\t\t{2} sensor_{1}_io {3} smart_home_{0}.{1}_io;\n'.format(sensor_element, 'http', port, connection_direction))
            aadlFile.write('\t\t\tinternet_to_{0}_{1}\t\t\t:\t\t\t{2} api_{1}_io {3} smart_home_{0}.{1}_io;\n'.format('application', 'smb', port, connection_direction))
            ## TODO: Rewrite the above as logic...
            #   Steps:
            #   1)      Determine which devices are neighbors to the external connections of the system definition (e.g. use an entry / exit map? need a way to represent this)     <----- Can come from the system_implementation_map  | ASSUME KNOWN
            #   2)      Determine which devices have the same port types as the external system ports (e.g. HTTP, SMB)
            #   3)      Connect each of the necessary ports for devices to external facing ports (e.g. system definition ports)
            #       -> NOTE: This will require determining where the ``software'' Entry / Exit points are within the model
            #   - NOTE: This part is far tricker due to needing to know any restrictions of the system description outputs
            #   -> It does seems that TAMSAT can handle all this with minimal problems
            #       - TODO: Need to find a way to map the system description to the system implementation map
            ## TODO: Fix the below to make use of the [ SYSTEM_CONNECTION_LIST ] to generate these final connections in the [ SYSTEM IMPLEMENTATION DESCRIPTION ]
            # Graphical User Interface to the Outside
            matching_io_ports = return_matching_elements_between_lists(device_io_map[graphical_user_interface_element]['io_list'], system_implementation_map[system_model][system_model_implementation]['connections']['external_ports'])
            for io_port in matching_io_ports:
                #aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{0}.{2}_io {4} smart_home_{1}.{2}_io;\n'.format(graphical_user_interface_element, application_element, io_port, port, connection_direction))
                aadlFile.write('\t\t\tinternet_to_{0}_{1}\t\t\t:\t\t\t{2} internet_{1}_io {3} smart_home_{0}.{1}_io;\n'.format(graphical_user_interface_element, io_port, port, connection_direction))

            # Sensors to the Outside
            matching_io_ports = return_matching_elements_between_lists(device_io_map[sensor_element]['io_list'], system_implementation_map[system_model][system_model_implementation]['connections']['external_ports'])
            for io_port in matching_io_ports:
                #aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{0}.{2}_io {4} smart_home_{1}.{2}_io;\n'.format(graphical_user_interface_element, application_element, io_port, port, connection_direction))
                aadlFile.write('\t\t\tinternet_to_{0}_{1}\t\t\t:\t\t\t{2} sensor_{1}_io {3} smart_home_{0}.{1}_io;\n'.format(sensor_element, io_port, port, connection_direction))

            # Applicaiton to the Outside
            matching_io_ports = return_matching_elements_between_lists(device_io_map[application_element]['io_list'], system_implementation_map[system_model][system_model_implementation]['connections']['external_ports'])
            for io_port in matching_io_ports:
                #aadlFile.write('\t\t\t{0}_{1}_{2}\t\t\t:\t\t\t{3} smart_home_{0}.{2}_io {4} smart_home_{1}.{2}_io;\n'.format(graphical_user_interface_element, application_element, io_port, port, connection_direction))
                aadlFile.write('\t\t\tinternet_to_{0}_{1}\t\t\t:\t\t\t{2} api_{1}_io {3} smart_home_{0}.{1}_io;\n'.format(application_element, io_port, port, connection_direction))
            ## TODO: Rewrite ALL of the above code to:
            #   [ ] Create the connections from the 'external_ports' to devices within the AADL model
            #       -> NOTE: Will need to know which elements are edge devices
            #       - BUT then we can just go through each edge device and the 'external_ports' and connect them all
            '''
            aadlFile.write('\tend {0}.{1};\n'.format(system_model, system_model_implementation))

## Function for [ ENCODIING THE ASSET OF IMPORTANCE ] into the AADL model file
def generate_aadl_encoded_asset_of_importance(system_asset_of_importance, aadlFilename):
    print("[*] Encoding the Asset of Importance Device Class [ {0} ] into the AADL model file".format(system_asset_of_importance))
    encodingHeader = "ASSET_OF_IMPORTANCE"
    encodedContent = encodingHeader + ' ' + system_asset_of_importance
    generate_aadl_comment(aadlFilename, encodedContent, indentLevel=0)
    print("[+] Completed the encoding")

## Function for [ WRITING THE AADL MODEL ] file
#   - Note: Ensure use of MySQL Database Server     |       NOTE: More generic than ORACLE MYSQL Database
#   - Note: Ensure use of ASPEED Server
#   - Note: Ensure use of BreeZ Sensor
def generate_aadl_model__adaptive_model(aadlFilename, packageName, bus_array, data_array, device_io_map, system_model_name, system_io_map, system_implementation_map, system_connections_list, system_edge_devices_array, system_asset_of_importance):
    print("[*] Generating an AADL model using Adaptive Logic")
    ### SETUP USER-BASED VARIABLES; FROM USER INPUT
    ## Variable Setup that User would need to Provide
    # Setting the default implementation name for each device model implementation
    implementation_name = 'simple'
    system_model_implementation_name = 'simple'       # TODO: This value SHOULD eventually come from the sysytem_implementation_map
    ### BEGIN WRITING THE AADL MODEL FILE CONTENTS
    ## Function Calls for Creating the [ PACKAGE HEADER ] for the AADL file
    # Start of the AADL model file
    genOpenHeader(packageName, aadlFilename)
    # Other inner parts of the AADL model file
    addEmptyLine(aadlFilename)
    ## Function Calls for Creating the [ BUS AND DATA DEFINITIONS ] for the AADL file
    # Bus and Data Definitions
    commentContent = 'Bus and Data Definitions'
    generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
    addEmptyLine(aadlFilename)
    generate_aadl_comment(aadlFilename, 'Bus Types', indentLevel=1)
    addEmptyLine(aadlFilename)
    ## Function Call for Creating the "Bus and Data Definitions" of the AADL file
    # Adding Bus Definitions
    for bus_type in bus_array:
        commentContent = '{0} Medium'.format(bus_type)
        generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
        generate_bus_medium_basic(aadlFilename, bus_type)
    addEmptyLine(aadlFilename)
    generate_aadl_comment(aadlFilename, 'Data Types', indentLevel=1)
    addEmptyLine(aadlFilename)
    # Adding Data Definitions
    for data_type in data_array:
        commentContent = '{0} Data Type'.format(data_type)
        generate_aadl_comment(aadlFilename, commentContent, indentLevel=1)
        generate_data_basic(aadlFilename, data_type)
    addEmptyLine(aadlFilename)
    ## Function Calls for Creating the [ DEVICE DEFINITIONS ] of the AADL file
    # Function Call for Creating the "Device Definitions" of the AADL file
    generate_aadl_comment(aadlFilename, 'Definition of Devices', indentLevel=1)
    addEmptyLine(aadlFilename)
    # Use the [ device_io_map ] for iteration
    for device_element in device_io_map:
        generate_aadl_custom_device(aadlFilename, device_element, device_io_map[device_element]['io_list'], device_io_map[device_element]['bus_connections'])
        addEmptyLine(aadlFilename)
        generate_aadl_custom_device_custom_implementation(aadlFilename, device_element, implementation_name)
        addEmptyLine(aadlFilename)
    ## Function Calls for Creating the [ SYSTEM DEFINITIONS ] of the AADL file
    # Function Call for Creating the "System Definitions" of the AADL file
    generate_aadl_comment(aadlFilename, 'Definition of Systems', indentLevel=1)
    addEmptyLine(aadlFilename)
    #system_array = ['smart_home_network']
    generate_aadl_networked_system(aadlFilename, system_model_name, system_io_map)     # TODO: Add the passing of the system model name
    addEmptyLine(aadlFilename)
    # Function Call for Creating the "System Implementation Definitions" of the AADL file
    #generate_aadl_networked_system_implementations(aadlFilename, system_implementation_map, device_io_map)          # Call to new design-agnositc system implementation generation
    generate_aadl_networked_system_implementations(aadlFilename, system_model_name, system_model_implementation_name, system_implementation_map, device_io_map, system_connections_list, system_edge_devices_array)
    addEmptyLine(aadlFilename)
    # Closing of the AADL mode file
    genEndHeader(packageName, aadlFilename)
    # Write in the final system Asset of Importance as an encoded comment for TAMSAT to read
    generate_aadl_encoded_asset_of_importance(system_asset_of_importance, aadlFilename)

## Function for [ COMPLETE AADL MODEL ] Generation
#   Inputs:
#       - User system architecture
#       - Devices to use in the model
#   NOTE: This function ONLY produces a SINGLE model.... This will need to be called multiple times to do multiple models
def generate_complete_aadl_model(aadlFilename, packageName, bus_array, data_array, device_io_map, system_model_name, system_io_map, system_implementation_map, system_connections_list, system_edge_devices_array, system_asset_of_importance):
    print("[*] GAM is generating the adaptive AADL model")
    if debugBit != 0:
        print("[+] Set the default package name for the generated AADL model")
    model_filename = aadlFilename       ## NOTE: Maybe expand this later
    print("\tProcessig Provided AADL Model Scenario...")
    aadlFilename = model_filename       ## NOTE: Repetative thing here.... Can remove later
    # Function Call to Now Generate the New AADL File
    generate_aadl_model__adaptive_model(aadlFilename, packageName, bus_array, data_array, device_io_map, system_model_name, system_io_map, system_implementation_map, system_connections_list, system_edge_devices_array, system_asset_of_importance)

## Function for Preparing Variable Structures for Complete AADL Model Generation
#   - Note: This function is used to generating the old test Smart Home model (for development of adaptive code)
#   -> No longer really used
def setting_up_aadl_model_variables(aadlFilename, packageName):
    ### Setting the variables to be used in the generation of the AADL model
    # Setting the default implementation name for each device model implementation
    implementation_name = 'simple'
    ## Setting the Basic Model information 
    bus_array = ['ethernet', 'wireless', 'bluetooth', 'zigbee', 'nfc', 'usb', 'hardware_pins', 'breez']      # Replace 'zigbee' or just add 'breez'
    data_array = ['http', 'ssh', 'rdp', 'smb', 'ldap', 'sql', 'no_sql', 'uart', 'jtag']     # Basically comes from the io_list
    ## Setting the Device Model information
    #device_io_map = create_and_return__device_io_map()                  # TODO: Add passing in the device list to thie funcionA
    # NOTE: Could have the above look for the devices in the GAM database, and then build the information from
    #       it?  
    #       -> Then later once the device and system maps are made then generate the BUS and DATA arrays
    #   -> NOTE: This wont work since the DEVICE and SYSTEM maps require knowledge of ALL the devices being used
    #       - Assume that the devices that appear in the device list WILL ALL be subcomponent devices within the
    #           system / implementation descriptions
    ## Setting the System Model information
    system_bus_array = ['ethernet', 'breez']            # NOTE: While different arrays, this should match the 'server_bus_list' for the AADL model
    system_io_list = ['http', 'smb']
    system_model_name = 'some_crazy_thing'
    ## Setting the variables for the model
    # Setting the GUI device specifics
    graphical_user_interface_element = 'graphical_user_interface'
    graphical_user_interface_io_list = ['http', 'smb']
    graphical_user_interface_bus_list = ['ethernet']
    # Setting the Application device specifics
    application_element = 'application'
    application_io_list = ['http', 'ssh', 'smb']
    application_bus_list = ['ethernet']
    # Setting the Server device specifics
    server_element = 'aspeed_server'
    server_io_list = ['http', 'ssh', 'smb', 'sql']
    server_bus_list = ['ethernet', 'breez', 'uart']
    # Setting the Database device specifics
    database_element = 'mysql_database'
    database_io_list = ['smb', 'sql']
    database_bus_list = ['ethernet']
    # Setting the Sensor device specifics
    sensor_element = 'breez_sensor'
    sensor_io_list = ['ssh', 'http', 'ldap']
    sensor_bus_list = ['breez']
    ## Creating the device_io_map
    # Variables that are used in producing all the variations within the adaptive AADL model
    #   - TODO: Further variablize each device's io_list and other contents to provide a more modular and easily changable model
    device_io_map = {
            server_element : {
                'io_list' : server_io_list,
                'bus_connections' : server_bus_list                # Note: Have to set the protocol type here as well
                },
            database_element : {
                'io_list' : database_io_list,
                'bus_connections' : database_bus_list
                },
            application_element : {
                'io_list' : application_io_list,
                'bus_connections' : application_bus_list
                },
            graphical_user_interface_element : {
                'io_list' : graphical_user_interface_io_list,
                'bus_connections' : graphical_user_interface_bus_list 
                },
            sensor_element : {
                'io_list' : sensor_io_list,
                'bus_connections' : sensor_bus_list                 # Note: Have to set the protocol type here as well
                }
            }
    if debugBit != 0:
        print("[+] Created and Returning the [ DEVICE_IO_MAP ]")
    # Creating the system io and implementation maps
    system_io_map = {
            system_model_name : {
                'io_list' : system_io_list
                }
            }
    # TODO: Need to figure out the best way to populate this map to help automate connection of components
    system_implementation_map = {
            system_model_name : {
                'ethernet_only' : {
                    'subcomponents' : {
                        'gui_element' : graphical_user_interface_element,
                        'application_element' : application_element,
                        'server_element' : server_element,
                        'database_element' : database_element,
                        'sensor_element' : sensor_element
                    },
                    'connections' : {
                        'bus_array' : system_bus_array,                     ## Internal system implementation buses
                        'external_ports': system_io_list                    ## system_external_ports_array       ## Same as the system_io_list???
                        }
                    }
                }
            }
    ## TODO: Replace ALL the above information with functions that "produce" the necessary structures
    # Call the complete generation and pass these variables
    #generate_complete_aadl_model(aadlFilename, packageName, bus_array, data_array, device_io_map, system_model_name, system_io_map, system_implementation_map)     # TODO: Add all the variables generated above (AFTER SPLITTING INTO FUNCTIONS)
    # TODO: FIX the above function to create the system_implementation_map properly based on passed information

## Function for reading and extracting device information from the GAM database
def read_and_return__gam_device_database(device_database_filename):
    print("[*] Reading and Returning the GAM Device Database")
    if debugBit != 0:   # ~!~
        print("\tChecking the current working directory\n\tcwd\t\t-\t{0}\n\tDirname\t\t-\t{1}\n\tBasename\t-\t{2}".format(os.getcwd(), os.path.dirname(os.getcwd()), os.path.basename(os.getcwd())))
    # Check to see if this code is being run via the framework or by itself
    #   - NOTE: Suuuuuuper hacky fix....    TODO: Make this better / cleaner
    if os.path.basename(os.getcwd()) == 'workDir':
        # Then we are being run as part of the GTS Framework.... Need to re-adjust the path to the GAM database
        device_database_filename = os.getcwd() + "/../GAM/ModelGen/" + device_database_filename
        if debugBit != 0:   # ~!~
            print("\tCheck the new path:\t{0}".format(device_database_filename))
    with open(device_database_filename, 'r') as device_database:
        device_database_json = json.loads(device_database.read())
    print("[+] Read and Returning the GAM Device Database")
    return device_database_json

## Function for checking the connections between devices and neighbors in the system architecture
def check_for_device_connection(system_connections_list, neighbor_element, device_element):
    if debugBit != 0:
        print("[*] Checking for existing connection in the system_connections_list between the device_element and neighbor_element")
    # Setup tracking variables for this function
    device_element_seen_flag = False
    neighbor_element_seen_flag = False
    # Begin by searching through the connections list and see if the device element exists in it
    for connection_tuple in system_connections_list:
        # Check for the device existing in ANY tuple
        if device_element in connection_tuple:
            # Set the device_element_seen_flag to True to show we have seen this
            device_element_seen_flag = True
            # Check for the neighbor exiting in the same tuple
            if neighbor_element in connection_tuple:
                # Combination already exists within the map; set the neighbor_element_seen_flag to True
                neighbor_element_seen_flag = True
            else:
                if debugBit != 0:
                    print("\tThe combination of device [ {0} ] and neighbor [ {1} ] has NOT been seen in the tuple [ {2} ]".format(device_element, neighbor_element, connection_tuple))
        else:
            if debugBit != 0:
                print("\tThe device [ {0} ] has NOT been seen in the tuple [ {1} ]".format(device_element, connection_tuple))
    ## Check the flag variables and based on their values, then either ADD the tuple or DO NOT
    # Neither the device or neighbor has been seen... Add the tuple
    if (device_element_seen_flag == False) and (neighbor_element_seen_flag == False):
        if debugBit != 0:
            print("\tAdding the tuple of device [ {0} ] and neighbor [ {1} ]".format(device_element, neighbor_element))
        system_connections_list.append((device_element, neighbor_element))
    # Device element is seen, but the neighbor has not been.... Then ADD the tuple
    elif (device_element_seen_flag == True) and (neighbor_element_seen_flag == False):
        if debugBit != 0:
            print("\tAdding the tuple of device [ {0} ] and neighbor [ {1} ]".format(device_element, neighbor_element))
        system_connections_list.append((device_element, neighbor_element))
    # Device element is not seen, but the neightbor has been.... Then ADD the tuple
    elif (device_element_seen_flag == False) and (neighbor_element_seen_flag == True):
        if debugBit != 0:
            print("\tAdding the tuple of device [ {0} ] and neighbor [ {1} ]".format(device_element, neighbor_element))
        system_connections_list.append((device_element, neighbor_element))
    # Device element has been seen and the neighbor has been seen.... Do nothing
    else:
        if debugBit != 0:
            print("\tNothing needs to be added to the system_connections_list")

## Function for reading through a system_architecture_map and producing the list of system connections
def read_and_return__system_connections_list(system_architecture_map):
    print("[*] Reading the System Architecture Map and Returning the System Connections List")
    ## Create variables for tracking information and returning the system connections list
    system_connections_list = []
    for device_element in system_architecture_map:
        for neighbor_element in system_architecture_map[device_element]:
            check_for_device_connection(system_connections_list, neighbor_element, device_element)
            # NOTE: The above function performs the check and adds to the system_connections_list
        # Done checking each neighbor element
    # Done checking the each device in the system_architecture_map
    print("[+] Completed read... Returning System Connections List")
    return system_connections_list

## Function for reading and returning the list of device_classes outlined in the system_architecture_map
def read_and_return__system_architecture_device_class_list(system_architecture_map):
    print("[*] Reading the System Architecture Map and Returning the System Architecture's Device Class List")
    ## Create variables for tracking information and returning the system architecture device class list
    system_architecture_device_class_list = []
    for device_element in system_architecture_map:
        system_architecture_device_class_list.append(device_element)
    print("[+] Completed read... Returning the System Architecture Device Class List")
    return system_architecture_device_class_list

## Function for reading and returning the list of edge devices outlined in the user supplied input
def read_and_return__system_edge_devices_list(user_input_json):
    print("[*] Reading the System Edge Devices List and Returning the information")
    return user_input_json["system_edge_devices_list"]

## Function for reading and returning the system_io_map outlined in the user input file
def read_and_return__system_io_map(user_input_system_io_map):
    # NOTE: One might NEED to change / further filter the system_io_map based on the provided information
    #   - Ex: If the user provided a system_io_map with a system_bus_list that contains 'breeZ', then the user does not care / want
    #       model designs that implement 'zigbee' protocol
    #   - THEREFORE need a method for determining:
    #       [ ] Does the system_bus_list match that of the valid_device_combination_sets (if user defined so)
    #       [ ] Did the user assigned 'generic' to the system_bus_list; in which case then ALL variations should be generated (e.g. both zigbee and breez)
    #   - Depending on the results of the above check then another round of filtering might need to occur
    #       -> THIS MEANS THEN that the system_io_map needs to be generated BEFORE the device_io_map
    #           - THEN AFTER this the GAM code can generate the system_implementation_map based on the other two + the system_connections_list
    print("[*] Reading the User System IO Map Input and Returning the User Input details")
    # Create variables for use in this function
    system_io_information = {}
    print("[+] Returning the generated system I/O information")
    return system_io_information

## Function for reading and returing the [ ASSET OF IMPORTANCE ] that is provided within the user input file
def read_and_return__system_asset_of_importance_device_class(user_input_json):
    print("[*] Reading the System Asset of Importance and Returning the User-Defined Device Class")
    return user_input_json["system_asset_of_importance"]

## Function for reading and returning a list of device classes intended to be used for generating an AADL model file
def create_and_return__device_class_list(user_json):
    print("[*] Creating and Returning the AADL Model's [ DEVICE CLASS LIST ]")
    # Create variables used for this function
    device_class_list = []
    # Loop through and add all of the 'devices' items to the device_class_list
    for device_class in user_json['devices']:
        if debugBit != 0:
            print("\tAdding device class [ {0} ] to the device_class_list".format(device_class))
        device_class_list.append(device_class)
    print("[+] Created and Returing the [ DEVICE CLASS LIST ]")
    return device_class_list

## Function for finding a device in the GAM database and returning its information
#   - NOTE: The purpose for this function is to returning information that is used to create devices
#       based on user input
def find_and_return__gam_device_information(device_class, brand_type, gam_device_database):
    if debugBit != 0:
        print("[*] Searching and returning for device with specific brand type in GAM database")
    # Note: This will search for an EXACT match     || Does not currently handle the bus variant
    pattern = '^' + brand_type + '_' + device_class + '$'
    gam_database_device_match = ''
    gam_database_device_entry = {}
    for device_entry in gam_device_database:
        if re.search(pattern, device_entry, re.IGNORECASE):
            if debugBit != 0:
                print("\tFound the exact match, device_entry:\t{0}".format(device_entry))
            gam_database_device_match = device_entry
    # Variable check for read from the database
    if debugBit != 0:   # ~!~
        print("\tGAM Return Check - GAM Db Match:\t{0}\n\tDatabase Check:\t{1}".format(gam_database_device_match, gam_device_database))
    # Check that something was found
    if not gam_database_device_match:
        print("[!] WARNING: Not exact match was found")
    # TODO: Add in a secondary search and return if not match is found? Have this check happen earlier?
    else:   
        # Pull out the GAM database device entry for the device match
        gam_database_device_entry[gam_database_device_match] = gam_device_database[gam_database_device_match]
    if debugBit != 0:
        print("[+] Returning the found device entry")
    return gam_database_device_entry

## Function for returning a user defined device class entry's brand_type, device_io_list, and device_bus_connections
def find_and_return__user_device_class_entry_information(user_json, device_class_entry):
    print("[*] Finding and returning information for the [ DEVICE_CLASS_ENTRY ] from the [ USER_INPUT_DEVICES ]")
    user_device_brand_type = user_json['devices'][device_class_entry]['brand_type']
    user_device_io_list = user_json['devices'][device_class_entry]['device_io_list']
    user_device_bus_list = user_json['devices'][device_class_entry]['device_bus_connections']
    print("[+] Returning the information for device class entry [ {0} ]".format(device_class_entry))
    return user_device_brand_type, user_device_io_list, user_device_bus_list

## Function for reading the user input, creating a user device database, and returning the new database
#   - Note: This function need to know where the GAM database is so it can generate the custom user defined devices
def create_and_return__user_input_device_database(user_json, gam_device_database):
    print("[*] Creating the [ USER_INPUT_DEVICE_DATABASE ] and returning it")
    ## Create variables used in the function
    user_input_device_database = {}
    ## Loop through and add all of the 'devices' items to the user_input_device_database
    #   - NOTE: This will require addition logic and work to generate each device's entries for the eventual device_io_map
    for device_class_entry in user_json['devices']:
        if debugBit != 0:
            print("\tExamining device_class_entry [ {0} ]".format(device_class_entry))
        user_device_brand_type, user_device_io_list, user_device_bus_list = find_and_return__user_device_class_entry_information(user_json, device_class_entry)
        # Logic for crafting the user-defined device_io_map entry (same as found in the GAM database)
        #   - Note: The return below may contain more than one event
        user_input_device_database_entry = find_and_return__custom_device_entry_using_gam_database(gam_device_database, device_class_entry, user_device_brand_type, user_device_io_list, user_device_bus_list)
        # Add the generated entry(ies) 
        #user_input_device_database.append(user_input_device_database_entry)
        for device_entry in user_input_device_database_entry:
            user_input_device_database[device_entry] = user_input_device_database_entry[device_entry]
        # TODO: Continue fixing this function
    print("[+] Created the [ USER_INPUT_DEVICE_DATABASE ]")
    if debugBit != 0:   # ~!~
        print("\tVariable Check - User Input Db:\t{0}".format(user_input_device_database))
    return user_input_device_database

## Function for returning an organized version of the pool_of_devices structure based on the system_architecture_device_class_list
#   - NOTE: This function will NOT RETURN (e.g. drop) any devices from the pool that do NOT MATCH the system architecture device classes provided
#   - NOTE: Also includes ALL DEVICES from the GAM DEVICE DATABASE
#   -> I think this should provide a completely sorted set based on ONLY the pool_of_devices given
#       - Additions from the GAM device database should be added beforehand?
# Assumption: The user_input_pool_of_devices contains devices that are UNIQUELY NAMED compared to the gam_device_database
#def organize_and_return__device_class_sorted_pool_of_devices(user_input_pool_of_devices, system_architecture_device_class_list, gam_device_database):
def organize_and_return__device_class_sorted_pool_of_devices(unorganized_pool_of_devices, system_architecture_device_class_list):
    print("[*] Preparing to organize the [ USER_INPUT_POOL_OF_DEVICES ] + [ GAM_DEVICE_DATABASE ] based on [ SYSTEM_ARHCITECTURE_DEVICE_CLASS_LIST ] provided")
    ## Create the variables used by this function
    device_class_sorted_pool_of_devices = {}        # NOTE: This is a JSON object that we will populate with the findings
    ## Loop through the pool_of_devices based on the provided system_architecture_device_class_list
    # Loop through the device classes to know what to look for
    for device_class in system_architecture_device_class_list:
        # Create variable that will track all found devices from pool that match the desired device_class
        matched_class_devices = []
        # Loop through the passed unorganized_pool_of_devices to populate the organized_pool_of_devices
        for potential_device in unorganized_pool_of_devices:
            if debugBit != 0:
                print("\tLooking for device class [ {0} ]... Comparing to potential device [ {1} ]".format(device_class, potential_device))
            # Check to see if the device class exists within the examined potential_device (simple text within larger text check)
            if device_class in potential_device:
                # Add the device into the matched_class_devices; NOTE: Do not care about duplicate because the unorganized_pool_of_devices should have ZERO duplicate entries
                #   -> Wrong, I do care!! Just in case
                if potential_device not in matched_class_devices:
                    matched_class_devices.append(potential_device)
                else:
                    if debugBit != 0:
                        print("\tPotential device [ {0} ] has already been matched for the desired class device [ {1} ]".format(potential_device, device_class))
            else:
                if debugBit != 0:
                    print("\tDid not match")
        # Quick check to see if NOTHING came back
        if len(matched_class_devices) == 0:
            print("[!] ERROR: No matching DEVICE found based on DEVICE_CLASS [ {0} ].... Panic time".format(device_class))
            exit()
        # Done going through the pool_of_devices and gam_device_database, so now add findings to device_class_sorted_pool_of_devices()
        device_class_sorted_pool_of_devices[device_class] = matched_class_devices
    print("[+] Completed organizing the [ USER_INPUT_POOL_OF_DEVICES ] + [ GAM_DEVICE_DATABASE ] and returning the [ DEVICE_CLASS_SORTED_POOL_OF_DEVICES ]")
    return device_class_sorted_pool_of_devices

## Function for creating all the variations of potential device combination sets given
#   - Assumption: The organized_device_pool has been organized BASED on the SYSTEM_ARCHITECTURE_DEVICE_CLASS_LIST
#       - This ensures that the resulting combination sets are true to the requirements provided by the user
#       - For example: If the user wants a server, a sensor, a database, and one more sensor this will be captured in the
#           production of the system_architecture_device_class_list (since it comes from the provided system architecture)
#           and THEREFORE will contain a list of all required devices for the AADL model
def create_and_return__device_combination_sets(organized_device_pool):
    print("[*] Creating and Returning sets of all potential device combinations based in inputs")
    if debugBit != 0:   # ~!~
        print("\tOrganized_device_pool:\t{0}".format(organized_device_pool))
    ## Create the variables to be used in this function
    #   - NOTE: The EXPECTATION is that the device_combination_sets is a LIST OF LISTS
    device_combination_sets = []
    # Create a list of all the sets to be used in the combination
    for device_class in organized_device_pool:
        # NOTE: The order does not matter here since 
        device_combination_sets.append(organized_device_pool[device_class])
    if debugBit != 0:   #  ~!~
        print("\tPrepared device_combination_sets:\t{0}".format(device_combination_sets))
        #print("\tTest itertool.product() return:\t{0}".format(list(itertools.product(*device_combination_sets))))
    # Without adding the list() not sure we would get back something that can be used later by GAM
    return list(itertools.product(*device_combination_sets))

## Function for returning device information for a specific implementation of a provided device class, brand, IO, and bus
#   - NOTE: There is no reason that this function can not return multiple versions / variants of the custom device instance
# Assumption: Other functions in the tool will make sense of the returned output; can assume that having multiple returns
#       just makes GAM explore a larger design space (so.... not a problem at all)
#   - NOTE: ENSURE that all names are UNIQUE
def find_and_return__custom_device_entry_using_gam_database(gam_device_database, device_class, brand_type, device_io_list, device_bus_list):
    print("[*] Reading, Creating, and Returning a custom device entry based on provided information and existing GAM database entries")
    ## Create variables to be used within this function
    device_instance_map = {}        # Structure to hold the device's instance mapping (i.e. device entry as seen in GAM database)
    potential_device_pool = []      # List that will be used for identifying potential device solutions; will be narrowed down based on user supplied information
    user_input_tag = 'user'
    default_io_list = ['http']
    default_bus_list = ['ethernet']
    default_name_tag = 'unknown'
    ## Loop through the GAM known device database and collcet all device instances that might match the desired device class
    for device_instance in gam_device_database:
        if debugBit != 0:
            print("\tComparing device instance [ {0} ] to the desired device class [ {1} ]".format(device_instance, device_class))
        # Check to see if this device instance is of the desired device class (NOTE: Because the device_class would be part of the device_instance name)
        if device_class in device_instance:
            if debugBit != 0:
                print("\tThe device instance [ {0} ] has been found to be of the device class [ {1} ]".format(device_instance, device_class))
            # Check first that we are not adding a duplicate entry
            if device_instance in potential_device_pool:
                print("[!] ERROR: GAM has found a duplicate entry trying to be added into the potential_device_pool... THIS SHOULD NEVER HAPPEN.... Panic")
            else:
                # Add the potential class to the potential device pool
                potential_device_pool.append(device_instance)
    ## TODO: Add the ability to recognize if EITHER no potential match is found or multiple potential matches are found
    #   - In the case of no matches, then create a new device_io_map based on user-provided data
    #   - In the case of multiple potential matches:
    #       i)  Find the one that best fits the model
    #       ii) Have a way to return MULTIPLE solutions
    #           - NOTE: In this case we can have the calling function check for the number of returned devices?
    #           - Then one can use all the returned device instances to create all the different models??
    # Variable check moving forward
    if debugBit != 0:   # ~!~
        print("\tVariable Check - Potential Device Pool:\t{0}".format(potential_device_pool))
    # Check to see if the potential device pool is empty
    if len(potential_device_pool) == 0:
        print("\tCreating a generic entry since NO MATCHES were found\n\tUsing default I/O and Bus lists\n\t\tI/O List:\t{0}\n\t\tBus List:\t{1}\n\t\tName Tag:\t{2}".format(default_io_list, default_bus_list, default_name_tag))
        device_instance_map[default_name_tag + '_' + user_input_tag + '_' + brand_type + '_' + device_class] = {
                "io_list" : default_io_list,
                "bus_connections" : default_bus_list
                }
        if debugBit != 0:
            print("\tExamining device_instance_map:\t{0}".format(device_instance_map))
    # Scenario where a NON-ZERO number of potential devices were found
    else:
        # Loop through the found potential devices and create a device_instance_map entry for each  # NOTE: This is where the re-creation of generic devices with specific attributes are generated
        for device_candidate in potential_device_pool:
            # NOW: Perform checks. First check the device_io_list and device_bus_list, then check if the brand_type is generic
            #   - Maybe just check brand first? Does it matter?
            # Are both the device IO and Bus lists set to generic?
            if (device_io_list == "generic") and (device_bus_list == "generic"):
                if brand_type == "generic":
                    if debugBit != 0:
                        print("\tAll GENERIC scenario given by user for device class [ {0} ]".format(device_class))
                    # TODO: Go to the GAM device database and pull out the generic device_class and copy the information
                    gam_search_return = find_and_return__gam_device_information(device_class, brand_type, gam_device_database)
                    # Since this is ALL generic then there is no further need to alter the returned information
                    for device_entry in gam_search_return:
                        device_instance_map[user_input_tag + '_' + device_entry] = gam_search_return[device_entry]
                else:
                    if debugBit != 0:
                        print("\tBrand Type [ {0} ] has been provided by user for device class [ {1} ]".format(brand_type, device_class))
                    # TODO: Check to see if this brand type of device_class exists in the GAM database and return the information
                    gam_search_return = find_and_return__gam_device_information(device_class, brand_type, gam_device_database)
                    # Should not need to change anything here since still in the scenario where everything is generic
                    for device_entry in gam_search_return:
                        device_instance_map[user_input_tag + '_' + device_entry] = gam_search_return[device_entry]
            elif (device_io_list == "generic") and (device_bus_list != "generic"):
                custom_device_bus_list = device_bus_list
                # TODO: Search for the rest of the information based on brand name
                gam_search_return = find_and_return__gam_device_information(device_class, brand_type, gam_device_database)
                # Add in the returned information BUT making sure to change the 'bus_list' to be the new custom set
                for device_entry in gam_search_return:
                    device_instance_map[user_input_tag + '_' + device_entry] = {
                            "io_list" : gam_search_return[device_entry]['io_list'],
                            "bus_connections" : custom_device_bus_list
                            }
            elif (device_io_list != "generic") and (device_bus_list == "generic"):
                custom_device_io_list = device_io_list
                # TODO: Search for the rest of the information based on brand name
                gam_search_return = find_and_return__gam_device_information(device_class, brand_type, gam_device_database)
                # Add in the returned information BUT making sure to change the 'io_list' to be the new custom set
                for device_entry in gam_search_return:
                    device_instance_map[user_input_tag + '_' + device_entry] = {
                            "io_list" : custom_device_io_list,
                            "bus_connections" : gam_search_return[device_entry]['bus_list']
                            }
            # Scenario where the io and bus lists are NOT generic
            else:
                custom_device_io_list = device_io_list
                custom_device_bus_list = device_bus_list
                # TODO: Search for the rest of the information based on brand name
                # Add the candidate device into the device_instance_map
                device_instance_map[user_input_tag + '_' + device_candidate] = {
                        "io_list" : custom_io_list,
                        "bus_connections" : custom_bus_list
                        }
            # TODO: Finish out the generation of the model AND accounting for the 'generic' key words
    if debugBit != 0:       # ~!~
        print("\t[?] Testing:\n\t\tPotential Device Pool:\t{0}\n\t\tDevice Instance Map:\t{1}".format(potential_device_pool, device_instance_map))
    print("[+] Returning the custom device entry generated")
    return device_instance_map

## Function for generating the device_io_map
#   Note: Issues due to missing information for the system_implementation_map making...
# Inputs:
#   - List of the devices to be used in producing a SINGLE device_io_map
#   - User Input JSON to be used in providing the brand, io, and bus lists for each device in the list?     <---- No? Remove this input?
#       -> Note: Maybe produce this before hand and just pass it to the function
#   - Database of the devices known to GAM
#   - Provide sets of:
#       -> Default generic_device_io_list
#       -> Default generic_bus_io_list
# Outputs:
#   - device_io_map that represents the inputs provided
def create_and_return__device_io_map(device_pool_list, user_input_database_device, gam_device_database):
    if debugBit != 0:
        print("[*] Creating and Returning the AADL Model's [ DEVICE_IO_MAP ]")
    '''
    ## NOTE: Using FAKE inputs that need to come from an existing JSON database
    generic_device_io_list = ['http', 'smb', 'sql']
    generic_device_bus_list = ['ethernet', 'zigbee']
    '''
    # Create device_io_map structure to hold in the informaiton we produce
    device_io_map = {}
    if debugBit != 0:   # ~!~
        print("\tDevice Pool List:\t{0}".format(device_pool_list))
    ## Loop through each device in the provided device_pool_list to construct the device_io_map
    for device_element_name in device_pool_list:
        if debugBit != 0:   # ~!~
            print("\tDevice Element's [ {0} ] device_io_map is being generated".format(device_element_name))
        # Determine if the device being examined is user-defined
        is_device_element_user_defined_flag = check_and_verify__is_device_user_defined(device_element_name)
        if debugBit != 0:   # ~!~
            print("\tIt is [ {0} ] that Device Element [ {1} ] is user-defined".format(is_device_element_user_defined_flag, device_element_name))
        # Fetch the existing device_io_map from either the user-defined database OR the GAM database
        #   - NOTE: If this device is part of the user-defined database, then MAKE SURE to remove the leading 'user_' tag before committing the device_element_io_map to the larger device_io_map
        #       -> The reason for this being that OTHERWISE TAMSAT would not know what the device_element is or have the information in TAMSAT's device database
        device_element_io_map = find_and_return__device_from_either_device_database(device_element_name, is_device_element_user_defined_flag, user_input_database_device, gam_device_database)
        if debugBit != 0:   # ~!~
            print("\tDevice I/O Map for Device Element [ {0} ]:\n\t\t{1}".format(device_element_name, device_element_io_map))
        ## Add the new devices to the larger device_io_map
        # Before adding, first check if a 'user_' tag needs to be removed from the front of the device_element_name
        if is_device_element_user_defined_flag:
            if debugBit != 0:
                print("\tNeed to remove the leading 'user_' tag from Device [ {0} ] I/O map before adding to the larger device_io_map".format(device_element_name))
            user_pattern = '^user_'
            # Create a sanitized device_element_name
            sanitized_device_element_name = re.sub(user_pattern, '', device_element_name)
            if debugBit != 0:
                print("\tSanitized Device Element Name:\t{0}".format(sanitized_device_element_name))
            device_io_map[sanitized_device_element_name] = device_element_io_map[device_element_name]
        # Scenario where no changes need to be made to the device_element_name
        else:
            if debugBit != 0:
                print("\tNo need to remove any leading 'user_' tag, simple add Device [ {0} ] I/O map to the larger device_io_map".format(device_element_name))
            device_io_map[device_element_name] = device_element_io_map[device_element_name]
    # Return the newly minted device_io_map
    if debugBit != 0:   # ~!~
        print("\tCompleted device_io_map:\n\t\t{0}".format(device_io_map))
        print("[+] Created and Returning the AADL Model's [ DEVICE_IO_MAP ]")
    return device_io_map

## Function for generating the system_io_map and system_bus_list
def create_and_return__system_information_map(user_input_json):
    print("[*] Creating and Returning the AADL Model's [ SYSTEM_IO_MAP ]")
    # Create system_io_map structure to hold in the information we produce
    system_io_map = {}
    # Pull the required information out of the system information provided by the user input
    system_model_name = user_input_json['system']['system_model_name']
    system_io_list = user_input_json['system']['system_io_list']
    system_bus_list = user_input_json['system']['system_bus_list']
    system_bus_exclusion_list = user_input_json['system']['system_bus_exclusion_list']
    # Generate the expected output from this function
    system_io_map = {
            system_model_name : {
                    "io_list" : system_io_list
                }
            }
    print("[+] Created and Returning the AADL Model's [ SYSTEM_IO_MAP ]")
    return system_io_map, system_bus_list, system_model_name, system_bus_exclusion_list

## Function for generating the system_implementation_map
def create_and_return__system_implementation_map():
    print("[*] Creating and Returning the AADL Model's [ SYSTEM_IMPLEMENTATION_MAP ]")
    # Create system_implementation_map structure to hold in the information we produce
    system_implementation_map = {}
    print("[+] Created and Returning the AADL Model's [ SYSTEM_IMPLEMENTATION_MAP ]")
    return system_implementation_map

## Function for reading the specific file provided by the user
def read_in_user_input(user_input_filename):
    print("[*] Reading in User Input File [ {0} ]".format(user_input_filename))
    with open(user_input_filename, 'r') as user_device_file:
        user_json_read = json.loads(user_device_file.read())
    if debugBit != 0:
        for item in user_json_read:
            print("Item:\t{0}".format(item))
    print("[+] Completed read of User Input File")
    return user_json_read

## Function for testing the uesr supplied system details are viable
def verify_system_details(user_json):
    if not user_json['system']["system_model_name"]:
            print("\tALERT!! NO SYSTEM MODEL NAME PROVIDED.... PANIC AND EXIT!!")
            return False
    system_element = user_json['system']['system_model_name']
    if user_json['system']["system_io_list"] == "generic":
            print("\tALERT! Using GENERIC for SYSTEM_IO_LIST for system [ {0} ]".format(system_element))
    if user_json['system']["system_bus_list"] == "generic":
            print("\tALERT! Using GENERIC for SYSTEM_BUS_LIST for system [ {0} ]".format(system_element))
    return True

## Function for returning the desired device_name entry from either the user-defined or GAM device databases based on a a flag indicating if the device is user-defined or not
def find_and_return__device_from_either_device_database(device_name, device_is_user_defined_flag, user_input_device_database, gam_device_database):
    if debugBit != 0:
        print("[*] Checking the User-Defined and GAM Databases for device [ {0} ] which has a user-defined flag of  [ {1} ]".format(device_name, device_is_user_defined_flag))
    searched_device_io_map = {}
    # If the device is user-defined, then grab the device entry information from the user_input_device_database
    if device_is_user_defined_flag:
        # Pull out the device definition within the user defined device database
        searched_device_io_map[device_name] = user_input_device_database[device_name]
    # If not, then grab the device entry information from the gam_device_database
    else:
        # Pull out the device definition within the GAM definied device database
        searched_device_io_map[device_name] = gam_device_database[device_name]
    # Return the found information
    return searched_device_io_map

## Function for identifying if a given device is a user-defined device or not
def check_and_verify__is_device_user_defined(device_element_name):
    if debugBit != 0:
        print("[*] Check if the device [ {0} ] is a user-defined device or not".format(device_element_name))
    # Create variables for use in this function
    user_pattern = '^user_'
    # Check if the device is user-defined and return the result
    is_device_user_defined_flag = bool(re.search(user_pattern, device_element_name, re.IGNORECASE))
    if debugBit != 0:
        print("[+] It is [ {0} ] that the provided device is user-defined".format(is_device_user_defined_flag))
    return is_device_user_defined_flag

## Function for retrieving the bus list information for a provided single valid device combination set
def find_and_return__complete_device_combination_bus_list(single_device_combination_set, user_input_device_database, gam_device_database, known_system_bus_list):
    if debugBit != 0:
        print("[*] Beginning search to return the associated bus list for the provided single device combination set")
    # Create variables to use for this function
    aggregated_device_combination_bus_list = []
    # Loop through the set combination of devices
    for device_element_name in single_device_combination_set:
        device_element_is_user_defined_flag = check_and_verify__is_device_user_defined(device_element_name)
        device_element_io_map = find_and_return__device_from_either_device_database(device_element_name, device_element_is_user_defined_flag, user_input_device_database, gam_device_database)
        # Aggregate bus types found
        for bus_type in device_element_io_map[device_element_name]['bus_connections']:
            aggregated_device_combination_bus_list.append(bus_type)
    # Now perform non-repeated list of bus types
    for bus_type in aggregated_device_combination_bus_list:
        if bus_type not in known_system_bus_list:
            known_system_bus_list.append(bus_type)
        else:
            if debugBit != 0:
                print("\tAlready seen bus type [ {0} ] in the known_system_bus_list")
    # Now return the updated known_system_bus_list
    return known_system_bus_list

## Function for identifying which database to look-up devices infomration from, return the respective Bus information, and ensure that the device combination provided will work with the user-defined system_bus_list
#   - Note: This function currently requires a 100% match between the device combination bus list and the user-defined system_bus_list
def compare_and_verify__device_combination_and_user_system_bus_list(single_device_combination_set, system_bus_list, user_input_device_database, gam_device_database):
    if debugBit != 0:
        print("[*] Beginning process to compare, validate, and verify that the device combination works with the uesr provided system bus list")
    # Create variables to use for this function
    is_device_combination_valid = True      # Same expectation that we begin with assuming it is true and work to provide it is false
    aggregated_device_combination_bus_list = []
    ## Create a HUGE LIST of ALL BUS INFORMATION, then perform a isdisjoin() between the larger bus_list and the user-defined system_bus_list
    for device_element_name in single_device_combination_set:
        device_element_is_user_defined_flag = check_and_verify__is_device_user_defined(device_element_name)
        device_element_io_map = find_and_return__device_from_either_device_database(device_element_name, device_element_is_user_defined_flag, user_input_device_database, gam_device_database)
        # NOTE: Need to make sure we are creating a single list and NOT a list of lists
        for bus_type in device_element_io_map[device_element_name]['bus_connections']:
            aggregated_device_combination_bus_list.append(bus_type)
    ## Now perform the Hardware validation check between the aggregation of the device hardware lists and the user-provided system_bus_list (i.e. hardware requirement of the 
    if debugBit != 0:   # ~!~
        print("\tAggregate List:\t{0}\n\tSystem Bus List:\t{1}".format(aggregated_device_combination_bus_list, system_bus_list))
    # NOTE: Not that simple.... Need to ensure that ALL user defined hardware bus types (in system_bus_list) are in the aggregate list
    #   - Otherwise: get erroneous information that allows for 'breez' in the system bus list AND 'zigbee' in the aggregate list
    #       -> This above scenario should FAIL
    for bus_type in system_bus_list:
        # Now check each bus type (one at a time) to ensure that the user-provided system bus list works with the expected device combinations
        #is_system_hardware_valid = not set(aggregated_device_combination_bus_list).isdisjoint(bus_type)
        # NOTE: For some reason the isdisjoint() does not seem to work between a set and a string?? So fuck it... going with a simpler check that will work
        is_system_hardware_valid = bus_type in set(aggregated_device_combination_bus_list)
        is_device_combination_valid = is_device_combination_valid & is_system_hardware_valid 
        if debugBit != 0:   # ~!~
            print("\t\tBus Type Examined [ {0} ]\n\t\tAggregate List:\t{1}\n\t\tSystem Hardware Valid?:\t{2}\n\t\tDevice Combo Valid?:\t{3}".format(bus_type, aggregated_device_combination_bus_list, is_system_hardware_valid, is_device_combination_valid))
    # NOTE: The reason we do the above loop multiple times over is that this allows us to determine the acceptability of the user-defined bus list to the provided device combination
    if debugBit != 0:   # ~!~
        print("\tVariable Check:\n\t\tAggregate Bus List:\t{0}\n\t\tSystem Bus List:\t{1}\n\t\tHardware Valid?:\t{2}".format(aggregated_device_combination_bus_list, system_bus_list, is_device_combination_valid))
    if debugBit != 0:
        print("[+] It was found [ {0} ] that the combination of devices and user-defined system bus list will work".format(is_device_combination_valid))
    return is_device_combination_valid

## Function for identifying which database to look-up devices information from, return the respective I/O and Bus information, and ensure the model combination makes sense
def compare_and_verify__device_combination_validation(single_device_combination_set, system_connections_list, user_input_device_database, gam_device_database):
    if debugBit != 0:   # ~!~
        print("[*] Beginning process to compare, validate, and verify that the device combination is functional or not")
        print("\tProvided Combination Set:\t{0}".format(single_device_combination_set))
    # Create variables to use for this function
    #is_device_combination_valid = False         # NOTE: Default value is false, since the assumption is that the combination need to be validated before moving forward
    is_device_combination_valid = True         # NOTE: Default value is True, so that if any aspect of the provided device combination set is not valid for the framework (GAM + TAMSAT + SMART) then this check will return False (indicating that this combination set is NOT valid)
    ## Begin the examination of the devices in the provided combination set
    #   -> Easiest way to get this working might be to create the device_io_map and then simply compare the bus/io aspects
    #   - Maybe do this by looking at each EXPECTED connection in the model and comparing that way
    # NOTE: Use the command 'not set(a).isdisjointb)' as the fastest way to know if there are no matches between the two sets
    for device_connection in system_connections_list:
        # Each device_connection should be a pair of two devices; e.g. ('database', 'server')
        #   - Expectation is that device_connections ONLY account for a connection between TWO devices
        #   - TODO: Will eventually need a method for comparing if there are two potential same device_class items in the system architecture
        #       -> Ex: What if there are TWO 'sensor' class devices in the presented system architecture
        ## Setup variables for the for loop
        device_pattern_1 = device_connection[0]     # NOTE: These are NOT the device name patterns yet... This is ONLY the DEVICE_CLASS
        device_pattern_2 = device_connection[1]     #   -> Still have to return the name of each device
        device_1_is_user_defined = False
        device_2_is_user_defined = False
        user_pattern = '^user_'       # Nota Bene: The need for implementing regex here and ENSURING that user pattern ONLY matches the START of the device name
        # Find the matching devices     || TODO: Check that these searches are checking the correct thing
        device_1_match = [device_candidate for device_candidate in single_device_combination_set if re.search(device_pattern_1, device_candidate, re.IGNORECASE)]
        device_2_match = [device_candidate for device_candidate in single_device_combination_set if re.search(device_pattern_2, device_candidate, re.IGNORECASE)]
        # Check that the matches came back with something
        if (len(device_1_match) < 1) or (len(device_2_match) < 1):
            print("[!] ERROR: GAM unable to find matching devices in provided combination set.... Panic!")
        # Now check and compare the device information to ensure at least one match in the bus and io device lists
        '''
        # First, figure out if either device is from the user-defined device database
        #   - TODO: Change the below calls to the any() function with a regex search... Require an EXACT match to the start of the string
        device_1_is_user_defined_flag = any(user_pattern in device_name for device_name in device_1_match)
        device_2_is_user_defined_flag = any(user_pattern in device_name for device_name in device_2_match)
        '''
        ## Prepare variables that will hold the returned device mapping for the TWO compared devices
        #   - NOTE: This should be a Go / No-Go point in the code; if we don't have two devices to compare, then DO NOT PROCEED...
        device_1_io_map = {}
        device_2_io_map = {}
        # Pop the device names out of the respective matches made earlier
        device_1_name = device_1_match.pop()        # Pull the item out of the list so that we can just match using the string key
        device_2_name = device_2_match.pop()        # Pull the item out of the list so that we can just match using the string key
        # Determine if either device is from the user-defined device database
        device_1_is_user_defined_flag = bool(re.search(user_pattern, device_1_name, re.IGNORECASE))
        device_2_is_user_defined_flag = bool(re.search(user_pattern, device_2_name, re.IGNORECASE))
        # Find and return the each device's IO map structure from the appropriate database
        device_1_io_map = find_and_return__device_from_either_device_database(device_1_name, device_1_is_user_defined_flag, user_input_device_database, gam_device_database)
        device_2_io_map = find_and_return__device_from_either_device_database(device_2_name, device_2_is_user_defined_flag, user_input_device_database, gam_device_database)
        ## Compare the two device_io_maps to ensure at least a single match in both the io_list and bus_list entries
        # Compare the Hardware bus_lists of the devices to ensure at least one match between them
        is_hardware_valid = not set(device_1_io_map[device_1_name]['bus_connections']).isdisjoint(device_2_io_map[device_2_name]['bus_connections'])
        # Compare the Software io_lists of the devices to ensure at least one match between them
        is_software_valid = not set(device_1_io_map[device_1_name]['io_list']).isdisjoint(device_2_io_map[device_2_name]['io_list'])
        # Final check for verification of the hardware, software, and previous assumption that the device combination set is valid
        #   - NOTE: If any of the validation checks fail (i.e. return false) then the entire is_device_combination_valid check MUST return false (i.e. failure)
        is_device_combination_valid = is_device_combination_valid & is_hardware_valid & is_software_valid
        # Note the use of the bitwise operator AND (&) since this should just be a simple AND operation; so long as all true, then answer is true
    '''
    # For-loop to look at each device in the combination set
    for device_candidate in 
    # Start by determining if it is a user-defined device or not
    '''
    if debugBit != 0:
        print("[+] Completed comparison and verificaiton process... Device Combination Set provided found to be [ {0} ]".format(is_device_combination_valid))
    return is_device_combination_valid

## Function for making complete call to new AADL model generation logic (adaptive)
#   - Note: Creates a SINGLE AADL model
def soup_2_nuts(user_input_filename):
    print("[*] Beginning process for creating an AADL model SOUP-2-NUTS")
    ## Setting up information from the input file
    #   - Ex: aadlFilename, packageName
    # Default location for the GAM database
    gam_device_database_filename = "../Database/deviceDb.json"
    #aadlFilename = "test_aadl_adaptive_model.aadl"
    #packageName = "adaptive_test"
    aadlFilename_base = "adaptive_generated_aadl_model_"
    packageName_base = "adapate_aadl_model_"
    ## Calling the function to build the model from soup-2-nuts (Old Smart Home development case)
    #setting_up_aadl_model_variables(aadlFilename, packageName)     # OLD FUNCTION CALL
    ## TODO: Incorporate the new model generation code into this
    explore_design_space_from_user_input_file(user_input_filename, gam_device_database_filename, aadlFilename_base, packageName_base)
    print("[+] Completed process for creating an AALD model SOUP-2-NUTS")

## Tetsing function to get the device_io_map generation working
def explore_design_space_from_user_input_file(user_input_filename, gam_device_database_filename, aadlFilename_base, packageName_base):
    # Set the file paths
    #gam_device_database_filename = "../Database/deviceDb.json"
    #user_input_filename = "../Database/test_user_device_list.txt"
    # Read in the files
    gam_device_database = read_and_return__gam_device_database(gam_device_database_filename)
    user_input_json = read_in_user_input(user_input_filename)
    # Test and verify the provided user_input_json
    system_detail_check = verify_system_details(user_input_json)
    if system_detail_check:
        print("\tUser input system details seem fine")
    else:
        print("\tUser input system details have an issue.... Panic?")
    # Create the list of needed connections for the system implementation
    system_connections_list = read_and_return__system_connections_list(user_input_json["system_architecture_map"])
    # Figure out the device classes present in the user file
    user_device_class_list = create_and_return__device_class_list(user_input_json)
    # Pull out the device classes needed for the system architecture model; how to determine the devices needed for each verison of a device_io_map, and used to make the system_implementation_map
    system_architecture_device_class_list = read_and_return__system_architecture_device_class_list(user_input_json["system_architecture_map"])
    # Pull out the list of system edge devices that is provided by the user
    system_edge_devices_array = read_and_return__system_edge_devices_list(user_input_json)
    # Extract the system's Asset of Importance's Device Class provided by the user
    system_asset_of_importance_device_class = read_and_return__system_asset_of_importance_device_class(user_input_json)
    ## Code for specifically creating the device_io_map, combination sets of devices
    ## A function for creating a user_input based device_io_maps for generating a user device database; purpose for easier building of device_io_map from easily looked-up information
    # Create the user-defined database of devices
    user_input_device_database = create_and_return__user_input_device_database(user_input_json, gam_device_database)        # NOTE: Here is where the call chain starts for producing custom devices using GAM and user-defined information
    if debugBit != 0:   # ~!~
        print("[?] Check on return of user_input_device_database:\t{0}".format(user_input_device_database))
    ## Create a merging of the user-defined and GAM device databases into a single 'pool_of_devices'
    # First copy the user_input_device_database into the new pool_of_devices
    pool_of_devices = user_input_device_database
    # Update the pool_of_devices to include the GAM device database
    pool_of_devices.update(gam_device_database)
    # Next, create the organized version of the pool_of_devices
    sorted_pool_of_devices = organize_and_return__device_class_sorted_pool_of_devices(pool_of_devices, system_architecture_device_class_list)
    if debugBit != 0:   # ~!~
        print("[?] Check on return of sorted_pool_of_devices:\t{0}".format(sorted_pool_of_devices))
    # Create an organized_user_device_pool?
    # NOTE: When removing the 'user_tag' from device names, make sure to use EXACT regex match of '^user_' so it
    #   ONLY removes the front pieces of the name
    # Create the combination sets of information
    potential_model_combination_sets = create_and_return__device_combination_sets(sorted_pool_of_devices)       # Note: This is producing mixes of 'bus_list', 'io_list' (6 times... expecting should be 5 for testing...?)
    # Next, need to filter the generated sets and make sure that
    #   i)      Hardware Bus elements match between connected elements (AT LEAST ONE)
    #   ii)     Software I/O elements match between connected elements (AT LEAST ONE)
    # Then attempt looping through all remaining device combination sets and make calls to the generate_complete_aadl_model
    #   -> NOTE: Going to need to prepare the AADL model structures and ensure all data is being passed properly
    if debugBit != 1:   # ~!~
        print("[?] Variable Check:\n\t\tPotential Model Combination Sets - Length:\t{0}\n\t\tPotential Model Combination Sets - Unique:\t{1}".format(len(potential_model_combination_sets), len(set(potential_model_combination_sets))))
    # For the purpose of working on the development, let us create a random sub-sample of the 384 combinations produced
    if developmentMode != 0:
        smaller_sample_of_combination_sets = random.sample(potential_model_combination_sets, 13)
        if debugBit != 0:   # ~!~
            print("\tSubset Check - Length:\t{0}\n\tSubset Check - Unique:\t{1}".format(len(smaller_sample_of_combination_sets), len(set(smaller_sample_of_combination_sets))))
            print("\tSubset Contents:\t{0}".format(smaller_sample_of_combination_sets))
        # NOTE: Doing an over-write here for development
        potential_model_combination_sets = smaller_sample_of_combination_sets
    ## Check through the generated potential model combination sets and begin filtering out 'non-sense' device combinations
    # Variables for tracking the device combination sets that work (are valid) and those that do not work (are invalid)
    valid_device_combination_sets = []
    invalid_device_combination_sets = []
    ## Validate and cull the combination sets down to a only those that will actually make a sensicle AADL model
    # Loop through the generated sets to search through each individually
    for single_device_combination_set in potential_model_combination_sets:
        # Call this function to check each individual combination set and verify its acceptability
        valid_combination = compare_and_verify__device_combination_validation(single_device_combination_set, system_connections_list, user_input_device_database, gam_device_database)
        if not valid_combination:
            # Add single_device_combination_set to the invalid_device_combination_set
            invalid_device_combination_sets.append(single_device_combination_set)
        else:
            # Add single_device_combination_set to the valid_device_combination_set
            valid_device_combination_sets.append(single_device_combination_set)
    # Review of the created valid and invalid device combination sets
    if debugBit != 1:   # ~!~
        print("[?] Device Combination Sets - Post Validation Process\n\tValid Device Combinations:\n\t\tValid Combinations - Length:\t{0}\n\t\tValid Combinations - Unique:\t{1}\n\tInvalid Device Combinations:\n\t\tInvalid Combinations - Length:\t{2}\n\t\tInvalid Combinations - Unique:\t{3}".format(len(valid_device_combination_sets), len(set(valid_device_combination_sets)), len(invalid_device_combination_sets), len(set(invalid_device_combination_sets))))       # Testing shows valid 96 and invalid 288
        print("\tContents of the valid/invalid sets\n\t\tValid Sets:\t{0}\n\t\tInvalid Sets:\t{1}".format(valid_device_combination_sets,invalid_device_combination_sets))
    # Now move towards creating the device_io_map, system_io_map, and system_implementation_map structures for generating AADL models
    system_io_map, system_bus_list, system_model_name, system_bus_exclusion_list = create_and_return__system_information_map(user_input_json)       # TODO: Add a system check that is the excluion list is "none" then return empty list ([])
    if debugBit != 1:   # ~!~
        print("\tSystem Information Return:\n\t\tSystem I/O Map:\t\t\t{0}\n\t\tSystem Bus List:\t\t{1}\n\t\tSystem Model Name:\t\t{2}\n\t\tSystem Bus Exclusion List:\t{3}".format(system_io_map, system_bus_list, system_model_name, system_bus_exclusion_list))
    # Check to correct the system_bus_exclusion_list
    if system_bus_exclusion_list == "none":
        system_bus_exclusion_list = []
    else:
        if debugBit != 1:   # ~!~
            print("\tDo not need to correct the system_bus_exclusion_list\t-\t{0}".format(system_bus_exclusion_list))
    # User has provided a 'generic' system_bus_list (NOTE: This is the more difficult scenario)
    if system_bus_list == "generic":        # TODO: Check that this spot gets hit correctly
        ### Scenario #1 where the user has provided a "generic" system_bus_list which means that GAM needs to produce a set of system_io_maps that will match each UNIQUE set of device combinations based on disjoint? Maybe ALREADY known bus types?
        #   => NOTA BENE: Because of the constant interations through different models, this has to be done with COPIES of the lists and NOT the original list...
        print("Ahhhhh shit.... User asked for the more complicated action.... *waves hands and escape*")
        ## Basic variables to use within Scenario #1
        #   - Note: Current assumption is that we will use ALL the bus types within a single generic bus list (and see what happens)
        generic_bus_list = ["ethernet"]
        technology_sets_not_allowed_in_the_same_design = [("zigbee", "breez")]
        aadl_model_number_counter = 0
        past_system_bus_lists = []
        ## Determine the list of all bus types that can exist under "general"
        #   -> Just create a list of all bus types within the existing set of valid_device_combination_sets
        for single_device_combination_set in valid_device_combination_sets:
            # Create variables used for tracking bus types
            additional_bus_types = []
            # Function call to extract the bus types from it
            generic_bus_list = find_and_return__complete_device_combination_bus_list(single_device_combination_set, user_input_device_database, gam_device_database, generic_bus_list)
            '''
            # Aggregate the bus types; checking that duplicates are not placed within the generic_bus_list
            for additional_bus in additional_bus_types:
                if additional_bus not in generic_bus_list:
                    generic_bus_list.append(additional_bus)
                else:
                    if debugBit != 0:
                        print("\tAlready have bus type [ {0} ] in the generic_bus_list".format(additional_bus)
            '''     # NOTE: Do not need the above block since it is already tackled by the find_and_return__complete_device_combination_bus_list function internally?
        ## Debug line
        if debugBit != 1:   # ~!~
            print("[?] System Bus List Check:\t{0}".format(generic_bus_list))
        ## Logic for cycling thorugh all potential system_bus_list combinations
        for technology_conflict_set in technology_sets_not_allowed_in_the_same_design:
            # Now examine each conflict set individually
            for technology in technology_conflict_set:
                # Next we need to create each specific system_bus_list and make a call to create_and_generate__aadl_model_generation_based_on_system_bus_list
                #   - Note: Make sure to track the aadl_model_number_counter
                if debugBit != 1:
                    print("\tCreating a system_bus_list around eleminating technology [ {0} ]".format(technology))
                # Create a copy of the original list and then remove the technology from the model (NOTE: This is because it is easier to just remove the technology)
                temp_system_bus_list = generic_bus_list.copy()
                temp_system_bus_list.remove(technology)
                # Set the temp_system_bus_list to be the same as system_bus_list cause I'm lazy for the funciton call
                system_bus_list = temp_system_bus_list
                if debugBit != 1:   # ~!~
                    print("\tSystem Bus List:\t{0}".format(system_bus_list))
                    print("\tVariable Check:\n\t\tSystem Bus List:\t{0}\n\t\tAADL Model Counter:\t{1}".format(system_bus_list, aadl_model_number_counter))
                    print("\t\tOriginal Bus List:\t{0}".format(generic_bus_list))
                ## Make call to the function that will further filter the potential device combination sets and then generate the rest of the variables
                aadl_model_number_counter = create_and_generate__aadl_model_generation_based_on_system_bus_list(aadlFilename_base, packageName_base, system_io_map, system_bus_list, system_model_name, valid_device_combination_sets, user_input_device_database, gam_device_database, system_architecture_device_class_list, system_connections_list, system_edge_devices_array, system_asset_of_importance_device_class, system_bus_exclusion_list, aadl_model_number_counter, counter_digit_padding=8)
                past_system_bus_lists.append(system_bus_list)
        ## Print Checks to make sure that this branch was taken
        print("\t[!] Completed the generic system_bus_list scenario")
        print("\t\tList of all seen system bus lists:\t{0}".format(past_system_bus_lists))      # NOTE: Issue of # of models may be coming from the fact that the 'aspeed_server' with same bus list as 'aspeed_breez_server'; check using grep
        # => Nope, the difference seems to come from the "generic_server" being translated into a "breez_server"; NOTE: Must be due to a conversion that is happening with the non-generic situation but NOT in the generic scenario???
        #   - Looks like ths is due to the fact that when asked to make a specific output, GAM generates more versions using a generic tmeplate.  Otherwise GAM simply provides the devices that are already defined within its database
        ## Lastly set the 'system_bus_list' variable to be the same as the 'generic_bus_list' so that the function call below goes forward without issue
        #system_bus_list = generic_bus_list
        # NOTE: The issue with this setup is that creating the generic bus list this way causes some scenarios that cause issues (e.g. having Zigbee and BreeZ buses within the SAME solution)
        #   - May require creation of multiple system_bus_lists and make a call for a set of variables for EACH bus list
        ## Make call to the function that will further filter the potential device combination sets and then generate the rest of the variables
        #create_and_generate__aadl_model_generation_based_on_system_bus_list(aadlFilename_base, packageName_base, system_io_map, system_bus_list, system_model_name, valid_device_combination_sets, user_input_device_database, gam_device_database, system_architecture_device_class_list, system_connections_list, system_edge_devices_array, system_asset_of_importance_device_class, system_bus_exclusion_list, aadl_model_number_counter=0, counter_digit_padding=8)
    # User has provided a specific set of system_bus_list elements
    else:
        ### Scenario #2 where the user has provided a system_bus_list that will specifically limit the models produced
        #   - Just need to pass the existing system_bus_list
        aadl_model_number_counter = 0
        if debugBit != 1:   # ~!~
            #print("\tSystem Bus List:\t{0}".format(system_bus_list))
            print("\tVariable Check:\n\t\tSystem Bus List:\t{0}\n\t\tAADL Model Counter:\t{1}".format(system_bus_list, aadl_model_number_counter))
            #print("\t\tOriginal Bus List:\t{0}".format(generic_bus_list))
        ## Variables to use in this scenario #2
        create_and_generate__aadl_model_generation_based_on_system_bus_list(aadlFilename_base, packageName_base, system_io_map, system_bus_list, system_model_name, valid_device_combination_sets, user_input_device_database, gam_device_database, system_architecture_device_class_list, system_connections_list, system_edge_devices_array, system_asset_of_importance_device_class, system_bus_exclusion_list, aadl_model_number_counter, counter_digit_padding=8)
        ## Print Checks to make sure that this branch was taken                                                                              
        print("\t[!] Completed the user-defined system_bus_list scenario")
        print("\t\tList of all seen system bus lists:\t{0}".format(system_bus_list))

## Function for performing final device combination set filtering based on a known system_bus_list (i.e. Hardware requirement)
def create_and_generate__aadl_model_generation_based_on_system_bus_list(aadlFilename_base, packageName_base, system_io_map, system_bus_list, system_model_name, valid_device_combination_sets, user_input_device_database, gam_device_database, system_architecture_device_class_list, system_connections_list, system_edge_devices_array, system_asset_of_importance_device_class, system_bus_exclusion_list, aadl_model_number_counter=0, counter_digit_padding=8):
    if debugBit != 0:
        print("[*]")
    ## Array that will carry the device combination sets that will need to be filtered out
    device_combinations_to_remove = []
    ## Debugging function input
    if debugBit != 0:   # ~!~
        print("[?] Variable Check:\n\tValid Combination Sets:\t{0}\n\tSystem Bus List:\t{1}".format(valid_device_combination_sets, system_bus_list))
    ## Second validation loop to ensure that the valid_device_combination_sets work with the user_provided system_bus_list
    for single_device_combination_set in valid_device_combination_sets:
        valid_system_hardware_combination = compare_and_verify__device_combination_and_user_system_bus_list(single_device_combination_set, system_bus_list, user_input_device_database, gam_device_database)
        if debugBit != 0:   # ~!~
            print("\tDoes Device Combination work with the System Hardware? [ {0} ]\n\t\tDevice Combo:\t{1}\n\t\tSystem Hardware:\t{2}".format(valid_system_hardware_combination, single_device_combination_set, system_bus_list))
        # Add the invalid combination to a list of device combinations to be removed
        if not valid_system_hardware_combination:
            device_combinations_to_remove.append(single_device_combination_set)
    ## Third validation loop to remove any system_bus_exclusion_list items
    #   - TODO: Add in the restriction code to the function
    for single_device_combination_set in valid_device_combination_sets:
        temp_device_combo_bus_list = []
        if debugBit != 0:
            print("\tChecks single device combination set [ {0} ] for excluded technology".format(single_device_combination_set))
        single_device_combination_bus_list = find_and_return__complete_device_combination_bus_list(single_device_combination_set, user_input_device_database, gam_device_database, temp_device_combo_bus_list)
        # Check if any elements from the system_bus_exclusion_list exist in the single_device_combination_bus_list, and it so, then remove it from the valid_device_combination_sets
        for excluded_technology in system_bus_exclusion_list:
            if excluded_technology in single_device_combination_bus_list:
                if single_device_combination_set not in device_combinations_to_remove:
                    if debugBit != 0:
                        print("\tRemoving combo [ {0} ] based on excluded technology [ {1} ]".format(single_device_combination_set, excluded_technology))
                    device_combinations_to_remove.append(single_device_combination_set)
    ## Clear out the bad combination sets from the valid_device_combination_sets
    for no_longer_valid_combination_set in device_combinations_to_remove:
        valid_device_combination_sets = [potential_combination_set for potential_combination_set in valid_device_combination_sets if potential_combination_set != no_longer_valid_combination_set]
    ## Test to check the remaining model variations
    if debugBit != 1:   # ~!~
        print("\tValid Device Combination Sets:\t{0}".format(valid_device_combination_sets))
        print("\tNumber of Valid Combinations:\t{0}".format(len(valid_device_combination_sets)))
    ## Now generate the necessary system_implementation_map (TODO)
    #   - Note: Will need to generate this separately based on EACH valid_combination
    system_implementation_name = "simple"
    ## Finally make the call to the generation of the rest of the AADL model fine information
    aadl_model_number_counter = create_and_generate__aadl_model_variables_and_files(aadlFilename_base, packageName_base, system_io_map, system_bus_list, system_model_name, system_implementation_name, valid_device_combination_sets, user_input_device_database, gam_device_database, system_architecture_device_class_list, system_connections_list, system_edge_devices_array, system_asset_of_importance_device_class, aadl_model_number_counter, counter_digit_padding)
    if debugBit != 0:
        print("[+]")
    return aadl_model_number_counter

## Function for generating each case of the AADL model requirements based on inputs
# Inputs:
#   aadlFilename_base - Base Naming Structure for the AADL Model Files
#   packageName_base - Base Naming Structure for the AADL Model packages
#   system_io_map - System I/O Map
#   system_bus_list - System Bus List
#   system_model_name - System Model Name
#   system_implementation_name - System Implementation Name (NOTE: Assumed 'simple' but can be something else)
#   valid_device_combination_sets - Sets of Valid Device Combinations that will work with the provided system_io_map
#   user_input_device_database - User input generated database of devices
#   gam_device_databaes - GAM database of devices
#   system_architecture_device_class_list - List of the Device Classes used as the System subcomponents
#   system_asset_of_importance_device_class - System Asset of Importance Device Class that will be evaluated as the root of the security risk
# Outputs:
#   Completed AADL model files
def create_and_generate__aadl_model_variables_and_files(aadlFilename_base, packageName_base, system_io_map, system_bus_list, system_model_name, system_implementation_name, valid_device_combination_sets, user_input_device_database, gam_device_database, system_architecture_device_class_list, system_connections_list, system_edge_devices_array, system_asset_of_importance_device_class, aadl_model_number_counter=0, counter_digit_padding=8):
    ## NOTE: This part should happen no matter what..... Turn this part into a function???
    if debugBit != 0:   # ~!~
        print("[*] Creating the AADL model variables and files")
        print("\tExpected Number of AADL models:\t\t{0}".format(len(valid_device_combination_sets)))
    ## Variables for tracking the AADL filename and packageName
    #aadl_model_number_counter = 0
    #counter_digit_padding = 8
    #aadlFilename_base = "adaptive_generated_aadl_model_"
    #packageName_base = "adapate_aadl_model_"
    ## For loop for going through each valid_combination in the valid_device_combination_sets
    for valid_combination in valid_device_combination_sets:
        if debugBit != 1:   # ~!~
            print("\tValid Combination being generated into an AADL model\t-\t{0}".format(valid_combination))
        ## Setup variables for generating the AADL model file; device_io_map, system_io_map, system_implementation_map
        # Create the device_io_map variable
        valid_combination_device_io_map = create_and_return__device_io_map(valid_combination, user_input_device_database, gam_device_database)
        # Checking correct return of the sanitized and valid combination device_io_map
        if debugBit != 0:   # ~!~
            print("\tValid Combination Returned device_io_map:\n\t\t{0}".format(valid_combination_device_io_map))
        # Create the system_io_map variable
        system_subcomponents_map = {}
        ## Loop through the system_architecture_device_class_list to create the subcomponents aspect of the system_implementation_map
        for system_subcomponent_device_class in system_architecture_device_class_list:
            # Now loop through the devices in the valid_combination_device_io_map; since need to take elements from the santizied names
            for valid_device_element in valid_combination_device_io_map:
                if system_subcomponent_device_class in valid_device_element:
                    # Add the matching device from the valid_combination set that is of the same device_class in the system_architecture_device_class_list
                    system_subcomponents_map[system_subcomponent_device_class] = valid_device_element
        # Now should have a complete subcomponents set
        if debugBit != 0:   # ~!~
            print("\tSubcomponent Map:\t{0}".format(system_subcomponents_map))
        ## Next step is to create the 'connections' aspects of the system_implementation_map
        system_connections_map = {
                'bus_array' : system_bus_list,
                'external_ports' : system_io_map[system_model_name]['io_list']
                }
        ## Now combine everything into a single system_implementaiton_map
        system_implementation_map = {
                system_model_name : {
                    system_implementation_name : {
                        'subcomponents' : system_subcomponents_map,
                        'connections' : system_connections_map
                    }
                }
            }
        # Check that the system_implementaiton_map was created as expected
        if debugBit != 0:   # ~!~
            print("\tSystem Implementaiton Map:\t{0}".format(system_implementation_map))
        ## CORRECT SYSTEM_IMPLEMENTATION_MAP CREATED.... Now to generate the AADL model files...
        ## Create the last misisng variables before making call to generate the complete AADL model
        # Create the aadlFilename
        aadlFilename = aadlFilename_base + str(aadl_model_number_counter).zfill(counter_digit_padding) + '.aadl'     # Pad out the number string
        # Create the packageName
        packageName = packageName_base + str(aadl_model_number_counter).zfill(counter_digit_padding)        # Pad out the number string
        # Create the bus_array and data arrays
        bus_array, data_array = create_and_return__aadl_model_bus_and_data_arrays(valid_combination_device_io_map)
        # Select the System Asset of Importance based on the provided system_asset_of_importance_device_class
        asset_of_importance_match = [device_element for device_element in valid_combination_device_io_map if re.search(system_asset_of_importance_device_class, device_element, re.IGNORECASE)]
        asset_of_importance_name = asset_of_importance_match.pop()        # Pull out the name of the device from the returned match list
        if debugBit != 0:   # ~!~
            print("\tAsset of Importance Search Check:\n\t\tAsset Name:\t{1}".format(asset_of_importance_name))
        system_asset_of_importance = asset_of_importance_name
        ## Call the complete generation and pass these variables
        if debugBit != 0:   # ~!~
            print("[!] Going to try and make an AADL file")
        generate_complete_aadl_model(aadlFilename, packageName, bus_array, data_array, valid_combination_device_io_map, system_model_name, system_io_map, system_implementation_map, system_connections_list, system_edge_devices_array, system_asset_of_importance)     # TODO: Add all the variables generated above (AFTER SPLITTING INTO FUNCTIONS)
        # FAILURE DUE TO 'user_generic_database'.... Why was this not cleaned?
        aadl_model_number_counter += 1      # Increase the model counter
    # Finally return the aadl_model_number_counter so that we can continue with the same numbering scheme for multiple device variations
    return aadl_model_number_counter

## Function for generating a complete AADL model bus_array and data_array
#   - The purpose for this is to create the basis bus types and data types that will be described within the AADL model
def create_and_return__aadl_model_bus_and_data_arrays(device_io_map):
    if debugBit != 0:
        print("[*] Generating the bus and data arrays from the supplied device_io_map")
    bus_array = []
    data_array = []         # Create two empty lists    | NOTE: Can not have the two sets equal to the same thing, cause this has python treat it all as the same thing
    for device_entry in device_io_map:
        for bus_type in device_io_map[device_entry]['bus_connections']:
            if bus_type not in bus_array:
                bus_array.append(bus_type)
        for data_type in device_io_map[device_entry]['io_list']:
            if data_type not in data_array:
                data_array.append(data_type)
    if debugBit != 1:
        print("[+] Completed and returning the bus and data arrays")
        print("\tGenerated Lists:\n\t\tData:\t{0}\n\t\tBus:\t{1}".format(bus_array, data_array))
        print("\tDevice IO Map:\t{0}".format(device_io_map))
    return bus_array, data_array

### Main Code

# Function for generating an AADL file
def main(user_input_file):
    if debugBit != 0:
        print("[*] Beginning GAM....")
    ## NOTE: No longer ask the user for anything expect the initial input
    # TODO: Add check for user input as to which type of AADL model GAM should generate (?)
    # Function call to generate the firewall-to-database AADL model
    #generate_firewall_to_database_aadl_models()
    #generate_smart_home_aadl_models()
    soup_2_nuts(user_input_file)
    # TODO: Create function for creating the adaptive AADL Model
    #   - Have switch statement for which variation of the adaptive Model will be generated
    #   - Have one variation that will just build them ALL
    if debugBit != 0:
        print("[*] Completed GAM!")

# Function that allows this script to be imported without automatically running the main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate AADL Models from a provided user input file.')
    # Add inputs to the function            
    parser.add_argument("userInputFile", help="Properly formatted user input file that details devices, system, architecture, and asset of importance")
    parser.add_argument("-v", "--verbose", action="store_true")
    # Grab the arugments passed to the file  
    args = parser.parse_args()                            
    #print("Args Parsed:\t{0}".format(args))             
    parser.parse_args()                       
    print("[?] Verbosity Level: {0}".format(args.verbose))
    debugBit = args.verbose               
    main(args.userInputFile)
