'''
 The purpose of thise code is to interact with JSON files & objects

 Goals of this code are:
    - Read from JSON file
    - Enumerate through JSON file
    - Mondify/Update JSON file
    - Write new JSON file
        - Use seek() function
        - Use truncate() function
        -> Note: Ensure safety check before OVERWRITE
    - Close JSON file

 
 Author:        Paul A. Wortman
 Last Edit:     6/9/2021 
'''

'''
 Imports
'''
import json

'''
 Defined Classes
'''

'''
 Global Varaibles
'''
verboseBit = 0
debugBit = 0

'''
 Defined Functions
'''
# Function for reading in a JSON file
def readJSON(jsonFile):
    jsonData = {}
    with open(jsonFile, 'r') as infile:
        jsonData  = json.load(infile)
    return jsonData

# Function for searching for a given element within a database
def findEntry(jsonData, entryName):
    if debugBit != 0:
        print("[*] Searching for [" + str(entryName) + "].....")
    if entryName in jsonData:
        if verboseBit != 0:
            print("[!] Hot damn, I found that thing you were looking for")
        return jsonData[entryName]

# Function for returning a subcategory of a database entry
def findSubEntry(entryData, subEntryName):
    if debugBit != 0:
        print("[*] Searching for [" + str(subEntryName) + "].....")
    if entryData is not None:   # Check that something actually got returned
        if subEntryName in entryData:
            if verboseBit != 0:
                print("[!] Sweet jesus! I saw that thing you were looking for")
            return entryData[subEntryName]
    else:
        return None     # If nothing is found, also return a NoneType Object
###
# Functions for adding an item to a provided database file
#   -> Note: Each function is SPECIFIC to the database being interacted with; the 'addEntry()' function is there for basic testing ONLY
###
# Function to add/update and entry to a given database
#   -> Note: This will overwrite an existing entry
def updateEntry(jsonData, entryName):
    if debugBit != 0:
        print("[*] Adding entry [" + str(entryName) + "]....")
    if jsonData is not None:        # Check that the database exists
        # NOTE: Don't need to use append since not a list, and new entries to a dictionary are this easy as py
        jsonData[entryName] = {  
                "Something": "Number",
                "Something Else": "Not Number",
                "Zuul": "No Diane"
            }
        if debugBit != 0:
            print("[+] Entry added to the provided Database file")
    else:
        print("[-] No Database information was provided to the function")

# Function for adding/updating an entry in the Risk Database
def updateEntry_riskDb(jsonData, entryName):
    if debugBit != 0:
        print("[*] Adding entry [" + str(entryName) + "]...")
    if jsonData is not None:        # Check that the database exists
        # Request information from User
        entry_Ps = float(input('What is the Probability of Success for ' + str(entryName) + ' (0.0 to 1.0); default 0.5: '))
        if entry_Ps is '':      # Set default if none given
            entry_Ps = "0.5"
        entry_Ca = float(input('What is the Cost of Attack for ' + str(entryName) + '; default 1: '))
        if entry_Ca is '':
            entry_Ca = "1"
        # Write collectecd information to database
        jsonData[entryName] = {
                "Probability of Success": entry_Ps,
                "Cost of Attack": entry_Ca
            }
        if debugBit != 0:
            print("[+] Entry added to the Risk Database")
    else:
        print("[-] No Database information was provided to the function")

# Function for adding/updating an entry in the Risk Database
def updateEntry_riskDb_userless(jsonData, entryName, entryProbOfSuccess, entryCostOfAttack):
    if debugBit != 0:
        print("[*] Adding entry [" + str(entryName) + "]...")
    if jsonData is not None:        # Check that the database exists
        # Request information from User
        #entry_Ps = float(input('What is the Probability of Success for ' + str(entryName) + ' (0.0 to 1.0); default 0.5: '))
        #if entry_Ps is '':      # Set default if none given
            #entry_Ps = "0.5"
        #entry_Ca = float(input('What is the Cost of Attack for ' + str(entryName) + '; default 1: '))
        #if entry_Ca is '':
            #entry_Ca = "1"
        # Write collectecd information to database
        jsonData[entryName] = {
                "Probability of Success": entryProbOfSuccess,
                "Cost of Attack": entryCostOfAttack
            }
        if debugBit != 0:
            print("[+] Entry added to the Risk Database")
    else:
        print("[-] No Database information was provided to the function")


# Function for adding/updating an entry in the Cost Database
def updateEntry_costDb(jsonData, entryName):
    if debugBit != 0:
        print("[*] Adding entry [" + str(entryName) + "]...")
    if jsonData is not None:        # Check that the database exists
        # Request information from User
        entry_Ci = float(input('What is the Initial Cost for ' + str(entryName) + ' (in dollars); default 2000: '))
        if entry_Ci is '':
            entry_Ci = "2000"
        entry_Cm = float(input('What is the Maintainence Cost for ' + str(entryName) + ' (in dollars); default 500: '))
        if entry_Cm is '':
            entry_Cm = "500"
        entry_Co = float(input('What is the Operational Cost for ' + str(entryName) + ' (in dollars); default 130: '))
        if entry_Co is '':
            entry_Co = "130"
        # Write collected information to databaes
        jsonData[entryName] = {
                "Cost of Initialization": entry_Ci,
                "Cost of Maintainence": entry_Cm,
                "Cost of Operation": entry_Co
            }
        if debugBit != 0:
            print("[+] Entry added to the cost Database")
    else:
        print("[-] No Database information was provided to the function")

# Function for adding/updating an entry in the Asset Database
def updateEntry_assetDb(jsonData, entryName):
    if debugBit != 0:
        print("[*] Adding entry [" + str(entryName) + "]...")
    if jsonData is not None:        # Check that the database exists
        # Request information from User
        entry_impact = float(input('What is the Impact for ' + str(entryName) + ' (0.0 to 99.0); default 42.0: '))
        if entry_impact is '':
            entry_impact = "42.0"
        entry_atkrVal = float(input('What is the Attacker Value for ' + str(entryName) + ' (0.0 to 99.0); default 28.0: '))
        if entry_atkrVal is '':
            entry_atkrVal = "28.0"
        entry_alpha = float(input('What is the Alpha for ' + str(entryName) + ' (0.0 to 1.0); default 1: '))
        if entry_alpha is '':
            entry_alpha = "1"
        entry_scaleAmount = float(input('What is the scale amoutn for the values being supplied by the user (e.g. 100); default 1000: '))
        if entry_scaleAmount is '':
            entry_scaleAmount = "1000"
        # Write collected information to databaes
        jsonData[entryName] = {
                "Impact": entry_impact,
                "Attacker Value": entry_atkrVal,
                "Alpha": entry_alpha,
                "Scale Amount": entry_scaleAmount
            }
        if debugBit != 0:
            print("[+] Entry added to the Asset Database")
    else:
        print("[-] No Database information was provided to the function")

###
# Functions for creating/removing a database file (?? IF THIS IS NEEDED ??)
###

# Function for saving a database file
def saveDb(jsonData, databaseFile):
    if debugBit != 1:
        print("[!] Saving database to [" + str(databaseFile) + "]....")
    with open(databaseFile, 'w') as jsonFile:
        json.dump(jsonData, jsonFile)

# Function for creating a database file

###
# Functions for Risk Values
###
# Function to return the Cost of Attack for given entry
def retCostOfAttack(entryData):
    return findSubEntry(entryData, 'Cost of Attack')

# Funcation to return the Probability of Success for given entry
def retProbOfSuccess(entryData):
    return findSubEntry(entryData, 'Probability of Success')

###
# Functions for Cost Values
###
# Function to return the Const of Initialization for given entry
def retCostOfInit(entryData):
    return findSubEntry(entryData, 'Cost of Initialization')

# Function to return the Cost of Maintainence for given entry
def retCostOfMain(entryData):
    return findSubEntry(entryData, 'Cost of Maintainence')

# Function to return the Cost of Operation for given entry
def retCostOfOper(entryData):
    return findSubEntry(entryData, 'Cost of Operation')

###
# Functions for Asset Values
###
# Function to return the Impact for given entry
def retImpact(entryData):
    return findSubEntry(entryData, 'Impact')

# Function to return the Attacker Value for given entry
def retAtkrVal(entryData):
    return findSubEntry(entryData, 'Attacker Value')

# Function to return the Alpha values for given entry
def retAlpha(entryData):
    return findSubEntry(entryData, 'Alpha')

# Function to return the Scale Amount value for given entry
def retScaleAmnt(entryData):
    return findSubEntry(entryData, 'Scale Amount')

###
# Continue creating search functions, create one to return all data??
#   -> NOTE: These functson are what will be called in combineScript.py to retrieve data
# TODO: Add in modification & adding of entries to database
#   -> Write functions to add specific pieces of infmraiton
###

# main() funcation
def main():
    print("[*] Inside the ioDatabase main function")

# Function that allows this script to be imported without automatically running the main function
if __name__ == "__main___":
    main()
