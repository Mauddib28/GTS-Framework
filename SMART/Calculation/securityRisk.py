#!/usr/bin/python

'''
 The purpose of this code is to calculate the security risk of a given asset 

 
 Author:        Paul A. Wortman
 Last Edit:     6/9/2021 

 Default Values:        [Note: The dollar amounts are scaled; $1k or $10k]
    -> Attack Value (A)         =   20
    -> Impact (I)               =   11.7
    -> Attack Cost (ca)         =   7
    -> Alpha Value              =   1
    -> Operational Cost (co)    =   2.45
    -> Maintenance Cost (cm)    =   7

 Basic Network Items:                   SL          ps          pa          SR          ci       ps * A >= ca?
    -> Database                 =       0.0         1.0         0.9999997   11.699974   3000        T
    -> Webserver w/ Database    =       0.1         0.9         0.9999833   10.529824   13000       T           [Design #1]
    -> Webserver                =       0.15        0.85        0.9999546   9.9445485   10000       T
    -> External Firewall        =       0.25        0.75        0.9996645   8.7720563   8000        T
    -> Internal Firewall        =       0.45        0.55        0.9816844   6.3171389   12000       T
    -> 3rd Party Application    =       0.7         0.3         0           0           20000       F
    -> VPN                      =       1.0         0.0         0           0           22000       F           [Design #5]
    -> Router                   =                                                       6000

 VPN Type:                  SL      ps      pa      SR      ci      ps * A >= ca?
    -> Credentials      =   0.8     0.2     0                           F
    -> Keys             =   1.0     0.0     0                           F

 Combinations:                                                  SL          ps          pa          SR          ci          ps * A >= ca?
    -> Ext. FW + Router + Webserver w/DB                =       0.325       0.675       0.9984966   7.8856266   21000           T           [Design #2]
    -> Webserver + Int. FW + Router + DB                =       0.5325      0.4675      0.9046308   4.9481045   25000           T           [Design #3]
    -> Ext. FW + Router + WS + Int. FW + Router + DB    =       0.649375    0.350625    0.0124222   0.0509597   33000           T           [Design #4]
    -> VPN w/ Credentials + Router                      =       0.8         0.2         0           0           18000           F
    -> WPN w/ Keys + Router                             =       1.0         0.0         0           0           21000           F

 Overall Attack Tree:                   Sum SR
    -> Ext. FW + VPN Path       =       7.8856266
    -> Ext. FW + App Path       =       7.8856266
    -> Ext. FW + App + VPN Path =       7.8856266
    -> Int. FW + VPN Path       =       4.9481045
    -> Int. FW + App Path       =       4.9481045
    -> Int. FW + App + VPN Path =       4.9481045
    -> App Path + VPN Path      =       0
    -> Full FW + VPN Path       =       0.0509597
    -> Full FW + App + VPN Path =       0.0509597
    -> Full FW + App Path       =       0.0509597

 NEED: ~!~ Create function that does all of the calculcation steps and produces answer based on only a few inputted values
 NEED: ~!~ Create method to input CSVs for each element in a design
    -> Include an over all design CSV for the combined elements
'''

'''
 Imports
'''
import sys      # Import for determining passed arguments
import math     # Import for using e exponential for probability of attack calculcations
import argparse    # Import for easy help and usage message, issue error, and writing user-friendly command-line script
import itertools    # Import for generation of all map paths

'''
 Debug and Other Variable Definitions
'''
debugBit = 0
verboseBit = 0
fListsBit = 0

'''
 Function Definitions
'''
# Function for calculating the probability of success for a single element given a Security Level (SL) value
def calcProbOfSuccess(securityLevel):
    return 1 - securityLevel

# Function for calculating total probability of success along a path (e.g. product of probabilities)
# Input: Currently brought in as a list of values   -[ Ex: (0.43, 0.78) ]-
def calcPathProbOfSuccess(securityLevels):     # Note: * here takes in as many variables as are present(???)    <----- Removing the * could cause issues with the TEST SCENARIO SCRIPT FUNCTIONS!!!
    pathPS = 1      # Set to one because multiplication won't be affected
    if fListsBit != 0:      # ~!~
        print("-- calcPathProbOfSuccess()::Checking Type: " + str(type(securityLevels)))    # Note: Fix to change from tuple to list | Adding [] makes it a list
        print("\t\tVar: " + str(securityLevels))
    for securityLevel in securityLevels:
        if fListsBit != 0:
            print("\t-- checking in loop; Checking Type: " + str(type(securityLevel)))
        pathPS *= securityLevel
        if fListsBit != 0:      # ~!~
            print("\t-- checking in loop: type of variables:\n\t\tpathPS: " + str(type(pathPS)) + "\t value: " + str(pathPS) + "\n\t\tsecurityLevel: " + str(type(securityLevel)) + "\t value: " + str(securityLevel))  # Note: Make conversion when the data is brough in from the user
    return pathPS
# Nota Bene: Works fine for varaibles passed to it, but NOT for raw numbers.... WHY?!?!?!

# function for calculating the total cost of attack along a path (e.g. summations of costs of attack)
def calcPathCostOfAttack(costsOfAttack):   # Note: * here takes in as many variables as are present             <----- Same warning as above about removing the '*' and the test functions
    pathCA = 0  # Set to zero because summation won't be affected
    if fListsBit != 0:
        print("-- calcPathCostOfAttack()::Checking Type: " + str(type(costsOfAttack)))
        print("\t\tVar: " + str(costsOfAttack))
    for costOfAttack in costsOfAttack:
        if fListsBit != 0:
            print("\t-- checking in loop; Checking Type: " + str(type(costOfAttack)))
        pathCA += costOfAttack
        if fListsBit != 0:
            print("\t-- checking in loop; type of variables:\n\t\tpathCA: " + str(type(pathCA)) + "\t value: " + str(pathCA) + "\n\t\tcostOfAttack: " + str(type(costOfAttack)) + "\t value: " + str(costOfAttack))
    return pathCA

# Function for determining if attack success reward greater than or equal to attacker cost
def checkAttackerChance(elem_PS, elem_AV, elem_CA):
    if verboseBit != 0:
        print("[?] Variable Check in securityRisk::checkAttackerChance:\n\telem_PS:\t{0}\n\telem_AV:\t{1}\n\telem_CA:\t{2}".format(elem_PS, elem_AV, elem_CA))
    return (elem_PS * elem_AV) >= elem_CA
    # EDIT for testing 3D graph fold
    #return True
    #return False    # Test for negative of conditional ONLY

# Funcation for calculating the probability of attack based on given variables
def calcProbOfAttack(elem_Alpha, elem_PS, elem_AV, elem_CA):
    return (1 - math.exp(-(elem_Alpha) * ((elem_PS * elem_AV) - elem_CA)))

# Function for calculating the security risk based on given variable values
def calcSecurityRisk(elem_PA, elem_PS, elem_Impact):
    if verboseBit != 0:
        print("[?] Values for Calculation of SR:\n\telem_PA:\t{0}\n\telem_PS:\t{1}\n\telem_Impact:\t{2}".format(elem_PA,elem_PS,elem_Impact))
    return elem_PA * elem_PS * elem_Impact

# Function for calculating the total cost based on combined cost of design and the security risk of the design
#   Note: The SR value will NOT be scaled to the same magnitude as the Cost varaible!! This will be fixed here within the function
def calcTotalCost(elem_Cost, elem_SR, scaleVar):
    return elem_Cost + (elem_SR * scaleVar)

# Function that envelops check for attacker chance, then calc Prob of Attack, and return any value based on these two step checks
def calcProbOfRewardingAttack(elem_Alpha, elem_PS, elem_AV, elem_CA):
    if fListsBit != 0:
        print("-- calcProbOfRewardingAttack()::Checking Type: " + str(type(elem_PS)))
    if checkAttackerChance(elem_PS, elem_AV, elem_CA):
        elem_PA = calcProbOfAttack(elem_Alpha, elem_PS, elem_AV, elem_CA)
    else:
        print("[!] The attack path is NOT WORTH IT.... PA being set to ZERO")
        elem_PA = 0     # Where the Pa of zero is coming from; since system is not worth attacking
    return elem_PA

# Function for calculating the security risk of a single element
def securityRiskCost_element(elem_PS, elem_Alpha, elem_AV, elem_CA, elem_Impact):
    #print("[*] Establishing the element Security Level value")
    #element_SL = elem_SL
    #print("[*] Calculating the element's Probability of Success")
    #element_PS = calcProbOfSuccess(elem_SL)     # Skip this step and just use PS?
    if verboseBit != 0:
        print("[*] Establishing the element's Probability of Success")
    element_PS = elem_PS
    if verboseBit != 0:
        print("[*] Calculating the element's Probability of Attack")
    element_Alpha = elem_Alpha
    element_AV = elem_AV
    element_CA = elem_CA
    element_PA = calcProbOfRewardingAttack(element_Alpha, element_PS, element_AV, element_CA)
    if verboseBit != 0:
        print("[*] Calculating the element's Security Risk")
    element_Impact = elem_Impact
    element_SR = calcSecurityRisk(element_PA, element_PS, element_Impact)
    return element_SR

# Function for calculating the security risk of a path of elements
# Note: This function will need to make use of a list of variables (Probability of Success values)
# Inputs:
#   -> List of Probabilities    -   probabilities
#       - Note: List passed as a single variable    -[ Ex: [0.43, 0.78] ]-
#   -> Alpha for Path           -   path_Alpha
#   -> Attack Value for Path    -   path_AV
#   -> Cost of Attack for Path  -   path_CA         <---- Also coming as a list
#   -> Impact for Path Exploit  -   path_Impact
def securityRiskCost_path(probabilities, path_Alpha, path_AV, path_CA, path_Impact):
    if verboseBit != 0:     # ~!~
        print("[*] Establishing the path's Probability of Success")
        print("[?] Function Input Breakdown (FIB).....securityRisk::securityRiskCost_path\n\tNote:\tProbabilities should be list passed as a single variable")
        print("\tProbabilities:\t\t" + str(probabilities) + "\n\tAlpha:\t\t\t" + str(path_Alpha) + "\n\tAttack Value:\t\t" + str(path_AV) + "\n\tCost of Attack:\t\t" + str(path_CA) + "\n\tImpact:\t\t\t" + str(path_Impact))
    if fListsBit != 0:
        print("-- securityRiskCost_path()::Checking Type: " + str(type(probabilities)))
        print("\tVar: " + str(probabilities))
    #print("\t-- checking conversion: " + str(type(*probabilities)))
    # Calculate the path probability                                                                                                                                                        __
    path_PS = calcPathProbOfSuccess(probabilities) # Note: The pointer here makes a difference for the 'Function Test' | Dereferenced the list?     <----- Note: This is taking the ps(P) = || pex(v) for v E P, but do NOT have that yet
    if verboseBit != 0:     # ~!~
        print("[*] Calculating the path's Probability of Attack")
        print("\tpath_PS = " + str(path_PS))
    if fListsBit != 0:
        print("-- securityRiskCost_path()::Checking Type: " + str(type(path_PS)))
    # Calculate the path cost of attack
    path_CA = calcPathCostOfAttack(path_CA)    # Note: The pointer here makes a difference (see above)                                              <----- Note: This also takes the sum of all costs in the path, but do NOT have that yet
    print("[?] Testing variables before calculating PA:\n\tAlpha:\t{0}\n\tPath Ps:\t{1}\n\tPath AV:\t{2}\n\tPath CA:\t{3}".format(path_Alpha, path_PS, path_AV, path_CA))
    path_PA = calcProbOfRewardingAttack(path_Alpha, path_PS, path_AV, path_CA)                                                                  #   <----- Note: This also takes calculation on a per-path basis, but do NOT have this yet
    if verboseBit != 0:     # ~!~
        print("[*] Calculating the path's Security Risk")
        print("\tPa:\t{0}\n\tPs:\t{1}\n\tImp:\t{2}".format(path_PA, path_PS, path_Impact))                  # NOTE: Issue is that path_PA is being passed as 0 here...
    # Calculate the security risk
    path_SR = calcSecurityRisk(path_PA, path_PS, path_Impact)                                                                                   #   <----- Note: This also does calculation on a per path basis, but do NOT have this yet
    if verboseBit != 0:     # ~!~
        print("\tSecurity Risk for Path:\t" + str(path_SR))         # Where I am seeing a 0.0 for risk...
    return path_SR

'''
# Function for aggregating security risk for multiple paths to a single objective
def securityRiskCost_paths(probabilities, path_Alpha, path_AV, path_CA, path_Impact):
    attackPaths = []
    paths_SR = []
    if verboseBit != 1:
        print("[?] Function Input Breakdown (FIB).....")
        print("\tProbabilities:\t\t" + str(probabilities) + "\n\tAlpha:\t\t\t" + str(path_Alpha) + "\n\tAttack Value:\t\t" + str(path_AV) + "\n\tCost of Attack:\t\t" + str(path_CA) + "\n\tImpact:\t\t\t" + str(path_Impact))
    for attackPath in range(len(probabilities)):
        if verboseBit != 1:
            print("[*] Enumerating through attack paths.....")
            print("\tCurrent Attack Path: " + str(attackPath))
        path_SR = securityRiskCost_path(probabilities[attackPath], path_Alpha, path_AV, path_CA[attackPath], path_Impact)
        paths_SR.append(path_SR)
    return paths_SR
'''

# Function for performing total security risk and cost calculation based on initial variables
#
# Input Variables to function:
#   -> Path's Probability of Success    -   path_PS         []
#   -> Path's Alpha Value               -   path_Aplha
#   -> Path's Attack Value              -   path_AV
#   -> Path's Cost of Attack            -   path_CA         []
#   -> Path's Impact                    -   path_Impact
#
# External Information Needed [Additional Function Input]
#   -> Attacker Value
#   -> Cost of Action to Attacker
#   -> Impact of Compromise to Defender
#   -> Costs of Design
#       -> Implementation Costs (ci)
#       -> Cost of Operation (co)
#       -> Cost of Maintenance (cm)
#   -> Scale of Variables (e.g. difference in magnitude between SR values and Costs)
# NEED: ~!~ Add check for incoming varibales that the ranges make sense
#
# Output from function:
#   -> calcTotalCost    -   Security Risk cost (USD) for all path combinations of a given potential path pairings                                                       \
#   -> subPathMaxSR     -   Security Risk associated with the most ``security risk expensive'' path in the evaluated attack tree                                        |-----  All need to be scaled (e.g. default 1000) to match the scale of ci, co, cm, etc.
#   -> subPathMaxSRitem -   Position in list(itertools.product(*<PS/CS Array>)) list that corresponds to the most ``security risk expensive'' path in the attack tree   |
#   -> subPathMinSR     -   Security Risk associated with the least ``security risk expensive'' path in the evaluated attack tree                                       |
#   -> subPathMinSRitem -   Position in list(itertools.product(*<PS/CS Array>)) list that corresponds to the least ``security risk expensive'' path in the attack tree  /
def fullPathTotalCost(path_PS, path_Alpha, path_AV, path_CA, path_Impact, path_ci, path_cm, path_co, scaleAmount):
    if debugBit != 0:
        print("[*] Establishing varaibles based on function inputs....")
    if verboseBit != 0: # ~!~
        print("[?] Function Input Breakdown (FIB)....... securityRisk::fullPathTotalCost")
        print("\tPath PS:\t\t\t" + str(path_PS) + "\n\tPath Alpha:\t\t\t" + str(path_Alpha) + "\n\tPath AtkVal:\t\t\t" + str(path_AV) + "\n\tPath CA:\t\t\t" + str(path_CA) + "\n\tPath Impact:\t\t\t" + str(path_Impact) + "\n\tPath Ci:\t\t\t" + str(path_ci) + "\n\tPath Cm:\t\t\t" + str(path_cm) + "\n\tPath Co:\t\t\t" + str(path_co) + "\n\tScale Amount:\t\t\t" + str(scaleAmount))
    if fListsBit != 0:
        print("-- fullPathTotalCost()::Checking Type: " + str(type(path_PS)))
        print("\tVar: " + str(path_PS))
    # Generate the product of attack tree Ps and Ca lists
    potentPath_PS = list(itertools.product(*path_PS))     # Create Ps potential paths list product
    potentPath_CA = list(itertools.product(*path_CA))     # Create Ca potential paths list product
    # NOTE: Both of the above are lists of the same length; therefore SHOULD be able to duplicate via the higher level CVE list itertools.product
    testPath_PS = []
    for item in itertools.product(*path_PS):
        testPath_PS.append(list(item))
    testPath_CA = []
    for item in itertools.product(*path_CA):
        testPath_CA.append(list(item))
    if fListsBit != 0:      # CHANGED FOR DEBUGGING | ~!~
        print("-- fullPathTotalCost()::Checking Lists:\n\tOrig Ps:\t{0}\n\tProd Ps:\t{1}\n\tTest Ps:\t{4}\n\tOrig Ca:\t{2}\n\tProd Ca:\t{3}\n\tTest Ca:\t{5}".format(path_PS, potentPath_PS, path_CA, potentPath_CA, testPath_PS, testPath_CA))
    path_SR = 0
    # Below produces correct lists  |   NEXT: CHECK THAT PS and CA GET CALCULATED CORRECTLY!!!
    #pathCA += costOfAttack
    path_PS = testPath_PS
    path_CA = testPath_CA
    subPathTrackerVar = 0
    subPathMaxSR = 0
    subPathMaxSRitem = 0
    # Adding in min versions of the variables
    subPathMinSR = 0
    subPathMinSRitem = 0
    for path in range(len(path_PS)):
        if fListsBit != 0:      # ~!~
            print("\tpath:\t{0}\n\tPs:\t{1}\n\tCa:\t{2}\n\tLen Ps:\t{3}".format(path, path_PS[path], path_CA[path], len(path_PS)))        # Check that this is correct, if I can make sure that subLists are getting passed here, then OK; otherwise have to create a 2nd layer sub-loop
        path_SR += securityRiskCost_path(path_PS[path], path_Alpha, path_AV, path_CA[path], path_Impact)    # Where each path's cost is determined
        # Check and determine individual path SR values and find ``most expensive'' path
        tmpSR = securityRiskCost_path(path_PS[path], path_Alpha, path_AV, path_CA[path], path_Impact)
        print("[?] Check SR Values:\n\tpath_SR:\t{0}\n\ttmpSR:\t{1}".format(path_SR, tmpSR))            # <---- NOTE: Getting weird behavior of 0 being returned for the path_SR / tmpSR for any calculation after the first
        if int(tmpSR) > subPathMaxSR:
            subPathMaxSR = tmpSR
            subPathMaxSRitem = subPathTrackerVar
        # Adding in minimum path check
        if subPathMinSR == 0:
            subPathMinSR = tmpSR
            subPathMinSRitem = subPathTrackerVar
        elif (int(tmpSR) < subPathMinSR) and (tmpSR != 0):
            sinPathMinSR = tmpSR
            subPathMinSRitem = subPathTrackerVar
        subPathTrackerVar += 1
    if debugBit != 0:       # ~!~
        # NOTE/TODO: Add in logic check to make sure that the reference frame for the output works
        if path_PS:     # The path_PS list is NON-EMPTY
            print("[?] ======= Expensive Path Information ======= [?]\n\tMax Path SR:\t{0}\n\tMax Path Item:\t{1}\n\tTracker Variable:\t{2}\n\tPath PS:\t{3}\n\tPath CA:\t{4}\n".format(subPathMaxSR, subPathMaxSRitem, subPathTrackerVar, path_PS[subPathMaxSRitem], path_CA[subPathMaxSRitem]))
        else:           # The path_PS list is EMPTY
            if path_CA:     # The path_CA list is NON-EMPTY
                print("[?] ======= Expensive Path Information ======= [?]\n\tMax Path SR:\t{0}\n\tMax Path Item:\t{1}\n\tTracker Variable:\t{2}\n\tPath PS:\t{3}\n\tPath CA:\t{4}\n".format(subPathMaxSR, subPathMaxSRitem, subPathTrackerVar,"None", path_CA[subPathMaxSRitem]))
            else:           # The path_CA list is EMPTY
                print("[?] ======= Expensive Path Information ======= [?]\n\tMax Path SR:\t{0}\n\tMax Path Item:\t{1}\n\tTracker Variable:\t{2}\n\tPath PS:\t{3}\n\tPath CA:\t{4}\n".format(subPathMaxSR, subPathMaxSRitem, subPathTrackerVar, "None", "None"))
    if verboseBit != 0:     # ~!~
        print("[?] path_SR summartion: {0}".format(path_SR))
    # NEED: ~!~ create a sum of the ci values passed
    path_Cost = 0
    if fListsBit != 0:
        print("-- path_ci information:\n\tType: " + str(type(path_ci)) + "\n\tValue: " + str(path_ci))
    for initCost in path_ci:
        path_Cost += initCost
    path_Cost += path_cm + path_co
    if verboseBit != 0:     # ~!~
        print("[?] Data Check before Calculating Total Cost:\n\tpath_Cost:\t{0}\n\tpath_SR:\t{1}\n\tscale:\t{2}".format(path_Cost, path_SR, scaleAmount))
    return calcTotalCost(path_Cost, path_SR, scaleAmount), subPathMaxSR, subPathMaxSRitem, subPathMinSR, subPathMinSRitem               # Now returns the total Path Cost, the maximum SR of all subPaths, and the item # of that max SR path (start counting from 0)

# Function for calculating path cost based on provided inputs
#   Input Notes:
#       -> path_PS  -   Must be passed as a list of the path PS values (e.g. [pathItem01_PS, pathItem02_PS, pathItem03_PS,...., pathItemXX_PS])
#       -> path_ci  -   Must be passed as a list of the path ci values (e.g. [pathItem01_ci, pathItem03_ci, pathItem03_ci,...., pathItemXX_ci])
def pathCostCalc(path_PS, path_alpha, path_attackValue, path_attackCost, path_impact, path_ci, path_cost_maintenance, path_cost_operation, path_scaleAmount):
    if debugBit != 0:
        print("[*] Printing out the results of the path cost run")
        print("\t\t\tTotal Cost\n\tPath:\t{0}\n\tMax Path:\t{1}\n\tPath Var:\t{2}\n".format(fullPathTotalCost(path_PS, path_alpha, path_attackValue, path_attackCost, path_impact, path_ci, path_cost_maintenance, path_cost_operation, path_scaleAmount)[0], fullPathTotalCost(path_PS, path_alpha, path_attackValue, path_attackCost, path_impact, path_ci, path_cost_maintenance, path_cost_operation, path_scaleAmount)[1], fullPathTotalCost(path_PS, path_alpha, path_attackValue, path_attackCost, path_impact, path_ci, path_cost_maintenance, path_cost_operation, path_scaleAmount)[2]))    # Print out the cost part of the return?
    # Return the calculated value
    return fullPathTotalCost(path_PS, path_alpha, path_attackValue, path_attackCost, path_impact, path_ci, path_cost_maintenance, path_cost_operation, path_scaleAmount)

# Function use for testing user input for calculation of total cost
def userRunCalc():
    # User suppled variables
    #   -> NEED: ~!~ Fix to be values passed to the function
    webserverWDB_PS = 0.9
    extFirewall_PS = 0.75
    webserver_PS = 0.85
    intFirewall_PS = 0.55
    database_PS = 1.0
    VPN_PS = 0.0
    attackValue = 20
    attackCost = 7
    impact = 11.7
    alpha = 1
    Router_ci = 6000
    webserverWDB_ci = 13000
    extFirewall_ci = 8000
    intFirewall_ci = 12000
    database_ci = 3000
    webserver_ci = 10000
    VPN_ci = 22000
    cost_maintenance = 70000
    cost_operation = 2450
    scaleAmount = 1000
    print("[*] Printing out the results of the run")
    print("\tDesign #\tTotal Cost")
    print("\tDesign #1\t{0}".format(fullPathTotalCost([webserverWDB_PS], alpha, attackValue, attackCost, impact, [webserverWDB_ci, Router_ci], cost_maintenance, cost_operation, scaleAmount)))
    print("\tDesign #2\t{0}".format(fullPathTotalCost([extFirewall_PS, webserverWDB_PS], alpha, attackValue, attackCost, impact, [extFirewall_ci, Router_ci, webserverWDB_ci], cost_maintenance, cost_operation, scaleAmount)))
    print("\tDesign #3\t{0}".format(fullPathTotalCost([webserver_PS, intFirewall_PS, database_PS], alpha, attackValue, attackCost, impact, [webserver_ci, intFirewall_ci, Router_ci, database_ci], cost_maintenance, cost_operation, scaleAmount)))
    print("\tDesign #4\t{0}".format(fullPathTotalCost([extFirewall_PS, webserver_PS, intFirewall_PS, database_PS], alpha, attackValue, attackCost, impact, [extFirewall_ci, Router_ci, webserver_ci, intFirewall_ci, Router_ci, database_ci], cost_maintenance, cost_operation, scaleAmount)))
    print("\tDesign #5\t{0}".format(fullPathTotalCost([VPN_PS], alpha, attackValue, attackCost, impact, [VPN_ci, Router_ci, database_ci], cost_maintenance, cost_operation, scaleAmount)))
    return 0

# Function used for testing of re-creation of example calculations thorugh use of functions
#   Note: Doing this run with the five example designs
def testRunCalc():
    print("[*] Creating the test scenario Security Levels, alpha values, costs")
    # Security Levels
    database_SL = 0.0
    webserverWDB_SL = 0.1
    webserver_SL = 0.15
    extFirewall_SL = 0.25
    intFirewall_SL = 0.45
    ThirdPartyApp_SL = 0.7
    VPN_SL = 1.0
    # Attack Variables
    attackValue = 20
    attackCost = 7
    # Defense Variables
    impact = 11.7
    # Alpha Variable
    alpha = 1
    # Costs of implementation
    database_ci = 3000
    webserverWDB_ci = 13000
    webserver_ci = 10000
    extFirewall_ci = 8000
    intFirewall_ci = 12000
    ThirdPartyApp_ci = 20000
    VPN_ci = 22000
    Router_ci = 6000
    # Costs of maintenance and operation
    cost_maintenance = 70000
    cost_operation = 2450
    # Scaling Variable
    scaleAmount = 1000
    print("[*] Generating the test scenario probabilities of success")
    database_PS = calcProbOfSuccess(database_SL)
    webserverWDB_PS = calcProbOfSuccess(webserverWDB_SL)
    webserver_PS = calcProbOfSuccess(webserver_SL)
    extFirewall_PS = calcProbOfSuccess(extFirewall_SL)
    intFirewall_PS = calcProbOfSuccess(intFirewall_SL)
    ThirdPartyApp_PS = calcProbOfSuccess(ThirdPartyApp_SL)
    VPN_PS = calcProbOfSuccess(VPN_SL)
    print("[*] Beginning run to generate security risk for each design element")
    database_SR = securityRiskCost_element(database_PS, alpha, attackValue, attackCost, impact)
    webserverWDB_SR = securityRiskCost_element(webserverWDB_PS, alpha, attackValue, attackCost, impact)
    webserver_SR = securityRiskCost_element(webserver_PS, alpha, attackValue, attackCost, impact)
    extFirewall_SR = securityRiskCost_element(extFirewall_PS, alpha, attackValue, attackCost, impact)
    intFirewall_SR = securityRiskCost_element(intFirewall_PS, alpha, attackValue, attackCost, impact)
    ThirdPartyApp_SR = securityRiskCost_element(ThirdPartyApp_PS, alpha, attackValue, attackCost, impact)
    VPN_SR = securityRiskCost_element(VPN_PS, alpha, attackValue, attackCost, impact)
    # Nota Bene: NEED to expand this part to calculate the combined probability of success.... Otherwise will NOT be able to get path SR
    ###
    # Designs:
    #   1) Webserver with Database
    #   2) External Firewall + Router + Webserver with Database
    #   3) Webserver + Internal Firewall + Router + Database
    #   4) External Firewall + Router + Webserver + Internal Firewall + Router + Database
    #   5) VPN Solution
    ###
    print("[*] Calculating the security risk of each design scenario")
    # NEED: ~!~ Redo with a list of different paths going into a single element
    design01_SR = securityRiskCost_element(webserverWDB_PS, alpha, attackValue, attackCost, impact) # Note: Can be done with the path function
    design02_SR = securityRiskCost_path([extFirewall_PS, webserverWDB_PS], alpha, attackValue, attackCost, impact)
    design03_SR = securityRiskCost_path([webserver_PS, intFirewall_PS, database_PS], alpha, attackValue, attackCost, impact)
    design04_SR = securityRiskCost_path([extFirewall_PS, webserver_PS, intFirewall_PS, database_PS], alpha, attackValue, attackCost, impact)
    design05_SR = securityRiskCost_path([VPN_PS], alpha, attackValue, attackCost, impact)
    print("[*] Calculating the costs of each design")
    design01_Cost = Router_ci + webserverWDB_ci + cost_maintenance + cost_operation
    design02_Cost = extFirewall_ci + Router_ci + webserverWDB_ci + cost_maintenance + cost_operation
    design03_Cost = webserver_ci + intFirewall_ci + Router_ci + database_ci + cost_maintenance + cost_operation
    design04_Cost = extFirewall_ci + Router_ci + webserver_ci + intFirewall_ci + Router_ci + database_ci + cost_maintenance + cost_operation
    design05_Cost = VPN_ci + Router_ci + database_ci + cost_maintenance + cost_operation
    print("[*] Printing out the results of the run")
    print("\tDesign #\tTotal Cost")
    print("\tDesign #1\t{0}".format(calcTotalCost(design01_Cost, design01_SR, scaleAmount)))
    print("\tDesign #2\t{0}".format(calcTotalCost(design02_Cost, design02_SR, scaleAmount)))
    print("\tDesign #3\t{0}".format(calcTotalCost(design03_Cost, design03_SR, scaleAmount)))
    print("\tDesign #4\t{0}".format(calcTotalCost(design04_Cost, design04_SR, scaleAmount)))
    print("\tDesign #5\t{0}".format(calcTotalCost(design05_Cost, design05_SR, scaleAmount)))
    return 0 #totalCost

#####
# Function for doing basic example calculations for security risk and total cost
#
# Note: This function uses default values and allows for an example to build the rest of the functional code around
#   - Need to fix to allow for more variable input
#####
def defaultSecurityRiskCostRun():
	print("[*] Generating the default Security Level values....")
	database_SL = 0.0
	webserverWDB_SL = 0.1
	webserver_SL = 0.15
	extFirewall_SL = 0.25
	intFirewall_SL = 0.45
	ThirdPartyApp_SL = 0.7
	VPN_SL = 1.0
	# Note: the 'Router' element is assumed to have no registerable SL or PS value
	#   -> This is due to being seems as a 'dumb piece of metal'
	
	print("[*] Setting up the Security Levels for VPN variations....")
	VPN_Creds_SL = 0.8
	VPN_Keys_SL = 1.0
	
	# Calculate the Probability of Success (ps)
	'''
	 Calculated via:    ps = 1 - SL
	'''
	print("[*] Generating the Probability of Success values for all variables....")
	database_PS = calcProbOfSuccess(database_SL)
	webserverWDB_PS = calcProbOfSuccess(webserverWDB_SL)
	webserver_PS = calcProbOfSuccess(webserver_SL)
	extFirewall_PS = calcProbOfSuccess(extFirewall_SL)
	intFirewall_PS = calcProbOfSuccess(intFirewall_SL)
	ThirdPartyApp_PS = calcProbOfSuccess(ThirdPartyApp_SL)
	VPN_PS = calcProbOfSuccess(VPN_SL)
	
	print("-- Continuing Probability of Success calculations....")
	VPN_Creds_PS = calcProbOfSuccess(VPN_Creds_SL)
	VPN_Keys_PS = calcProbOfSuccess(VPN_Keys_SL)
	
	print("-- Calculating Probability of Success for combinations....")
	extFW_Router_webserverWDB_PS = calcPathProbOfSuccess(extFirewall_PS, webserverWDB_PS)
	webserver_intFW_Router_database_PS = calcPathProbOfSuccess(webserver_PS, intFirewall_PS, database_PS)
	extFW_Router_webserver_intFW_Router_database_PS = calcPathProbOfSuccess(extFirewall_PS, webserver_PS, intFirewall_PS, database_PS)
	vpnCreds_Router_PS = calcPathProbOfSuccess(VPN_PS, VPN_Creds_PS)
	vpnKeys_Router_PS = calcPathProbOfSuccess(VPN_PS, VPN_Keys_PS)
	
	# Determine if ps * A >= ca?
	'''
	 Take in:
	    -> A value
	    -> ca value
	 Precalculated from earlier step:
	    -> ps value
	 NEED: ~!~ Create it so that each design can have its own VA and CA value
	    -> Will require a default "blasting" chunk that will mass set defaults if something is not passed
	
	 Calculated via:    T/F = [(ps * A) >= ca]
	'''
	usingDefaults = 1       # Note: ~!~ Need to add check for passed AV and CA values for main function
	if usingDefaults != 0:
	    print("[*] Establishing default values for AV & CA")
	    VA = 20
	    CA = 7
	    if debugBit != 0:
	        print("-- Testing.... Check database only")
	        print("\t\tResult: " + str(checkAttackerChance(database_PS, VA, CA)))
	        print("-- Testing.... Check 3rd party application")
	        print("\t\tResult: " + str(checkAttackerChance(ThirdPartyApp_PS, VA, CA)))
	    print("-- Using defaults for probability calculcations")
	else:
	    print("[-] Error! Not using default values.....\n\tTHIS HAS NOT BEEN SETUP!!")
	    sys.exit()
	
	# Calculate the Probability of Attack (pa)
	'''
	 Note: This calculation requires a T/F check first! (Done in the step above)
	
	 Calculated via:    pa = 1 - exp(-[alpha] * ([ps] * [A] - [ca]))
	'''
	alpha = 1
	print("[*] Calculating the Probability of Attack values for all scenarios...")
	if checkAttackerChance(database_PS, VA, CA):
	    if debugBit != 0:
	        print("-- Value of Probability of Attack: " + str(calcProbOfAttack(alpha, database_PS, VA, CA)))
	    database_PA = calcProbOfAttack(alpha, database_PS, VA, CA)
	else:
	    database_PA = 0
	if checkAttackerChance(webserverWDB_PS, VA, CA):
	    webserverWDB_PA = calcProbOfAttack(alpha, webserverWDB_PS, VA, CA)
	else:
	    webserverWDB_PA = 0
	if checkAttackerChance(webserver_PS, VA, CA):
	    webserver_PA = calcProbOfAttack(alpha, webserver_PS, VA, CA)
	else:
	    webserver_PA = 0
	if checkAttackerChance(extFirewall_PS, VA, CA):
	    extFirewall_PA = calcProbOfAttack(alpha, extFirewall_PS, VA, CA)
	else:
	    extFirewall_PA = 0
	if checkAttackerChance(intFirewall_PS, VA, CA):
	    intFirewall_PA = calcProbOfAttack(alpha, intFirewall_PS, VA, CA)
	else:
	    intFirewall_PA = 0
	if checkAttackerChance(ThirdPartyApp_PS, VA, CA):
	    ThirdPartyApp_PA = calcProbOfAttack(alpha, ThirdPartyApp_PS, VA, CA)
	else:
	    ThirdPartyApp_PA = 0
	if checkAttackerChance(VPN_PS, VA, CA):
	    VPN_PA = calcProbOfAttack(alpha, VPN_PA, VA, CA)
	else:
	    VPN_PA = 0
	if checkAttackerChance(VPN_Creds_PS, VA, CA):
	    VPN_Creds_PA = calcProbOfAttack(alpha, VPN_Creds_PS, VA, CA)
	else:
	    VPN_Creds_PA = 0
	if checkAttackerChance(VPN_Keys_PS, VA, CA):
	    VPN_Keys_PA = calcProbOfAttack(alpha, VPN_Keys_PS, VA, CA)
	else:
	    VPN_Keys_PA = 0
	if checkAttackerChance(extFW_Router_webserverWDB_PS, VA, CA):
	    extFW_Router_webserverWDB_PA = calcProbOfAttack(alpha, extFW_Router_webserverWDB_PS, VA, CA)
	else:
	    extFW_Router_webserverWDB_PA = 0
	if checkAttackerChance(webserver_intFW_Router_database_PS, VA, CA):
	    webserver_intFW_Router_database_PA = calcProbOfAttack(alpha, webserver_intFW_Router_database_PS, VA, CA)
	else:
	    webserver_intFW_Router_database_PA = 0
	if checkAttackerChance(extFW_Router_webserver_intFW_Router_database_PS, VA, CA):
	    extFW_Router_webserver_intFW_Router_database_PA = calcProbOfAttack(alpha, extFW_Router_webserver_intFW_Router_database_PS, VA, CA)
	else:
	    extFW_Router_webserver_intFW_Router_database_PA = 0
	if checkAttackerChance(vpnCreds_Router_PS, VA, CA):
	    vpnCreds_Router_PA = calcProbOfAttack(alpha, vpnCreds_Router_PS, VA, CA)
	else:
	    vpnCreds_Router_PA = 0
	if checkAttackerChance(vpnKeys_Router_PS, VA, CA):
	    vpnKeys_Router_PA = calcProbOfAttack(alpha, vpnKeys_Router_PS, VA, CA)
	else:
	    vpnKeys_Router_PA = 0
	
	# Calculate the Security Risk (SR)
	'''
	 Calculated via:    pa * ps * impact
	
	 NEED: ~!~ Create it so that each design can have its own Impact value
	'''
	impact = 11.7
	print("[*[ Calculating the Security Risk values for all scenarios....")
	database_SR = calcSecurityRisk(database_PA, database_PS, impact)
	webserverWDB_SR = calcSecurityRisk(webserverWDB_PA, webserverWDB_PS, impact)
	webserver_SR = calcSecurityRisk(webserver_PA, webserver_PS, impact)
	extFirewall_SR = calcSecurityRisk(extFirewall_PA, extFirewall_PS, impact)
	intFirewall_SR = calcSecurityRisk(intFirewall_PA, intFirewall_PS, impact)
	ThirdPartyApp_SR = calcSecurityRisk(ThirdPartyApp_PA, ThirdPartyApp_PS, impact)
	VPN_SR = calcSecurityRisk(VPN_PA, VPN_PS, impact)
	VPN_Creds_SR = calcSecurityRisk(VPN_Creds_PA, VPN_Creds_PS, impact)
	VPN_Keys_SR = calcSecurityRisk(VPN_Keys_PA, VPN_Keys_PS, impact)
	extFW_Router_webserverWDB_SR = calcSecurityRisk(extFW_Router_webserverWDB_PA, extFW_Router_webserverWDB_PS, impact)
	webserver_intFW_Router_database_SR = calcSecurityRisk(webserver_intFW_Router_database_PA,webserver_intFW_Router_database_PS, impact)
	extFW_Router_webserver_intFW_Router_database_SR = calcSecurityRisk(extFW_Router_webserver_intFW_Router_database_PA, extFW_Router_webserver_intFW_Router_database_PS, impact)
	vpnCreds_Router_SR = calcSecurityRisk(vpnCreds_Router_PA, vpnCreds_Router_PS, impact)
	vpnKeys_Router_SR = calcSecurityRisk(vpnKeys_Router_PA, vpnKeys_Router_PS, impact)
	
	# Determine the individual cost (ci)
	'''
	 This is determined from outside data & research
	
	 Note: Currenty defaults are being used, but should be able to take in this information externally
	
	 NEED: ~!~ Way to automate this step for combining costs of path elements
	    -> Requires identification of elements that have PS, PA vs. just Costs
	'''
	print("[*] Generating default cost values for design parts")
	database_ci = 3000
	webserverWDB_ci = 13000
	webserver_ci = 10000
	extFirewall_ci = 8000
	intFirewall_ci = 12000
	ThirdPartyApp_ci = 20000
	VPN_ci = 22000
	Router_ci = 6000
	
	# Note: ~!~ Try to redo this adding in the router costs
	print("-- Calculating combined solution costs of parts...")
	extFW_Router_webserverWDB_ci = extFirewall_ci + webserverWDB_ci
	webserver_intFW_Router_database_ci = webserver_ci + intFirewall_ci + database_ci
	extFW_Router_webserver_intFW_Router_database_ci = extFirewall_ci + webserver_ci + intFirewall_ci
	vpnCreds_Router_ci = 18000
	vpnKeys_Router_ci = 21000
	
	# Calculate the Aggregate SR for combined solutions
	'''
	 Overall Attack Tree aggregation of combined solutions for security risk calculation
	'''
	print("[*] Calculating aggregated Security Risk for various solutions....")
	extFW_vpnPath = extFW_Router_webserverWDB_SR + VPN_SR
	extFW_appPath = extFW_Router_webserverWDB_SR + ThirdPartyApp_SR
	extFW_appPath_vpnPath = extFW_Router_webserverWDB_SR + ThirdPartyApp_SR + VPN_SR
	intFW_vpnPath = webserver_intFW_Router_database_SR + VPN_SR
	intFW_appPath = webserver_intFW_Router_database_SR + ThirdPartyApp_SR
	intFW_appPath_vpnPath = webserver_intFW_Router_database_SR + ThirdPartyApp_SR + VPN_SR
	appPath_vpnPath = ThirdPartyApp_SR + vpnCreds_Router_SR
	fullFW_vpnPath = extFW_Router_webserver_intFW_Router_database_SR + vpnCreds_Router_SR
	fullFW_appPath = extFW_Router_webserver_intFW_Router_database_SR + ThirdPartyApp_SR
	fullFW_appPath_vpnPath = extFW_Router_webserver_intFW_Router_database_SR + ThirdPartyApp_SR + vpnCreds_Router_SR
	
	# Calculcate the Cost (combined c values)
	'''
	 This is determined from outside data & research
	
	 Note: Currently defaults are being used, but should be able to take in this information externally
	'''
	# Note: These values can be brouth down to 7 & 2.45
	print("[*] Generating default maintenance and operation costs")
	cost_maintenance = 70000
	cost_operation = 2450
	
	# Calculcate the Total Cost (Cost + SR) for each design
	'''
	 Calculate the total cost (Costs + Security Risks)
	    -> Two variations for this calculation
	        - 1) Cost of parts + Security Risk
	        - 2) Cost or parts + cost of operation + cost of maintenance + Security Risk
	 Note: Initial calculations are for only the five designs used for the SR paper
	    - 1) Webserver with Database
	    - 2) External Firewall + Router + Webserver with Database
	    - 3) Webserver + Internal Firewall + Router + Database
	    - 4) External Firewall + Router + Webserver + Internal Firewall + Router + Database
	    - 5) VPN Solution
	
	 Nota Bene: There is a default scale value that is used to re-scale the SR value to a range that fits the costs of a given design
	'''
	# This scale amount represents a dollar amount (e.g. $1000)
	scaleAmount = 1000
	# NEED: ~!~ Create a total cost calculation funcation
	print("[*] Calculating simple total cost for scenarios.... Cost or parts + Security Risks")
	webserverWDB_Cost = Router_ci + webserverWDB_ci
	webserverWDB_TC = webserverWDB_Cost + (webserverWDB_SR * scaleAmount)
	extFW_Router_webserverWDB_Cost = webserverWDB_ci + extFirewall_ci + Router_ci
	extFW_Router_webserverWDB_TC = extFW_Router_webserverWDB_Cost + (extFW_Router_webserverWDB_SR * scaleAmount)
	webserver_intFW_Router_database_Cost = webserver_ci + intFirewall_ci + Router_ci + database_ci
	webserver_intFW_Router_database_TC = webserver_intFW_Router_database_Cost + (webserver_intFW_Router_database_SR * scaleAmount)
	extFW_Router_webserver_intFW_Router_database_Cost = extFirewall_ci + Router_ci + webserver_ci + intFirewall_ci + Router_ci + database_ci
	extFW_Router_webserver_intFW_Router_database_TC = extFW_Router_webserver_intFW_Router_database_Cost + (extFW_Router_webserver_intFW_Router_database_SR * scaleAmount)
	VPN_Cost = VPN_ci + Router_ci + database_ci
	VPN_TC = VPN_Cost + (VPN_SR * scaleAmount)
	print("-- Redoing calculations, including maintenance and operational costs....")
	webserverWDB_CostAdjusted = webserverWDB_Cost + cost_maintenance + cost_operation
	extFW_Router_webserverWDB_CostAdjusted = extFW_Router_webserverWDB_Cost + cost_maintenance + cost_operation
	webserver_intFW_Router_database_CostAdjusted = webserver_intFW_Router_database_Cost + cost_maintenance + cost_operation
	extFW_Router_webserver_intFW_Router_database_CostAdjusted = extFW_Router_webserver_intFW_Router_database_Cost + cost_maintenance + cost_operation
	VPN_CostAdjusted = VPN_Cost + cost_maintenance + cost_operation
	# Output the calculated information
	print("[*] Printing out the calculated information for total cost per design")
	print("\tDesign #\tTotal Cost")
	print("\tDesign #1:\t{0}".format(webserverWDB_TC))
	print("\tDesign #2:\t{0}".format(extFW_Router_webserverWDB_TC))
	print("\tDesign #3:\t{0}".format(webserver_intFW_Router_database_TC))
	print("\tDesign #4:\t{0}".format(extFW_Router_webserver_intFW_Router_database_TC))
	print("\tDesign #5:\t{0}".format(VPN_TC))
	print("-- Printing out the adjusted total cost per design")
	print("\tDesign #\tTotal Cost (Adjusted)")
	print("\tDesign #1\t{0}".format(calcTotalCost(webserverWDB_CostAdjusted, webserverWDB_SR, scaleAmount)))
	print("\tDesign #2\t{0}".format(calcTotalCost(extFW_Router_webserverWDB_CostAdjusted, extFW_Router_webserverWDB_SR, scaleAmount)))
	print("\tDesign #3\t{0}".format(calcTotalCost(webserver_intFW_Router_database_CostAdjusted, webserver_intFW_Router_database_SR, scaleAmount)))
	print("\tDesign #4\t{0}".format(calcTotalCost(extFW_Router_webserver_intFW_Router_database_CostAdjusted, extFW_Router_webserver_intFW_Router_database_SR, scaleAmount)))
	print("\tDesign #5\t{0}".format(calcTotalCost(VPN_CostAdjusted, VPN_SR, scaleAmount)))
	
	# End of Script for defulat design calculations
	print("[*] Completed calculation of design values uding defaults")

# Function to call all the testing functions
def testRuns():
	print("\nDefault Test:\n[*] Running through the default scenario...")
	defaultSecurityRiskCostRun()
	print("\nFunction Test:\n[*] Running through the new test scenario replicating default run")
	testRunCalc()
	print("\nUser Input Function Test:\n[*] Running test using user supplsed data")
	userRunCalc()

# Adding an 'extend' action provided into ArgumentParser
class ExtendAction(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        items = getattr(namespace, self.dest) or []
        items.extend(values)
        setattr(namespace, self.dest, items)

# Main function that runs the security risk script
#   Note: main MUST take in the following varaibles:
#       - item_PS
#       - item_alpha
#       - item_attackValue
#       - item_attackCost
#       - item_impact
#       - item_ci
#       - item_cost_maintenanc
#       - item_cost_operaiton
#       - item_scaleAmount
def main(item_PS, item_alpha, item_attackValue, item_attackCost, item_impact, item_ci, item_cost_maintenance, item_cost_operation, item_scaleAmount):
#def testing():
    if debugBit != 0:
        print("[*] ------------ Starting Security Risk Calculation Script ------------ [*]")

    # Performing test runs
    testRuns()

    if debugBit != 0:
        print("[*] Calling the pathCostCalc() using defaults and used suppled information")
    pathCostCalc(item_PS, item_alpha, item_attackValue, item_attackCost, item_impact, item_ci, item_cost_maintenance, item_cost_operation, item_scaleAmount)

    # Add in run for fullPathTotalCost() OR pathCostCalc() function calls
    if debugBit != 0:
        print("[*] ------------- Ending Security Risk Calculation Script ------------- [*]")

# Establish the Security Level (SL) for each design (e.g. ranking for each; worst to best)
'''
 Static mapping OR import of values from a user

 NEED: ~!~ Check for a large number of potential inputs for customizaiton of data being passed to this function
'''

'''
# Check for an argument sent to the script
if len(sys.argv) < 2:
    print("[-] Error: No argument was passed to the script!")
    print("-- Pass a specific Probability of Success (PS) to grab information for:\n\tsecurityRisk.py <Probability of Success>")
    print("-- [!] WARNING - Ensure that the PS value passed is on a 0.0 to 1.0 scale; script expects this")
    sys.exit()
else:
    print("[+] Argument(s) received")
    print("-- Number of arguments: " + str(len(sys.argv)) + " arguments")
    print("-- Argument List: " + str(sys.argv))
    print("[*] Setting the value of user input PS")
    userPS = float(sys.argv[1])
    print("-- userPS set to " + str(userPS))
'''

'''
Fixed the fucking lists problem.... now need to get arg.parser working for when a user supplied information to the function
'''

'''
# Setup for allowing import without immediate run of code
def main():
    testing()
'''

# Function that allows for this script to be imported without automatically running the main function
if __name__ == "__main__":
    print("[@] Testing Parser code [@]")
    # Creating the ArgumentParser object and passing a description for the script
    parser = argparse.ArgumentParser(description='Calculate the Security Risk of a given asset, path, or attack graph.')
    parser.register('action', 'extend', ExtendAction)
    # Adding informaiton about program arguments using 'add_argument()' method; states how to take strig on command line ad turn them into objects
        # Nota Bene:  DO NOT SET A VARIABLE TO TYPE LIST!!! Will end up with a list of lists, or each character being its own list
    parser.add_argument('-psList', nargs=1,  type=float, action='extend', required=True, help='Ordered list of Probabilit(y/ies) of Success for %(prog)s (Note: Order is important)')
    parser.add_argument('attackValue', type=float, nargs=1, help='Value of an asset, path, or network of elements to an Attacker')
    parser.add_argument('attackCost', type=float, nargs=1, help='Cost an Attacker pays when compromising/exploiting a given asset, path, or network of elements')
    parser.add_argument('--alpha', type=float, nargs=1, default=1, help='Alpha value used to scale the Security Risk calculation (default: %(default)s)')
    parser.add_argument('--impact', type=float, nargs=1, help='Impact of having a given asset, path, or netowrk of elements being compromised or exploited')
    parser.add_argument('-ciList', nargs=1, type=float, action='extend', help='Ordered list of Cost(s) of Implementation for %(prog)s (Note: Order is important)')
    parser.add_argument('--costMaintenance', type=int, nargs=1, help='Cost of maintenance of a given asset, path, or network of elements (cumulative)')
    parser.add_argument('--costOperation', type=int, nargs=1, help='Cost of operating a given asset, path, or network of elements (cumulative)')
    parser.add_argument('--scaleValue', type=int, nargs='?', default=1000, help='The scaling value used to determine the magnitude of the Security Risk & Total Cost (default: %(default)s)')

    args = parser.parse_args()

    # Setting defaults for user supplied information 
    print("-- [*] Setting up default variable values")
    item_attackValue = 20
    item_attackCost = 7
    item_impact = 11.7
    item_alpha = 1
    item_ci = 6000 + 13000
    item_cost_maintenance = 70000
    item_cost_operation = 2450
    item_scaleAmount = 1000
    print("-- [*] Setting the Probability of Success based on user input")
    item_PS = args.psList #[0.9, 0.5] #[0.9, 0.5] #args.psList #userPS    #0.9

    print("[@] COMPLETED PARSER CODE TEST [@]")

    main(item_PS, item_alpha, item_attackValue, item_attackCost, item_impact, [item_ci], item_cost_maintenance, item_cost_operation, item_scaleAmount)
