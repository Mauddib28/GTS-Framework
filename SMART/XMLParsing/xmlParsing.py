#!/usr/bin/python

#####
# The purpose of this function is to parse XML documents
#####

'''
 Import package list
 
 Author:        Paul A. Wortman
 Last Edit:     3/5/2021 
'''
#import xml.etree.ElementTree as etree   # Original etree package
from lxml import etree  # Importing from lxml for use the getpath() function 

'''
 Variable definitions
'''
debugBit = 0

'''
 Function definitions
'''
# Function for reading in an attack tree XML file
#   -> Input: XML file path
#   -> Output: ElementTree Object
def readAttackTree(filePath):
    return etree.parse(filePath)

# Function for iterating through attributes of a given XML node
def iterAttrib(attributeObject):
    for info, data in attributeObject.items():  # Note: items() for python 3, iteritems() for python 2
        print("-------\n\tInfo: " + info + "\n\tData: " + data)

# Function for returning all paths from tree root node to a specific node element
#   Note: if rootNode == endNode then will return full original tree path(??)
#   Note: 'endNode' must be a node object!!
def findPathToNode(rootNode, endNode):
    if rootNode == endNode:
        print("[!] No path necessary!! Mapping from same node to self....")
        return None
    else:
        return etree.ElementTree(rootNode).getpath(endNode)

# Function for returning all paths between a provided root node and searched node elements (if the element exists)
#   Note: Element string must be passed in XPath synatx (e.g. search query or single element variable name)
# Output: List of all paths between the root node and node containing the desired element
def findAllPaths(rootNode, elementString):
    # Code to ensure that the elementString starts with a relative path... This ensures that all existing paths can and will be found
    if not elementString.startswith('.//'):     # Check if the element string begins with a relative path
        # Clean off any potential starting characters that would cuase trouble
        elementString = elementString.lstrip('.').lstrip('/')
        # Change the elementString to have the relative starting path
        elementString = './/' + elementString
    else:
        # Do not change a thing
        pass
    if len(rootNode.findall(elementString)) == 0:
        print("[-] No nodes of element {0} were found".format(elementString))
        return None
    else:
        pathList = []
        # Note: if only a simple string is given, then it will ONLY search immediate children of the rootNode
        nodeList = rootNode.findall(elementString)  # Due to haste of code being put together, should use relative path for FULL tree coverage
        for node in nodeList:
            pathList.append(findPathToNode(rootNode, node))
        return pathList

# Function for returning all the paths to each leaf in a given attack tree (starting from a root node)
def findLeafs(rootNode):
    # NEED: Determine that the varaible passed is ACTUALLY a rootNode (e.g. element)
    leafList = []
    # Moving forward, sure that we are working with a ROOT node
    for element in rootNode.iter('subNodes'):   # Only doing an interation of the 'subNodes' tag elements b/c we are not treating 'vulnerabilities' tags as leafe elements.  This is because they are seen as PROPERTIES of the leaf 'subNodes'
        # Check to see if the current element has 'subNodes' children or not
        if element.find('subNodes') is None:    # Using find() because this would return the first element with that tag
            if debugBit != 0:
                print("Found a leaf!\n\tNode Tag: " + element.tag + "\n\tItems: " + str(list(element)))
            leafList.append(findPathToNode(rootNode, element))
    return leafList

# Function for collecting all 'vulnerabilities' tag 'name' attributes of a given node element
def grabNodeCVEs(elementNode):
    cves = []
    vulnList = elementNode.findall('vulnerabilities')
    for vuln in vulnList:
        cves.append(vuln.get('name'))
    return cves

# Function for recursively grabbing CVE (e.g. 'name') information   [Good recursive concept]    ~!~ DO NOT USE ~!~
# Nota Bene: Error where the call to grabNodeCVEs() will not output the information.... need to find a better way
def cveDive(node):
    if node.tag == 'rootNode':      # We have reached the rootNode of the attack graph
        grabNodeCVEs(node)
    else:                           # Grab current node CVEs and then go up to the parent node
        grabNodeCVEs(node)
        cvdDive(node.getparent())

'''
# Function for producing CVE list from ONLY a root Node [Special case]
def buildRootCVEList(treeObject):   # NOTE: Output must be of form [[[pathA],[pathB]]]; currently works with this weird triple nested list
    cveList = []
    for len(treeObject.findall('vulnerabilities')):
        cvePath = []
        cvePath.append(
'''

# Function for producing list of CVEs from provided XPath
# Input:
#   1) xpathList
#   2) tree object (raw read attack tree)
# Output:
#   List of CVEs
#   List of node names
def buildCVEList(xpathList, treeObject):        # WORKS!!
    cveList = []
    for path in xpathList:
        cvePath = []
        node = treeObject.find(path)
        while node.tag != 'rootNode':      # We have reached the rootNode of the attack graph
            cvePath.append(grabNodeCVEs(node))
            node = node.getparent()
        cvePath.append(grabNodeCVEs(node))
        cveList.append(cvePath)
    return cveList

# Function for getting the name of each element being examined for the passed paths
def buildNameList(xpathList, treeObject):
    nameList = []
    for path in xpathList:
        namePath = []
        node = treeObject.find(path)
        while node.tag != 'rootNode':
            #print("Node Info: \n\tTag: " + node.tag + "\n\tName: " + node.get('name'))
            namePath.append(node.get('name'))
            node = node.getparent()
        #print("List Node Info: \n\tTag: " + node.tag + "\n\tName: " + node.get('name'))
        namePath.append(node.get('name'))
        nameList.append(namePath)
    return nameList

# Function for processing through a given XML node and output a structure of data that can be passed to the security risk calculation function
'''
     Note: Input to the function below must be in a specific order
        - item_PS   [Gets calculated later, therefore need list of CVEs
        - item_alpha
        - item_attackValue
        - item_attackCost
        - item_impact
        - item_ci
        - item_cost_maintenance
        - item_cost_operation
        - item_scaleAmount
    How to determine node path/depth
        -> pass each child to a separate function?
            - start simple, grow recursively

    Plan:
        Start:  single node with one vuln
        Next:   single node with two vuln
        Next:   single node with four vuln
        Next:   1 root with 1 child
        Next:   1 root with 2 child (different path)
        Next:   1 root with 4 child (different path)
        Next:   1 root with 1 child with 1 gchild
    Use DDoS Vulns
 '''
'''
def dissectAttackTree(treeObject):
    # Definition local temp variables
    vulnCVEs = []   # Note: Will need to create place holder CVE for nodes that do not currently have a CVE value
    # Find the total number of vulnerabilities in the current attack tree
    totalVulns = len(treeObject.findall('//vulnerabilities'))
    totalSubNodes = len(treeObject.findall('//subNodes'))
        # Check to see how many vulnerabilities exist for the current node
        child_vulNum = len(child.findall('vulnerabilities'))    # Note: Not using './/' because that would return ALL vulnerabilities, not just the current child nodes'
        for vuln in child.findall('vulnerabilities'):   # Loops through all child vulnerability nodes of the current node
            # Check the vulnerability node for CVE information (Note: should be under the 'name' attribute)
'''

# Function for examining a single node in XML attack tree
#   Output: List of CVEs relating to this node
#   Note: This function ONLY search immediate children of the passed node
def singleNode(treeObject):
    cves = []
    root = treeObject.getroot() # Get the root node from tree object
    # Test that we are dealing with a single node
    if len(root) == 1:
        print("[+] There is a single child to the root node")
        for vuln in root[0].findall('vulnerabilities'):
            cves.append(vuln.get('name'))   # .get() function accesses an element's attributes
    return cves

# Function for examining a single node with multiple vulnerabilities in an XML attack tree
#   Nota Bene: MAKE SURE that the findall() terms are spelled correctly!!!
#   Note: This function ONLY search immediate children of the passed node
def grabTreeNodeCVEs(treeObject):   # Note: May want to create a version that takes in a single node and returns a CVE list
    cves = []
    root = treeObject.getroot()
    # Check that the node being examined has vulnerabilities, otherwise assume it is one node lower
    if not root.findall('vulnerabilities'):  # If findall() on root returns and empty list
        vulnList = root[0].findall('vulnerabilities')   # Get list of vulnerabilities from immediate/first child node
    else:
        vulnList = root.findall('vulnerabilities')
    # Create the CVEs list that will be returned
    for vuln in vulnList:
        cves.append(vuln.get('name'))
    return cves

# Function for getting the CVEs for a path of nodes (e.g. root + 1 child)
#   Nota Bene: findall() returns list, find() returns single element
def singleRootChild(treeObject):
    cves = []
    # Note: There should only be ONE rootNode
    root = treeObject.getroot()[0]  # Note: Using [0] since the AADL attack tree has a model definition root prior to the actual rootNode
    # Collect all attributes for each node in a given XPath
    pathList = findAllPaths(root, 'vulnerabilities')    # Will return a list of XPaths
    # Loop search found paths to create list of CVEs
    for path in pathList:
        cves.append(treeObject.find(path).attrib['name'])
    return cves

''' Now I can provide the different paths for given vulnerabiltiies within an attack tree
    Next: Review the CS 2018 paper, see what steps are required for calculating the security risk, and write any missing code 
    
    Create a List of Probabilities (P) for every path in the graph '''

# Function that allows for this script to be imported without automatically running the main funciton
if __name__ == "__main__":
    main()
