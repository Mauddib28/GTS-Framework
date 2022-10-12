#!/usr/bin/env python

###
# The purpose of this code is to read in an AADL model file and generate the corresponding attack tree model (as expected by SMART)
# 
# Author:       Paul A. Wortman
# Last Edit:    03/27/2022 
# Version:      2.1
#
# Notes/Additions:
#   [x] Teaching TAMSAT to deal with in-out (i.e. <->) ports
#   [ ] Teaching TAMSAT to read 'bus' elements in system implementations
#       -> Specifically with respect to linking hardware requirements (e.g. required access bus)
#       [ ] Teaching TAMSAT how to handle 'bus required' instances
#       [ ] Teach TAMSAT how to understand 'bus connections' wtihin implementations
#   [ ] Add vulnerabilities based on 'bus' elements tracked
#       -> Shows that specific elements of hardware / communication mediums that provide vulnerabilities
#   [x] Train TAMSAT to correctly interpret the smart home model
#   [x] Incorporate a proper mapping function for finding the different paths within a mapped area
#       -> Nota Bene: Extra points for being able to add constraints of Entry/Exit points (e.g. specialized input with no output)
#   [ ] Tolerance of a lack of 'flows' information within implementations
#
#   [x] SMART requires updates on how to interpret the new attack tree and idiot checks that the attack paths are being interpreted correctly
#       [ ] Add in connection medium specific constraints to the SMART code capabilites
#
#   Added fixing of TAMSAT interpreter to correctly understand 'in out'/'<->' connection details
#   Added translation of connection map '<->' elements into a Graph object
#   Extended Graph object to allow for generation of nodeMap from AADL model connection information
#   Added writing to output file for AADL XML from graph conversion
#   Added edgeMap and vertexMap tracking from the AADL model
#   Added vulnMap tracking from the AADL model
#   Added Skeleton logic for HARDWARE VULNERABILITY association and addition to the vulnerability map
#   Added recognition of the BreeZ hardware vulnerability
#   Added check for UART bus with ASPEED server
#
#   TODO:
#       [x] Create a 'bus' Database
#       [x] Teach TAMSAT how to export the Graph Object model
#       [x] Add ASPEED Hardware Vulnerability logic to TAMSAT
#       [ ] Reorganize the TAMSAT vulnerability logic
#           - Improve vulnerability allocation
#
# WE HAVE ACHEIVED SOUP-2-NUTS CAPABILITY..... V in S Day!
###

'''
Pseudo Code Sketch:
1) Read in AADL model file (line by line?)
--------------- Reading General Larger Model ----------------------
2) For each line check:
    i) does the line start with "package"?
        - If so, then we have started examining a model file
    ii) Does the line start with "public"?          <----- Nota Bene: There can be a "private line"; will eventually need to watch out for this
        - If so, then we look for additional checks....
    iii) Does the line start with "with"?
        - If so, then the following lines will be either:
            a) "<something>;"
                - A package that contains references used for componentns & other properties
            b) <emptyline> or '\n'
                - 1st time it is an empty line between "with" & additional packages
                - 2nd+ times it is an indicator that the "with" statement is concluding
    iv) Does the line start with a "keyword case" (e.g. bus, data, device, system)
        - If so, then we have entered the descriptiong of a component and/or property, THEREFORE we check:
            a) Does the line also contain the word "implementation"?
                - If so, then we are looking at the implementation of <thing> defined
            b) Does the line also contain the word "extends"?
                - If so, then we are looking @ an extension of a previously define <thing>
            c) Does the line ONLY have the key word + <thing>? (Else case)
                - If so, then we are looking @ the definition of the <thing>, thus we begin looking for new "keywords"
                    I) Does the line contain the word "features"?
                        - If so, then we are looking @ features of the <thing>
                    II) Does the line contain the word "flows"?
                        - If so, then we are looking @ entry & exit points as well as how information flaws
    v) Does the line start with "end" + <thing>?
        - If so, then we have finished the description of a component and/or property
    vi) Does the line start with "end" + model file name?
        - If so, then we have reached the end of the model file
--------------- Entries & Exists for Devices ---------------
3) Examine the contents of the "features" section (line by line?)
    i) Split the feature along the ':' character (e.g. <feature name>:<details>)
        a) Log the <feature node> as part of the parent <device>
        b) Parse the <details> information for <feature name>
            I) Is the feature an "in" or "out"?
            II) What is the type of <thing> being passed by the feature?
            III) what is the type of connection? (e.g. port)
        c) Log the <details> as part of the feature
4) Examine the contents of the "flows" section (line by line?)
    i) Split the flow along the ':' character (e.g. <flow name>:<details>)
        a) Log the <flow name> as part of the partent <device>
        b) Parse the <details> information for <flow name>
            I) Is the flow a "source" or "sink"?
            II) What is the <feature name> that the <flow name> is connected to?
        c) Log the <details> as part of the flow
5) Compare the details of <feature name> & <flow name> for <device>         <----- Use this to create definition of the device
    - NOTE: This should happen during examination of the "end" line
    - If this information matches, then have found the entry/exit point of the device
--------------- Entries & Exits for Systems ---------------                 <----- NOTE: should be similar to 'devices'
6) Same examination as a 'device', but will create a definition of the system based ontop of definitions for 'device' elements
--------------- For Implementation Interpretation ---------------           <----- This will help show/state how the <thing> features connect
7) Examine the contents of the "subcomponents" section (line by line?)
    i) Split the subcomponent along the ':' character (e.g. <subcomponent name>:<details>)
        a) Log the <subcomponent name> as part of the parent <system>
        b) Parse the <details> information for <subcomponentn name>
            I) Is the subcomponentn a device?               <----- NOTE: If not, then don't know what to do/is going on
            II) What is the implementation name of the <thing> that is a subcomponentn?
        c) Log the <details> as part of the subcomponent
8) Examine the contents of the "connections" section (line by line?)
    i) Split the connect along the ':' character (e.g. <connection name>:<details>)
        a) Log the <connection anem> as part of the parent <system>
        b) Parse the <details> information for <connection name>
            I) What is the type fo connection? (e.g. port)
            II) Use a loop to build the connection (e.g. pointA -> pointB....)      <---- enumerate to the end of the passed array
                A) Is the current element NOT a '->'
                    - If so, then add <element> to the "connection map" for the implementation
                B) Is the current element a '->'
                    - If so, then prepare a continuation to the "connection map"
                C) Did we reach the end of the parse array? (see a ';')
                    - If so, terminate the "connection map"
                D) Check that the end of the "connection map" is an <element>
                    - If NOT, throw an error & alert the user
        c) Log the <details> as part of the <connection name>
9) Examine the contents of the "flows" section (line by line?)
    i) Split the connection along the ':' character (e.g. <flow name>:<details>)
        a) Log the <flow name> as part of the parent <system>
        b) Parse the <details> information for <flow name>
            I) Is the flow a "source" or a "sink"?
            II) Use a loop to build the connection (e.g. flowPointA -> flowPointB....)
                A) Is the current element NOT a '->'
                    - If so, then add <element> to the "flow map" for the implementation
                B) Is the current element a '->'
                    - If so, then prepare a continuation to the "flow map"
                C) Did we reach the end of the parse array? (see a ';')
                    - If so, terminate the "flow map"
                D) Check that the end of the "flow map" is an <element>
                    - If NOT, throw an error & alert the user
        c) Log the <details> as part of the <system>

Nota Bene: The regular definition are the equivalent of high-level (black box) description of a 'device' or 'system', there 'implementation'
    definitions are the equivalent of a detailed connection & subcomponent mapping of a 'device' or 'system'
'''

'''
======================================================
    SKETCH FOR nodeMap AND edgeMap STRUCTURES
======================================================

------------------------------------------------------
EXAMPLES / SKETCHES OF JSON MAPS
------------------------------------------------------

nodeMap = {
    'server' : {
        'Ports' : {
            'SMB' : {
                'Data Type' : 'smb',
                'Port Direction' : 'in out',
                'Port Boolean' : True,
                'Event Boolean': True,
                'Data Boolean' : True
                'Entry Boolean': true/false,
                'Exit Boolean' : true/false
            },
            ( ... ... )
        }
    }
}

edgeMap = {
    edge_label_i : {            <---- NOTE: Use the AADL connection names (e.g. server_database_smb) as the edge labels
        'Nodes' : {
            'Start Node' : vertex_name,
            'End Node' : vertex_name
            },
        'Data Type' : data_type,
        'Bus Boolean' : true/false,
        'Bus Type' : bus_type,
        'Edge Direction' : in/out/in out,
        'Port Boolean' : true/false,
        'Entry Boolean': true/false,
        'Exit Boolean': true/false
    },
    ( ... ... )
}

------------------------------------------------------
STRUCTURE INFORMATION
------------------------------------------------------

    - nodeMap STRUCTURE -
nodeMap_name = {
    vertex_node_i :   {
        'Ports' :   {
            port_name_i : {
                'Data Boolean'  :   [ true / false ],
                'Data Type' :   port_data_type,
                'Port Boolean'  :   [ true / false ],
                'Event Boolean' :   [ true / false ],
                'Entry Boolean' :   [ true / false ],
                'Exit Boolean'  :   [ true / false ]
                },
            ( ... ... )
        }
    },
    ( ... ... )
}

    - edgeMap STRUCTURE -
edgeMap_name = {
    edge_label_i    :   {
        'Nodes' :   {
            'Start Node'    :   vertex_name,
            'End Node'      :   vertex_name
        },
        'Data Boolean'  :   [ true / false ],
        'Data Type'     :   data_type,
        'Bus Boolean'   :   [ true / false ],
        'Bus Type'      :   bus_type,
        'Port Boolean'  :   [ true / false ],
        'Edge Direction'    :   in/out/in out,
        'Entry Boolean' :   [ true / false ],
        'Exit Boolean'  :   [ true / false ]
    },
    ( ... ... )
}

'''

## Imports
import re           # Import for using regular expressions to search for whole words
import pprint       # Import for using pretty print to debug dictionary structure building
import json         # Import for using JSON with database, device, system, and implementation interaction
import collections  # Import for using OrderedDicts for creating attack graphs from model path information
import argparse     # Import for having import variable parsing
import os.path      # Import for checking existance of vulnerability database
from os import walk # Import for walking directory information to locate filename information; database identification
import fnmatch      # Import for pattern matching to files being looked up

## Variable Definitions
debugBit = 0
detailDebugBit = 0

# Global Variables
hardware_database="Database/vulnsDb.hardware.json"

## Class Definitions

# Definition of Graph Class
#   - A simple Python graph class, demonstrating the essential facts and functionalities of graphs
class Graph(object):

    # Class Initialization Function
    def __init__(self, graph_dict=None):
        """ initializes a graph object 
            If no dictionary or None is given, 
            an empty dictionary will be used
        """
        if graph_dict == None:
            graph_dict = {}
        self._graph_dict = graph_dict

    # Class Function for Returning a List of All Edges of a Vertice (i.e. Node)
    def edges(self, vertice):
        """ returns a list of all the edges of a vertice"""
        return self._graph_dict[vertice]
       
    # Class Function for Returning a Set of All Verticies within the Graph
    def all_vertices(self):
        """ returns the vertices of a graph as a set """
        return set(self._graph_dict.keys())

    # Class Function for Returning the Edges within the Graph
    def all_edges(self):
        """ returns the edges of a graph """
        return self.__generate_edges()

    # Class Function for Adding a Vertex (i.e. Node) to the Graph
    def add_vertex(self, vertex):
        """ If the vertex "vertex" is not in 
            self._graph_dict, a key "vertex" with an empty
            list as a value is added to the dictionary. 
            Otherwise nothing has to be done. 
        """
        if vertex not in self._graph_dict:
            self._graph_dict[vertex] = []

    # Class Function for Adding an Edge to the Graph
    def add_edge(self, edge):
        """ assumes that edge is of type set, tuple or list; 
            between two vertices can be multiple edges! 
        """
        edge = set(edge)
        vertex1, vertex2 = tuple(edge)
        for x, y in [(vertex1, vertex2), (vertex2, vertex1)]:
            # NOTE: Improving this logic prevents duplicates appearing in the later connectionGraph object  ~!~
            if x in self._graph_dict:
                if y not in self._graph_dict[x]:
                    self._graph_dict[x].append(y)
            else:
                self._graph_dict[x] = [y]

    # Class Function for Generating a List of all the Edges within the Graph
    def __generate_edges(self):
        """ A static method generating the edges of the 
            graph "graph". Edges are represented as sets 
            with one (a loop back to the vertex) or two 
            vertices 
        """
        edges = []
        for vertex in self._graph_dict:
            for neighbour in self._graph_dict[vertex]:
                if {neighbour, vertex} not in edges:
                    edges.append({vertex, neighbour})
        return edges
   
    # Class Function for Returning an Iterable Object of the Graph (???)
    def __iter__(self):
        self._iter_obj = iter(self._graph_dict)
        return self._iter_obj
    
    # Class Function for Iterating over the Verticies within the Graph (i.e. traversing nodes)
    def __next__(self):
        """ allows us to iterate over the vertices """
        return next(self._iter_obj)
    
    # Class Function for Returning a String of the Contents within the Graph
    def __str__(self):
        res = "vertices: "
        for k in self._graph_dict:
            res += str(k) + " "
        res += "\nedges: "
        for edge in self.__generate_edges():
            res += str(edge) + " "
        return res

    # Internal Class Function for Finding a Path between Two Nodes within the Graph
    def find_path(self, start_vertex, end_vertex, path=None):
        """ find a path from start_vertex to end_vertex 
            in graph """
        if path == None:
            path = []
        graph = self._graph_dict
        path = path + [start_vertex]
        if start_vertex == end_vertex:
            return path
        if start_vertex not in graph:
            return None
        for vertex in graph[start_vertex]:
            if vertex not in path:
                extended_path = self.find_path(vertex, 
                                               end_vertex, 
                                               path)
                if extended_path: 
                    return extended_path
        return None
    
    # Internal Class Function for Finding All Paths within the Graph 
    def find_all_paths(self, start_vertex, end_vertex, path=[]):
        """ find all paths from start_vertex to 
            end_vertex in graph """
        graph = self._graph_dict 
        path = path + [start_vertex]
        if start_vertex == end_vertex:
            return [path]
        if start_vertex not in graph:
            return []
        paths = []
        for vertex in graph[start_vertex]:
            if vertex not in path:
                extended_paths = self.find_all_paths(vertex, 
                                                     end_vertex, 
                                                     path)
                for p in extended_paths: 
                    paths.append(p)
        return paths

    # Internal Class Function for Pretty Printing the Contents of the Graph
    def pretty_print(self):
        # Print out information about the Graph contents
        print("[*] Graph contents information")
        print("\tVerticies of the Graph:\t{0}".format(self.all_vertices()))
        print("\tEdges of the Graph:\t{0}".format(self.all_edges()))

    # Function for Finding Depth of Nodes in Graph from Starting rootNode
    # Input:    rootNode of the Depth Mapping being performed using BFS technique
    #           - NOTE: rootNode is where in the Graph the Depth Mapping will occur
    # Output:   Dictionary/JSON object that contains the Node Type and Indent Level
    #   - Example:
    #           nodeMap[node] = {
    #                       "Node Type": "rootNode"||"subNodes",
    #                       "Indent Level": depth_tracker
    #                       }
    def find_depths_from_node(self, rootNode):
        # Create the visited_nodes, queue_nodes, and next_level_queue lists for Depth Tracking
        visited_nodes, queue_nodes, next_level_queue = [], [], []       # All lists are set to empty at the start
        # Create the queue_removal list for performing clean-up after each depth level is examined
        queue_removal = []
        # Create the nodeMap that will be returned by this function
        nodeMap = {}
        # Setup the depth_tracker variable
        depth_tracker = 0
        # Add the starting rootNode to the queue_nodes to prime the while loop
        queue_nodes.append(rootNode)
        # While there are still vertex points in the queue_nodes list, perform the following
        while queue_nodes:
            if detailDebugBit != 0:
                print("[?] Debugging the Depths Search\n\tvisited_nodes:\t\t\t{0}\n\tqueue_nodes:\t\t\t{1}\n\tnext_level_queue:\t\t{2}\n\tDepth Tracker:\t\t\t{3}".format(visited_nodes, queue_nodes, next_level_queue, depth_tracker))
                print("\tFor-loop through vertex points in queue_nodes")
            # Loop through each node within the queue_nodes array
            for vertex in queue_nodes:
                if detailDebugBit != 0:
                    print("\t\tInside the For-loop.... Looking at vertex [ {0} ]".format(vertex))
                # Check if the vertex is not already in visited_nodes
                if vertex not in visited_nodes:     # Have NOT visited this vertex before
                    # Add the vertex to list of visited_nodes
                    visited_nodes.append(vertex)
                    # Check if vertex has any neighbour_nodes
                    #   - TODO: Alter later to have more refined check
                    if vertex in self._graph_dict:          # Check that the vertex exists in the graph
                        # Iterate through each of the neighbour nodes to the vertex
                        for neighbour in self._graph_dict[vertex]:
                            # Check that the neighbour is NOT visited_nodes
                            if neighbour not in visited_nodes:
                                # Add each neighbour to the next_level_queue
                                next_level_queue.append(neighbour)
                else:                               # Have visited this vertex before
                    if debugBit != 0:
                        print("[*] Already visited node:\t{0}".format(vertex))
                # Remove the vertex from the queue_nodes list
                #queue_nodes.remove(vertex)         # NOTE: Do NOT do this... causing index errors meaning loops do not behave correctly (i.e. leaving For-loop before completed)
                # Add the vertex to queue_removal
                queue_removal.append(vertex)        # NOTE: This will be used within a SECOND For-loop for cleaning
            if detailDebugBit != 0:
                print("\tDone looping through the queue_nodes\n\t\tqueue_nodes:\t{0}\n\t\tqueue_removal:\t{1}".format(queue_nodes, queue_removal))
            ## Cleaning of the queue_nodes based on those present in the queue_removal list
            #   - NOTE: This space also doubles as when the nodeMap can be updated
            for node in queue_removal:
                if detailDebugBit != 0:
                    print("\t\tGoing to remove [ {0} ] from queue_nodes\n\t\t\tqueue_nodes:\t{1}".format(node, queue_nodes))
                # Add in the node information to the nodeMap
                ## Check to see if we are adding the rootNode or a normal subNode
                if node == rootNode:            # For the rootNode of the Grpah (i.e. AoI)
                    nodeMap[node] = {
                            "Node Type": "rootNode",
                            "Indent Level": depth_tracker
                            }
                else:                           # For all other nodes within the Graph
                    nodeMap[node] = {
                            "Node Type": "subNodes",
                            "Indent Level": depth_tracker
                            }
                # Remove the seen node from the queue_nodes
                queue_nodes.remove(node)
            # Clear the queue_removal to prepare for the next depth of the Graph object
            queue_removal.clear()
            # Check that all of the current queue_nodes has been exhausted; ready for next_level_queue
            if not queue_nodes:
                if detailDebugBit != 0:
                    print("\tCompleted looking at the queue_nodes....\n\t\tDepth Tracker changning from {0} to {1}\n\t\tProof of Empty:\t{2}".format(depth_tracker, depth_tracker + 1, queue_nodes))
                # Increase the depth_tracker variable by 1; to signify decending one level in the Graph connections
                depth_tracker += 1          # Depth Tracker gets updated correctly (once queue_nodes is empty)
                if debugBit != 0:
                    print("\tDepth Tracker Update:\t{0}".format(depth_tracker))
            if detailDebugBit != 0:
                print("\tChecking if the next_level_queue is empty")
            # Check if the next_level_queue is empty
            if not next_level_queue:        # The next_level_queue is empty
                if debugBit != 0:
                    print("[*] There are no more depth levels to explore in this graph\n\tProof of next_level_queue:\t{0}".format(next_level_queue))
            else:                           # The next_level_queue is NOT empty
                # Copy the contents of next_level_queue into the (expectedly empty) queue_nodes
                #   - NOTE: Making sure not to use a shallow copy to maintain information after the upcoming clear()
                queue_nodes = next_level_queue[:]           # Using list slicing to copy the contents of the list
                # Clear the contents of the next_level_queue; ready for next pass of the while-loop
                next_level_queue.clear()
                #print("[?] Checking the value of the two queue lists:\n\tqueue_nodes:\t\t{0}\n\tnext_level_queue:\t{1}".format(queue_nodes, next_level_queue))
            if detailDebugBit != 0:
                print("\tChecking.... About to restart the while-loop\n\t\tqueue_nodes:\t\t{0}\n\t\tnext_level_queue:\t{1}".format(queue_nodes, next_level_queue))
        # Done tracking depths
        if detailDebugBit != 0:
            print("[?] Final Check of Variables\n\tvisited_nodes:\t{0}\n\tqueue_nodes:\t{1}\n\tnext_level_queue:\t{2}\n\tDepth Tracker:\t{3}".format(visited_nodes, queue_nodes, next_level_queue, depth_tracker))
        return nodeMap

    # Function for Output of a Vulnerabilities Map relating to a given Vertex Map
    #   - TODO: Find a cleaner way to check for all vulnerabilities types from both the vertex and its associated bus_mediums
    #   - NOTE: Current work-around is to create a list of 'ignored_vulnreabilities' to prevent purposely ignored vulns from being added to the vertex element's vulnerability list
    #           -> EX: MySQL only adding vulnerabilities that are related to a SPECIFIC VERSION of MySQL
    #       -> Nota Bene: This function works properly..... Somewhere ELSE in the code is causing ALL VULNERABILITIES to be added to the model (?)
    #           => HAS TO BE AN ARTIFACT FROM VERSION 1.0/1.5 OF TAMSAT
    #           - It is.... Everything works fine with the newer Python Object Model
    def create_and_output_vulnerabilities_map(self, vertex_map, vulnerability_database, vulnerabilities_map_filename, entry_exit_map):
        # Create the vulnerability map dictionary
        vulnMap = {}
        # Read in the hardware database that contains known vulnerabilities that REQUIRE/CAUSE a new Entry / Exit point (i.e. Access-way)
        hardware_access_vulns = readJSON(hardware_database)
        # TODO: Add in constraint check for version information
        #   - This should come from a check against the element node description (e.g. detail information that either comes from a provided database or from the AADL model information)
        model_constraints = {}
        # For each vertex in the vertex_map find the associated vulnerabilities and place them into the vulnMap
        for vertex in vertex_map:
            if detailDebugBit != 0:     # ~!~
                print("[?] Vertex [ {0} ] from Vertex Map".format(vertex))
                print("[?] Vertex contents:\n\tBus Medium\t-\t{0}".format(vertex_map[vertex]['Bus']))
            # Variable used to track vulnerabilities related to a given vertex
            vertex_vuln_list = []
            # Variable used to track vulnerabilities that should be ignored to a given vertex; e.g. vulnerabilities that are known mitigated OR unrelated
            vertex_ignore_vuln_list = []
            # Variable used to track vulnerabilities related to a given vertex's bus mediums
            vertex_bus_vuln_list = []           # Maybe use this??? Over complicating this?
            # Search for and add vulnerabilities based on the vertex / vulnerable element
            for vulnerable_element in vulnerability_database:
                matched_element = re.search(vertex, vulnerable_element, re.IGNORECASE)      # Search to see if the vertex name exists in the vulnerabilities dictionary
                if matched_element:     # A match was found
                    # Check that the beginning of the matched_element is also the start for the JSON vulnerability element
                    start_keyword = "^" + vertex
                    match_start = re.search(start_keyword, vulnerable_element, re.IGNORECASE)
                    if match_start:     # The match is at the beginnig of the string (e.g. regex ^)
                        # Since the vulnerale_element matches, cycle through the vulnerabilities and add the "appropriate ones"
                        #   - TODO: Add in constrinats / filtering to only add specific sets of vulnerabilities
                        for vulnerability in vulnerability_database[vulnerable_element]["Vulnerability List"]:
                            if vulnerability in vertex_vuln_list:
                                print("[!] This entry already exists")
                            elif vulnerability in vertex_ignore_vuln_list:
                                print("[!] This entry needs to be ignored [ {0} ]".format(vulnerability))
                            else:       # The vulnerability does not exist within the vulnreability list, THEREFORE we must add it
                                if debugBit != 0:
                                    print("[!] This entry did NOT exist!... Adding it\n\tVuln [ {0} ]\t\t-\t\tElem [ {1} ]".format(vulnerability, vertex))
                                if detailDebugBit != 0:         # ~!~
                                    print("\tChecking vulnerability description of [ {0} ]:\t\t[ {1} ]".format(vulnerability, vulnerability_database[vulnerable_element]["Vulnerability List"][vulnerability]))
                                # TODO: Add in method for comparing the known version of a given device element (e.g. MySQL) by:
                                #       (i)     Passing the verison information within the device / vertex map structure
                                #       (ii)    Do a simple word/text search in the vulnerability description for a match (e.g. "7.2" in the description details)
                                if vertex == 'mysql_database' or vertex == 'mysql':             # Check to see if dealing with a MySQL database         |       NOTE: Currently hardcoding in these checks, but TODO passing the information (i)
                                    if detailDebugBit != 0:
                                        print("\tIdentified MySQL from vertex [ {0} ]".format(vertex))
                                    version_check = "8.0.19"                            # NOTE: This is a version chosen AT RANDOM and is used as a PoC for a mitigation-decision logic for only choosing specific vulnerabilities out of a longer list
                                    vulnerability_description = vulnerability_database[vulnerable_element]["Vulnerability List"][vulnerability] 
                                    if version_check in vulnerability_description:
                                        if debugBit != 0:
                                            print("\t\tFound a match in the vulnerability description of [ {0} ]\n\t\t\tVersion Check:\t\t[ {1} ]\n\t\t\tDescription:\t\t[ {2} ]".format(vulnerability, version_check, vulnerability_description))
                                        # ONLY add the vulnerability if the version_check was found in the vulerability_description
                                        vertex_vuln_list.append(vulnerability)              # Add the vulnerability to the vulnerability list for the given vertex element
                                    else:
                                        if debugBit != 0:
                                            print("\t\tAdding vulnerability [ {0} ] to the vertex [ {1} ] ignore vulnerability list".format(vulnerability, vertex))
                                        # Add the vulnerability to the vertex_ignore_vuln_list to prevent its addition later in the bus_medium vulnerability check logic
                                        vertex_ignore_vuln_list.append(vulnerability)
                                else:
                                    # Add each vulnerability to the list of vulnerabilities for this given vertex
                                    vertex_vuln_list.append(vulnerability)              # TODO: Check that the vulnerability has not ALREADY been added to the vertex's vulnerability list; (MAYBE do in the HARDWARE section?)
                            # NOTE: TODO: Fix this so that the description information gets passed along as well
                            #print("[?] TESTING Vulnerability List and Vulnerability Ignore List\n\tVulnerability List:\t\t{0}\n\tVulnerability Ignore List:\t\t{1}".format(vertex_vuln_list, vertex_ignore_vuln_list))
                            # ^ The vertex_vuln_list and vertex_ignore_vuln_list work perfectly.... BUT the IGNORED vulnerabilities are still getting added.... WTF?
            #something.update(vertex_vuln_list)
            # Variable used to track bus mediums related to a given vertex
            bus_medium_list = []
            # Create a list of Bus Medium elements related to the current vertex element
            for bus_medium in vertex_map[vertex]['Bus']:
                print("[!]\tBus Medium Element:\t{0}\n\tVertex it belongs to:\t{1}".format(bus_medium, vertex))
                bus_medium_list.append(bus_medium)
            # Decision logic for determining potential existence of HARDWARE vulnerabilities based on VERTEX and BUS information coupling
            #   - Ex: BreeZ protocol medium + Sensor device
            #   - NOTE: At the first interation of this decision logic, the assumptions are VERY SPECIFIC, but SHOULD BE EXPANDED to perform checks on BOTH SIDES of the BUS MEDIUM connection
            #       -> Should be able to leverage the edgeMap for this, since it INCLUDES and START and END vertex which can BOTH be associated to the given BUS MEDIUM vulnerabilities
            # TODO: Add capability to add Entry / Exit points to the Entry_Exit_map based on HARDWARE VULNERABILITIES
            #   -> NOTE: Will require IDENTIFICATION OF HARDWARE ONLY VULNERABILITIES
            #   - Could do this as a comparison against a list of KNOWN HARDWARE VULNERABILITIES
            #       => We could expect this separation as CVE database is developed and THEREFORE begin with the set of vulnerabilities that we picked from for the GTS paper
            #       - TODO: Create a database of known Hardware Vulnerabilities to compare to
            # Cycle through existing bus_mediums and check them against the current vertex element to see if vulnerabilities should be added to the 'vertex_vuln_list'
            for bus_medium in bus_medium_list:
                # Check for potential vulnerabilities due to Zigbee Protocol
                if bus_medium == 'zig_bus' or bus_medium == 'zigbee':
                    print("[!] Comparing for Zigbee Protocol Vulnerabilities")
                    # Search for Zigbee related vulnerabilities
                elif bus_medium == 'eth_bus' or bus_medium == 'ethernet_bus':
                    print("[!] Comparing for Ethernet Protocol Vulnerabilities")
                    # Search for Ethernet related vulnerabilities
                elif bus_medium == 'uart_bus' or bus_medium == 'uart':
                    print("[!] Comparing for UART Protocol Vulnerabilities")
                    # Search for UART related vulnerabilities
                    for vulnerable_element in vulnerability_database:           # Search through the entire vulnerability database by one vulnerable element (e.g. vertex OR bus medium type) at a time
                        # Check to see if the bus_medium name exists in the vulnerabilities dictionary
                        matched_bus_element = re.search(bus_medium, vulnerable_element, re.IGNORECASE)
                        if matched_bus_element:     # A matching bus element was found
                            # Check that the beginning of the matched_bus_element is also the start for the JSON vulnerability element
                            bus_start_keyword = "^" + bus_medium
                            match_bus_start = re.search(bus_start_keyword, vulnerable_element, re.IGNORECASE)
                            if match_bus_start:     # The beginning of the string was found to match the beginning of the string (e.g. regex ^)
                                # Since the vulnerable_element matches, cycle through the vulnerabilities and add the "appropriate ones"
                                #   - TODO: Add in constraints / filtering to only add specific sets of vulnerabilities
                                for vulnerability in vulnerability_database[vulnerable_element]["Vulnerability List"]:
                                    print("[!!] On Vulnerability\t[ {0} ]\n\tBus:\t{1}\n\tVertex:\t{2}".format(vulnerability, bus_medium, vertex))
                                    if vulnerability in vertex_vuln_list:
                                        print("[!] This entry already exists for HARDWARE BUS")
                                        # NOTE: This helps prevent addition of multiple of the same vulnerability from a BreeZ device and BreeZ bus medium
                                    else:       # the vulnerability does not exist within the vulnerability list, THEREFORE we must add it
                                        print("[!] This entry did NOT exist!... Adding it for HARDWARE BUS?\n\tVuln [ {0} ]\t\t-\t\tElem [ {1} ]".format(vulnerability, vertex))
                                        # Add each vulnerability to the list of vulnerabilities for this given vertex element (EVEN THOUGH ths vulnerability is coming from the bus element being used?)
                                        vertex_vuln_list.append(vulnerability)
                                        # Perform hardware_access_vulns checks to see if the given vulnerability requires addition of an Entry / Exit point
                                        #   - NOTE: At this point in time was are just looking for "Access-way"
                                        for hardware_vuln in hardware_access_vulns["Hardware Vulnerabilities"]:
                                            print("[?!?] Looking at HW Vuln [ {0} ]\n\tCompare to Vuln [ {1} ]".format(hardware_vuln, vulnerability))
                                            # Setting default variable setting; used to adding in entries to the Entry / Exit map
                                            #   -> NOTE: This comes from other code in TAMSAT that is defaulting to this value
                                            vertex_node = "Access-way"
                                            if vulnerability == hardware_vuln:          # Check if the current vulnerability is the same as a known hardware_access_vulns entry
                                                print("[!!!!] The vulnerabilities MATCH!\n\tVuln:\t[ {0} ]\n\tHW Vuln:\t[ {1} ]".format(vulnerability, hardware_vuln))
                                            ## This is the code that adds the given HARDWARE VULNERABILITY to the Entry / Exit map
                                            #       - Should happen AFTER the decision logic determines that the current vulnerability is a special `hardware_access_vulns' vulnerability
                                            # Add the new HARDWARE VULNERABLE ELEMENT to the Entry / Exit map
                                            if vertex_node not in entry_exit_map:
                                                # Fix the missing Entry/Exit/Access-way issue
                                                entry_exit_map_entry = {
                                                        vertex_node : {}
                                                    }
                                                entry_exit_map.update(entry_exit_map_entry)
                                            # Add the other connecting node to the corresponding entry_exit_map category (i.e. Entry, Exit, Access-way)
                                            # NOTE: The below should only happen in SPECIFIC scenarios... (e.g. ASPEED server)
                                            if vertex_node == 'aspeed_server':
	                                            neighbour_entry = {
	                                                    vertex : {
	                                                        "Leaf Node" : None             # NOTE: Setting a DEFAULT VALUE of NONE for the Leaf Node; TODO: Perform an update of this information down the road
	                                                        }
	                                                    }
	                                            entry_exit_map[vertex_node].update(neighbour_entry)
                                    # NOTE: TODO - Fix this so that the description information gets passed along as well
                                    #   -> Potentially use this information as the constraint methodology for TAMSAT decision logic
                elif bus_medium == 'breez_bus' or bus_medium == 'breez':
                    print("[!] Comparing for BreeZ Protocol Vulnerabilities\n\tSearching for a {0} vulnerability list in the vulnerability database".format(bus_medium))
                    # Search for BreeZ related vulnerabilities      | NOTE: Using the logic below the BreeZ vulnerability gets added to BOTH the server and sensor devices (since both communicate over BreeZ protocol)
                    for vulnerable_element in vulnerability_database:           # Search through the entire vulnerability database by one vulnerable element (e.g. vertex OR bus medium type) at a time
                        # Check to see if the bus_medium name exists in the vulnerabilities dictionary
                        matched_bus_element = re.search(bus_medium, vulnerable_element, re.IGNORECASE)
                        if matched_bus_element:     # A matching bus element was found
                            # Check that the beginning of the matched_bus_element is also the start for the JSON vulnerability element
                            bus_start_keyword = "^" + bus_medium
                            match_bus_start = re.search(bus_start_keyword, vulnerable_element, re.IGNORECASE)
                            if match_bus_start:     # The beginning of the string was found to match the beginning of the string (e.g. regex ^)
                                # Since the vulnerable_element matches, cycle through the vulnerabilities and add the "appropriate ones"
                                #   - TODO: Add in constraints / filtering to only add specific sets of vulnerabilities
                                for vulnerability in vulnerability_database[vulnerable_element]["Vulnerability List"]:
                                    print("[!!] On Vulnerability\t[ {0} ]\n\tBus:\t{1}\n\tVertex:\t{2}".format(vulnerability, bus_medium, vertex))
                                    if vulnerability in vertex_vuln_list:
                                        print("[!] This entry already exists for HARDWARE BUS")
                                        # NOTE: This helps prevent addition of multiple of the same vulnerability from a BreeZ device and BreeZ bus medium
                                    else:       # the vulnerability does not exist within the vulnerability list, THEREFORE we must add it
                                        print("[!] This entry did NOT exist!... Adding it for HARDWARE BUS?\n\tVuln [ {0} ]\t\t-\t\tElem [ {1} ]".format(vulnerability, vertex))
                                        # Add each vulnerability to the list of vulnerabilities for this given vertex element (EVEN THOUGH ths vulnerability is coming from the bus element being used?)
                                        vertex_vuln_list.append(vulnerability)              # TODO: Need to fix this BECAUSE this line of code is adding the ENTIRE 'mysql_database' vulnerability list to the attack tree...
                                        # Perform hardware_access_vulns checks to see if the given vulnerability requires addition of an Entry / Exit point
                                        #   - NOTE: At this point in time was are just looking for "Access-way"
                                        for hardware_vuln in hardware_access_vulns["Hardware Vulnerabilities"]:
                                            print("[?!?] Looking at HW Vuln [ {0} ]\n\tCompare to Vuln [ {1} ]".format(hardware_vuln, vulnerability))
                                            # Setting default variable setting; used to adding in entries to the Entry / Exit map
                                            #   -> NOTE: This comes from other code in TAMSAT that is defaulting to this value
                                            vertex_node = "Access-way"
                                            if vulnerability == hardware_vuln:          # Check if the current vulnerability is the same as a known hardware_access_vulns entry
                                                print("[!!!!] The vulnerabilities MATCH!\n\tVuln:\t[ {0} ]\n\tHW Vuln:\t[ {1} ]".format(vulnerability, hardware_vuln))
                                            ## This is the code that adds the given HARDWARE VULNERABILITY to the Entry / Exit map
                                            #       - Should happen AFTER the decision logic determines that the current vulnerability is a special `hardware_access_vulns' vulnerability
                                            # Add the new HARDWARE VULNERABLE ELEMENT to the Entry / Exit map
                                            if vertex_node not in entry_exit_map:
                                                # Fix the missing Entry/Exit/Access-way issue
                                                entry_exit_map_entry = {
                                                        vertex_node : {}
                                                    }
                                                entry_exit_map.update(entry_exit_map_entry)
                                            # Add the other connecting node to the corresponding entry_exit_map category (i.e. Entry, Exit, Access-way)
                                            neighbour_entry = {
                                                    vertex : {
                                                        "Leaf Node" : None             # NOTE: Setting a DEFAULT VALUE of NONE for the Leaf Node; TODO: Perform an update of this information down the road
                                                        }
                                                    }
                                            entry_exit_map[vertex_node].update(neighbour_entry)
                                    # NOTE: TODO - Fix this so that the description information gets passed along as well
                                    #   -> Potentially use this information as the constraint methodology for TAMSAT decision logic
                else:
                    print("[!?] Comparing for Unknown Protocol [ {0} ] Vulnerabilities".format(bus_medium))
            # TODO: Redo the above logic but include examination of the edgeMap to check the connectivity between two elements within the AADL model
            # TODO: Add in recognition of hardware bus elements to ensure that HARDWARE related vulnerabilities are incorporated in the vulnerability map
            #   - Do this by making use of the vertex_map "Bus" sublisting for each vertex in the map
            # NOTE: The hardware vulnerability is intended as use ONLY with the BUS information, BUT some can be linked to specific devices (e.g. ASPEED server)
            #   -> How to account for the difference in HARDWARE VULNERABILITY SOURCE for either a given device OR the communication medium
            #       - Ex:   BreeZ Protocol vulnerability; can be reflected in EITHER the sensor/component name OR via the protocol used to communicate between models
            #       - Ex:   Intel server vulnerability; can ONLY really be reflected in the device element and NOT with some bus/medium
            #   - This must mean that (much like with the devices) there is only a certain degree of specificity that can be brought by the 'Bus' elements, same as with the device information
            # Search for and add vulnerabilities based on the Bus / vulnerable mediums
            #   - NOTE: Perhaps this needs to be a SEPARATE for loop that goes thorugh all the bus_medium in the bus_map
            # TODO: Figure out WHERE this information is stored
            #           -> Bus information is maintained within the `vertex_map' (same as the ones used to extract system elements)
            #       Figure out HOW to interate through the information
            #           -> Do a for-loop through the 'Bus Medium' entries and associate them to the given vertex
            #       Figure out WHAT should be check and ADD the necessary vulnerabilities to the larger VULNERABILITY MAP
            #           -> NOTE: Will need to figure out which element(s) to attach the given vulnerability to......
            #               => Not sure how to automate this process....
            #           - This will require some additional decision logic within the Vulnerability Mapping Function
            #           i)      Obtain a list of `Bus Medium' for each vertex in the list
            #           ii)     Determine if the combination of device element + bus medium equates to a combination that can produce a vulnerability
            #                   -> NOTE: This is a similar mechanism to the one used to constrain vulnerabilities based on version number
            #           iii)    Once this combination is validated, then go search the vulnerability database for vulnerabilities BASED ON the BUS MEDIUM
            # Add the returned vulneraiblity list into the vertex entry for the vulnerability map dictionary
            print("[?!?] Checking on the Vulnerability Lists compiled for vertex [ {3} ]\n\tvertex_vuln_list:\t\t[ {0} ]\n\tvertex_bus_vuln_list:\t[ {1} ]\n\tvertex_ignore_vuln_list:\t[ {2} ]".format(vertex_vuln_list, vertex_bus_vuln_list, vertex_ignore_vuln_list, vertex))
            vertex_entry = {
                vertex : {
                    'Vulnerability List' : vertex_vuln_list
                }
            }
            vulnMap.update(vertex_entry)
        if debugBit != 1:   # ~!~
            # Output the contents of the vulnMap
            print("[?] VulnMap:\t{0}".format(vulnMap))          # This is being generated correctly, but not getting output into the attack tree properly
        return vulnMap, entry_exit_map

    # Function(s?) for doing DFS XML Translation of Graph
    # Inputs:
    #       self                    -       The Graph Object itself (i.e. where the graph of the AADL model is maintained)
    #       current_node            -       The current node that is to be printed into the AADL XML attack tree file
    #       nodeMap                 -       Database of information relating to the nodes in the Graph Object; specifically Node Type and Indent Level
    #       visited_nodes           -       List of the nodes that have already been added to the AADL XML atttack tree file
    #       vulnerability_database  -       Databaes of Vulnerable Elements and their known vulnerabilities
    #       attack_tree_file        -       File that the AADL XML Attack Tree is written to
    # Outputs:
    #       visited_nodes           -       Returns the updated list of visited node in the process of prinitng out the AADL XML attack tree
    # TODO: Add in vulnerability additions into the AADL XML representation
    def print_xml_from_node(self, current_node, nodeMap, visited_nodes, vulnerability_database, attack_tree_file):           # NOTE: Recall that need to also add the 'self' item to the function
        # Setup variables used for Node Type and Indent Level
        nodeType = nodeMap[current_node]["Node Type"]
        indent_level = nodeMap[current_node]["Indent Level"]
        # Check which type of node is being written
        #   - Only need to check that the nodeType exists, no need to compare since the structure is the same
        if nodeType:              
            for indent in range(indent_level):
                print(" ", end="")          # NOTE: Use of 'end' variable to ensure that the indentation does not cause a newline
                attack_tree_file.write(" ")
            print('<{0} name="{1}">'.format(nodeType, current_node))
            attack_tree_file.write('<{0} name="{1}">\n'.format(nodeType, current_node))
        else:
            print("[!] ERROR - Unexpected Node Type returned for node [ {0} ]".format(current_node))
        # Add in the vulnerability information to the AADL XML attack tree file
        #   - TODO: Fix a problem where the vulnerabilities can leverage the vulnerabilities already found and now just simply add them to the XML AADL File
        #           => Currently does not include HARDWARE vulnerabilities since the decision logic is not replicated or leveraged below
        #           - This part is using the OLDER logic for TAMSAT; simply check the vulnerability database for matches RATHER than Bus + Device comparison
        for vulnerable_element in vulnerability_database:
            matched_element = re.search(current_node, vulnerable_element, re.IGNORECASE)    # Search to see if the rootNode name exists in the vulnerabilities dictionary
            if matched_element:       # A match was found
                # Check that the beginning of the matched_element is also the start for the JSON vulnerability element
                start_keyword = "^" + current_node
                match_start = re.search(start_keyword, vulnerable_element, re.IGNORECASE)
                if match_start:         # The match is at the beginning of the string (e.g. regex ^)
                    # Since the vulnerable_element matches, cycle through the vulnerabilities and add the "appropriate" ones
                    #   - TODO: Add in constraints to the vulnerabilities added based on the vulnerable_element's features(?) (e.g. version, implementation, configuration; vulnerable_element
                    #           should be the same as the current_node                                  
                    for vulnerability in vulnerability_database[vulnerable_element]["Vulnerability List"]:
                        # Do the thing with the vulnerabilities; NOTE: Vulnerabilities are a single indent more than the associated rootNode/subNode
                        for indent in range(indent_level + 1):
                            print(" ", end="")
                            attack_tree_file.write(" ")
                        print('<vulnerabilities name="{0}" description="{1}"/>'.format(vulnerability, vulnerability_database[vulnerable_element]["Vulnerability List"][vulnerability]))
                        attack_tree_file.write('<vulnerabilities name="{0}" description="{1}"/>\n'.format(vulnerability, vulnerability_database[vulnerable_element]["Vulnerability List"][vulnerability]))
        if debugBit != 0:
            print("List of Neighbours:\t\t{0}".format(self._graph_dict[current_node]))
        # Add this node to the visited_nodes list
        visited_nodes.append(current_node)  # NOTE: Because this is compared to the internal map (which has the first letter capitalized, need to be currNode and NOT current_node)
        # Cycle through the neighbours to perform recursive calls on the neighbours
        for vertex in self._graph_dict[current_node]:
            if debugBit != 0:
                print("\tNeightbour:\t{0}".format(vertex))
            # Check that the neighbour vertex has not already been visited
            if vertex not in visited_nodes:
                if detailDebugBit != 0:
                    print("\t-> Jumping into a recursive loop.... Here is what I know\n\t\tvertex:\t[ {0} ]\n\t\tnodeMap:\t{1}\n\t\tVisited:\t{2}".format(vertex, nodeMap, visited_nodes))
                # Recursive call to the function
                visited_nodes = self.print_xml_from_node(vertex, nodeMap, visited_nodes, vulnerability_database, attack_tree_file)
        # Write out the closing tag to the current_node
        for indent in range(indent_level):
            print(" ", end="")
            attack_tree_file.write(" ")
        print('</{0}>'.format(nodeType))
        attack_tree_file.write('</{0}>\n'.format(nodeType))
        # Return the updated visited_nodes list
        return visited_nodes

    # Function for printing header and footer information of the AADL XML attack tree file
    #   - NOTE: This is the function that calls the recursive helper function print_xml_from_node()
    # Input:
    #       outputFile      -       Output file that the AADL XML gets written to
    def graph_to_full_xml(self, rootNode, nodeMap, vulnerability_database, outputFile):
        # Create a visited_nodes list that tracks vertex points that have already been added to the AADL XML file
        #   - NOTE: Purpose is to prevent un-ending recursive loop due to neighbours
        visited_nodes = []
        # Setup file to write the AADL XML file to
        attacktreeFile = open(outputFile,"w+")
        # Write attacktree file header
        print("[*] Going to print out AADL XML Attack Graph from Graph Structure\n\tUsing rootNode of [ {0} ]".format(rootNode))
        print('<?xml version="1.0" encoding="UTF-8"?>')
        attacktreeFile.write('<?xml version="1.0" encoding="UTF-8"?>\n')      # NOTE: Use of ' character to escape " in strings
        print('<attacktree:Model xmi:version="2.0" xmlns:xmi="http://www.omg.org/XMI" xmlns:attacktree="http://www.example.org/attacktree" name="WebServerExample01" description="Example of Web Server being protected behind a firewall with DoS vulnerabilitiy">')
        #print("[?] Passing arguments to print_xml_from_node\n\trootNode:\t{0}\n\t\tLength:\t{2}\n\tnodeMap:\t{1}\n\t\tLength:\t{3}".format(rootNode, nodeMap, len(rootNode), len(nodeMap)))
        attacktreeFile.write('<attacktree:Model xmi:version="2.0" xmlns:xmi="http://www.omg.org/XMI" xmlns:attacktree="http://www.example.org/attacktree" name="WebServerExample01" description="Example of Web Server being protected behind a firewall with DoS vulnerabilitiy">\n')
        visited_nodes = self.print_xml_from_node(rootNode, nodeMap, visited_nodes, vulnerability_database, attacktreeFile)
        print('</attacktree:Model>')
        attacktreeFile.write('</attacktree:Model>\n')
        attacktreeFile.close()

## NOTE: The following are functions relating to the creation / addition / alteration of nodeMap Objects

# Function for Testing node map functionality
def test_vertex_map():
    vertexMap = {}
    vertex_name_001 = 'server'
    vertex_name_002 = 'database'
    is_port = True
    port_name = 'dat_cool_port'
    port_name_002 = 'http_ice_port'
    port_data_type_001 = 'http'
    port_data_type_002 = 'smb'
    port_direction = 'in out'
    is_data = True
    is_event = True
    data_type_001 = 'http'
    data_type_002 = 'smb'
    is_entry = 'Unknown'
    is_exit = 'Unknown'
    add_vertex_port_to_node_map(vertexMap, vertex_name_001, is_port, port_name, port_data_type_001, port_direction, is_data, data_type_001, is_event, is_entry, is_exit)
    print(vertexMap)
    add_vertex_port_to_node_map(vertexMap, vertex_name_002, is_port, port_name_002, port_data_type_001, port_direction, is_data, data_type_001, is_event, is_entry, is_exit)
    print(vertexMap)
    print("Testing Data Type input")
    add_vertex_port_to_node_map(vertexMap, vertex_name_002, is_port, port_name, port_data_type_002, port_direction, is_data, data_type_001, is_event, is_entry, is_exit)
    print(vertexMap)

# Function for adding a given device element and its properties to a provided nodeMap Object
# Input:
#       nodeMap         -   Node map that the given information will be added into
#       vertex_name     -   Name of the vertex node that is having the port information added to
#       is_port         -   Boolean that indicates if the feature is a port
#       port_name       -   Name of the port that will be added to the provided nodeMap under the given vertex_name node
#       is_data         -   Boolean that indiciates if the port is a data port
#       data_type       -   Data Type for the port_name begin added to the nodeMap
#       is_event        -   Boolean that indiciates if the port is an event port; NOTE: Can be BOTH data and event
#       is_entry        -   Boolean that indiciates if the port is related to an Entry vertex in the node map
#       is_exit         -   Boolean that indiciates if the port is related to an Exit vertex in the node map
# Output:
#
# NOTE: Adding entries into a database is a "hap-hazard" process; requires writing of the COMPLETE entry at once.... Trying to update the entry causes problems
def add_vertex_port_to_node_map(nodeMap, vertex_name, is_port, port_name, port_data_type, port_direction, is_data, data_type, is_event, is_entry, is_exit):
    if debugBit != 0:
        print("[*] Adding vertex [ {0} ] to the provided node map".format(vertex_name))
    # Check if an entry already exists for the provided vertex_name node
    #   - Nota Bene: This check is MANDITORY, if not then the entry will just be over written and replaced with the new info
    #       - Otherwise get a constant re-write issue occuring
    if vertex_name in nodeMap:          # Does the vertex_name already exist in nodeMap; Have we seen/added this vertex before?
        if debugBit != 0:
            print("[!] This vertex [ {0} ] is known!".format(vertex_name))
    else:
        if debugBit != 0:
            print("[!] This vertex [ {0} ] is new!".format(vertex_name))
        # Test adding a vertex entry into the nodeMap
        vertex_entry = {
                vertex_name : {
                    'Ports' : {},
                    'Bus' : {},
                    'Root Node' : False     #   NOTE: Default of False; changed later during establishing Asset of Importance (AoI)
                }
            }
        nodeMap.update(vertex_entry)
    # Now that the function has made sure that an entry exists for the vertex_name within the node map
    #   the function moves to adding in the port information provided
    if debugBit != 0:
        print("[*] Moving to now add in the port information to the vertex_name [ {0} ]".format(vertex_name))
    # Add in the additional infomraiton about any ports into the nodeMap under the vertex_name
    add_port_info_to_node_map(nodeMap, vertex_name, is_port, port_name, port_data_type, port_direction, is_data, data_type, is_event, is_entry, is_exit)    # Note: This function works since the vertex_name check happens earlier
    if debugBit != 0:
        print("[+] Added the vertex [ {0} ] to the provided node map".format(vertex_name))

# Function for adding a given device element and its bus properties to a provided vertex_map Object
# Input:
#       vertex_map          -   Vertex amp that the fiven information will be added into
#       vertex_name         -   Name of the vertex node that is having the bus information added to
#       is_bus              -   Boolean that indicates if the feature is a bus
#       bus_name            -   Name of the bus that will be added to the provided vertex_map under the given vertex_name node
#       bus_type            -   Type of Bus that is to be added to the vertex_map
#       bus_direction       -   Direction of the Bus Connection; e.g. whether communication can go both ways or one
# Output:
#
# NOTE: Adding entries into a database is a "hap-hazard" process; requires writing of the COMPLETE entry at once.... Trying to update the entry causes problems
#   - TODO: Figure out why adding in 'Bus' information is clearing / not adding properly to the vertex_map
def add_vertex_bus_to_node_map(vertex_map, vertex_name, is_bus, bus_name, bus_type, bus_direction, bus_required_flag):
    if debugBit != 0:
        print("[*] Adding vertex [ {0} ] to the provided vertex map".format(vertex_name))
    # Check if an entry already exists for the provided vertex_name vertex
    #   - NOTE: This check is MANDITORY, if not then the entry will just be over written and replaced with the new info
    if vertex_name in vertex_map:           # Does the vertex_name already exist in vertex_map; Has this vertex been seen/added before?
        if debugBit != 0:
            print("[!] This vertex [ {0} ] is known!".format(vertex_name))
    else:
        if debugBit != 0:
            print("[!] This vertex [ {0} ] is new!".format(vertex_name))
        # Create the new vertex entry and add it to the vertex_map
        vertex_entry = {
                vertex_name : {
                    'Ports' : {},
                    'Bus' : {},
                    'Root Node': False      #   NOTE: Default of False; changed later during establishing Asset of Importance (AoI)
                }
            }
        vertex_map.update(vertex_entry)
    # Now that the function has made sure that an entry exists for the vertex_name within the node map
    #   the function moves to adding in the port information provided
    add_bus_info_to_vertex_map(vertex_map, vertex_name, is_bus, bus_name, bus_type, bus_direction, bus_required_flag)       # Note: This function works since the vertex_name check happens earlier
    if debugBit != 0:
        print("[+] Added the vertex [ {0} ] to the provided vertex map".format(vertex_name))

# Function for adding port information to a given vertex node in a provided node map object
# Input:
#       nodeMap         -   Node map that the given information will be added into
#       vertex_name     -   Name of the vertex node that is having the port information added to
#       is_port         -   Boolean that indicates if the feature is a port
#       port_name       -   Name of the port that will be added to the provided nodeMap under the given vertex_name node
#       is_data         -   Boolean that indiciates if the port is a data port
#       data_type       -   Data Type for the port_name begin added to the nodeMap
#       is_event        -   Boolean that indiciates if the port is an event port; NOTE: Can be BOTH data and event
#       is_entry        -   Boolean that indiciates if the port is related to an Entry vertex in the node map
#       is_exit         -   Boolean that indiciates if the port is related to an Exit vertex in the node map
# Output:
#       Edits made to the provided nodeMap to include the port information
def add_port_info_to_node_map(nodeMap, vertex_name, is_port, port_name, port_data_type, port_direction, is_data, data_type, is_event, is_entry, is_exit):
    if debugBit != 0:
        print("[*] Adding port information about [ {0} ] under node vertex [ {1} ] to the given node map".format(port_name, vertex_name))
        print("\tGiven Map:\t{0}".format(nodeMap))
    # Check that I should be added a port; i.e. the function has been provided a port feature
    if is_port == True:
        # Check if this port has already been added into the node map dictionary
        if port_name in nodeMap[vertex_name]['Ports']:          # The port has already been added to the node map dictionary
            if debugBit != 0:
                print("[!] The port [ {0} ] has already been added to vertex [ {1} ] in the node map".format(port_name, vertex_name))
        else:
            if debugBit != 0:
                print("[+] Adding the port [ {0} ] under the vertex [ {1} ] in the node map".format(port_name, vertex_name))
            port_entry = {
                    port_name : {
                        'Data Boolean': is_data,
                        'Data Type': port_data_type,
                        'Port Boolean': is_port,
                        'Port Direction': port_direction,
                        'Event Boolean': is_event,
                        'Entry Boolean': is_entry,
                        'Exit Boolean': is_exit
                        }
                    }
            nodeMap[vertex_name]['Ports'].update(port_entry)        # NOTE: Using .update() here INSTEAD of .append() since Python Dictionaries allow for .update()
    else:
        print("[-] ERROR: Incorrect information provided.... expecting a port for vertex [ {0} ]".format(vertex_name))
    if debugBit != 0:
        print("\tExport Map:\t{0}".format(nodeMap))
    return nodeMap

# Function for adding bus information to a given vertex node in a provided node map object
# Input:
#       vertex_map          -   
#       vertex_name         -       Name of the Vertex to which the Bus should be added under
#       is_bus              -       
#       bus_name            -       Name of the Bus Connection
#       bus_type            -       The Bus Type that the Bus Connection uses
#       bus_direction       -       Feature Direciton of the Bus Connection
#       bus_required_flag   -       Flag that indicates if Bus Connection is one of 'requires access'
# Output:
#       Edits made to the provided vertex_map to include the port information
def add_bus_info_to_vertex_map(vertex_map, vertex_name, is_bus, bus_name, bus_type, bus_direction, bus_required_flag):
    if debugBit != 0:
        print("[*] Adding bus information about [ {0} ] under node vertex [ {1} ] to the given vertex map".format(bus_name, vertex_name))
    # Check that a bus should be added; i.e., the function has been provided a bus feature
    if is_bus == True:
        if debugBit != 0:
            print("[+] A bus connection is to be added to the vertex map")
            print("[?] Testing the bus information in the vertex map\n\tVertex Map:\t{0}\n\tBus Name:\t{1}\n\tVertex Name:\t{2}\n\tCheck Return:\t{3}".format(vertex_map, bus_name, vertex_name, vertex_map[vertex_name]['Bus']))
        if bus_name in vertex_map[vertex_name]['Bus']:          # The bus has already been added to the vertex_map dictionary
            if debugBit != 0:
                print("[!] The bus [ {0} ] has already been added to vertex [ {1} ] in the vertex map".format(bus_name, vertex_name))
        else:
            if debugBit != 0:
                print("[+] Adding the port [ {0} ] under the vertex [ {1} ] in the vertex map".format(bus_name, vertex_name))
                print("[?] Data to be added to the vertex_map\n\tBus Boolean:\t\t{0}\n\tBus Direction:\t\t{1}\n\tBus Type:\t\t\t{2}\n\tBus Required:\t\t{3}".format(is_bus, bus_direction, bus_type, bus_required_flag))
            bus_entry = {
                    bus_name : {
                        'Bus Boolean':  is_bus,
                        'Bus Direction': bus_direction,
                        'Bus Type': bus_type,
                        'Bus Required': bus_required_flag
                    }
                }
            vertex_map[vertex_name]['Bus'].update(bus_entry)        # NOTE: Using .updatE() here INSTEAD of .append() since Python Dictionaries allow for .update()
    else:
        print("[-] ERROR: Incorrect information provided.... expecting a bus for vertex [ {0} ]".format(vertex_name))
    if debugBit != 0:
        print("\tExport Map:\t{0}".format(vertex_map))
    return vertex_map

'''
    - nodeMap STRUCTURE -
nodeMap_name = {
    vertex_node_i :   {
        'Ports' :   {
            port_name_i : {
                'Data Boolean'  :   [ true / false ],
                'Data Type' :   port_data_type,
                'Port Boolean'  :   [ true / false ],
                'Event Boolean' :   [ true / false ],
                'Entry Boolean' :   [ true / false ],
                'Exit Boolean'  :   [ true / false ]
                },
            ( ... ... )
        }
    },
    ( ... ... )
}
'''

## NOTE: The following are functions relating to the creation / addition / alteration of nodeMap Objects

# Function for Testing edge map functionality
def test_edge_map():
    print("Testing edge map functionality")
    edgeMap = create_edge_map()
    edge_name = 'server_to_database'
    edge_name_002 = 'server_to_sensor'
    start_node = 'server'
    end_node = 'database'
    end_node_002 = 'sensor'
    is_data = True
    edge_data_type = 'http'
    edge_data_type_002 = 'smb'
    is_bus = False
    edge_bus_type = 'ethernet'
    edge_bus_type_002 = 'zigbee'
    is_port = True
    edge_direction = 'in out'
    is_entry = "Unknown"
    is_exit = "Unknown"
    bus_required_access_flag = None
    print("[*] Adding edge [ {0} ] to edgeMap".format(edge_name))
    add_edge_to_edge_map(edgeMap, edge_name)
    print(edgeMap)
    print("[*] Adding information to edgeMap about edge [ {0} ]".format(edge_name))
    add_edge_information_to_edge_map(edgeMap, edge_name, start_node, end_node, is_data, edge_data_type, is_bus, edge_bus_type, is_port, edge_direction, is_entry, is_exit, bus_required_access_flag)
    print(edgeMap)
    print("[*] Adding moar information to edge map")
    add_edge_to_edge_map(edgeMap, edge_name_002)
    add_edge_information_to_edge_map(edgeMap, edge_name_002, start_node, end_node_002, is_data, edge_data_type_002, is_bus, edge_bus_type_002, is_port, edge_direction, is_entry, is_exit, bus_required_access_flag)
    print(edgeMap)

# Function for creating the edge map
def create_edge_map():
    print("[*] Returning a blank starter for the edge map")
    edgeMap = {}
    return edgeMap

# Function for adding in the edge-connection to the edge map
def add_edge_to_edge_map(edgeMap, edge_name):
    if debugBit != 0:
        print("[*] Adding edge [ {0} ] to the provided edge map".format(edge_name))
    # Check if edge_name is already been added to the provided edgeMap
    if edge_name in edgeMap:        # The edge edge_name is already in the map
        if debugBit != 0:
            print("[!] Edge [ {0} ] is already known".format(edge_name))
    else:
        if debugBit != 0:
            print("[+] Adding edge [ {0} ] to the edgeMap".format(edge_name))
        edge_entry = {
                edge_name : {}
                }
        edgeMap.update(edge_entry)

# Function for populating the information related to the edge-connection in the edge map
#   - Note: Assumption is that this function is used to place new information into the edge map OR overwrite existing entries
def add_edge_information_to_edge_map(edgeMap, edge_name, start_node, end_node, is_data, edge_data_type, is_bus, edge_bus_type, is_port, edge_direction, is_entry, is_exit, bus_required_access_flag):
    if debugBit != 0:
        print("[*] Adding information about edge [ {0} ]  to the edge map".format(edge_name))
        print("\t[!] Note: This function will potentially overwrite existing information")
    # Check to see if informaiton has already been added under this edge_name entry of the edgeMap
    if 'Nodes' in edgeMap[edge_name]:       # Information already present
        if debugBit != 0:
            print("[!] WARNING: Information already present under [ {0} ] in the edgeMap".format(edge_name))
    else:
        if debugBit != 0:
            print("[+] Adding information under edge [ {0} ] in the edgeMap".format(edge_name))
        edge_information_entry = {
                'Nodes' : {
                    'Start Node' : start_node,
                    'End Node' : end_node
                },
                'Data Boolean' : is_data,
                'Data Type' : edge_data_type,
                'Bus Boolean' : is_bus,
                'Bus Type' : edge_bus_type,
                'Port Boolean' : is_port,
                'Edge Direction' : edge_direction,
                'Entry Boolean' : is_entry,
                'Exit Boolean' : is_exit,
                'Bus Required' : bus_required_access_flag
            }
        edgeMap[edge_name].update(edge_information_entry)

# Function for comparing booleans that are used in the edgeMap
# Inputs:
#       old_bool    -   Older Boolean that will be Updated
#       new_bool    -   Newer Boolean that will be used to Update
# Output:
#       old_bool    -   Updated value of old_bool
def compare_bools_return_update(old_bool, new_bool):
    if new_bool is not None:
        if old_bool is None:        # Value is set to None (default used for error / debug checking)
            old_bool = new_bool
        elif old_bool and new_bool:              # Value of old_bool and new_bool are both True
            old_bool = new_bool
        elif old_bool and not new_bool:          # Value of old_bool and new_bool are True and False
            old_bool = True                     #   - Note: Default to True for the time being
        elif not old_bool and new_bool:          # Value of old_bool and new_bool are False and True
            old_bool = new_bool
        else:
            print("[!?!] Wtf..... This should not have happened - readModel::compare_bools_return_update()")
    else:
        print("[-] ERROR: new_bool [ {0} ] is not a boolean".format(new_bool))
    return old_bool

# Function for comparing data type variables that are used in the edgeMap
# Inputs:
#       old_var    -   Older Data Type that will be Updated
#           -> Note: Assumption of empty string ('') on first feed into function
#       new_var    -   Newer Data Type that will be checked for Update
# Output:
#       old_var    -   Updated value data type variable
def compare_data_type_return_update(old_var, new_var):
    if new_var == '':
        print("[-] ERROR: new_var [ {0} ] is empty...".format(new_var))
    else:
        if old_var == '':
            old_var = new_var
        elif old_var == new_var:
            print("[+] Match between old_var [ {0} ] and new_var [ {1} ]".format(old_var, new_var))
        elif old_var != new_var:
            print("[!] Conflict found between old_var [ {0} ] and new_var [ {1} ]".format(old_var, new_var))
            # NOTE: The above could be used to check for differences in Data Types relating to "mis-matched connections"
        else:
            print("Well.... this was unexpected... readModel::compare_data_type_return_update")
    return old_var

# Function for comparing data type variables that are used in the edgeMap
# Inputs:
#       old_direction    -   Older Data Type that will be Updated
#           -> Note: Assumption of empty string ('') on first feed into function
#       new_direction    -   Newer Data Type that will be checked for Update
# Output:
#       old_direction    -   Updated value data type variable
def compare_direction_return_update(old_direction, new_direction):
    if new_direction == '':
        print("[-] ERROR: new_direction [ {0} ] is empty...".format(new_direction))
    else:
        if old_direction == '':
            old_direction = new_direction
        elif old_direction == new_direction:
            print("[+] Match between old_direction [ {0} ] and new_direction [ {1} ]".format(old_direction, new_direction))
        elif old_direction != new_direction:
            print("[!] Conflict found between old_direction [ {0} ] and new_direction [ {1} ]".format(old_direction, new_direction))
            # NOTE: The above could be used to check for differences in Direction relating to "mis-matched connections"
        else:
            print("Well.... this was unexpected... readModel::compare_direction_return_update")
    return old_direction

'''
    - edgeMap STRUCTURE -
edgeMap_name = {
    edge_label_i    :   {       <----- Have this be the name of the connection being made (i.e. name from AADL model file)
        'Nodes' :   {
            'Start Node'    :   vertex_name,
            'End Node'      :   vertex_name
        },
        'Data Boolean'  :   [ true / false ],
        'Data Type'     :   data_type,
        'Bus Boolean'   :   [ true / false ],
        'Bus Type'      :   bus_type,
        'Port Boolean'  :   [ true / false ],
        'Edge Direction'    :   in/out/in out,
        'Entry Boolean' :   [ true / false ],
        'Exit Boolean'  :   [ true / false ]
    },
    ( ... ... )
}
'''

## Function Definitions

# Function for reading in the file contents
def readFile(fileName):
    if debugBit != 0:
        print("[*] Reading in the file....")
    # Open the file for reading
    f = open(fileName, "r")
    # Use 'readlines()' to read all lines in the file; the variable 'lines' is a list containing all lines in the file
    lines = f.readlines()
    # Close the file after reading the lines
    f.close()
    # Return the read in list
    return lines

'''
# Function for reading in a JSON file; Example - Used to read the hardware_database
def readJSON(jsonFile):
    jsonData = {}
    with open(jsonFile, 'r') as infile:
        jsonData  = json.load(infile)
    return jsonData
'''

# Function for parsing the content lines of the AADL model file
#   -> NOTE: Use of .lstrip(' ') removes ONLY whitespaces; .lstrip() will remove leading tabs AS WELL
# Input:    Lines of read in AADL model file
# Output:   deviceFile, systemFile, implementatFile
#   -> These are each a python dictionary that contain definitions of the models
#       - device and system files contains HIGH LEVEL descriptions
#       - implementation file contains a DETAILED CONNECTION description
def parseContent(fileContents):
    # General Variable Setting 
    seenImport = 0
    importingDefs = 0
    elementDef = 0
    deviceFeatures = 0
    modelName = ""
    currElement = ""
    elemFeatureDef = 0
    elemFlowDef = 0
    implementDef = 0
    elemSubcompDef = 0
    elemConnsDef = 0
    # Lists used for sanity checking
    busList = []
    dataList = []
    deviceList = []
    systemList = []
    # Dictionaries used for creation of device, system, and implementation databases
    deviceFile = {}
    systemFile = {}
    implementationFile = {          # NOTE: Devices and System implementations are stored in the SAME dictionary (?? Maybe Don't Do This)
                #"Devices": {},
                #"Systems": {}
            }
    featureList = {}        # Create an empty dictionary that will be filled with features | Make sure to clear
    flowList = {}           # Create an empty dictionary that will be filled with flows
    subcompList = {}        # Create an empty dictionary that will be filled with subcomponents
    connList = {}           # Create an empty dictionary that will be filled with connections
    # Key framework information used to let SMART know what the asset of importance is
    assetOfImportance = 'UNKNOWN'           # Default value of UNKNOWN so as to trigger user interaction later with SMART
    if debugBit != 0:
        print("[*] Parsing the file contents....")
    # Begin parsing through the file contents
    for line in fileContents:
        if debugBit != 0:
            print(re.split('\s+', line.lstrip()))
        lineBreakdown = re.split('\s+', line.lstrip())      # Prepare array of tokenized contents for the line being examined
        # Check if we are seeing a 'package' keyword (shows the start of the AADL model file)
        if lineBreakdown[0] == "package":
            modelName = lineBreakdown[1]
            if debugBit != 0:
                print("[+] Started to parse the package {0}".format(modelName))
        # Check if we are seeing a 'public' keyword (dealing with the import of other packages)
        elif lineBreakdown[0] == "public":
            importingDefs = 1
        # Check if we are seeing a 'with' keyword; importing definitions for the model; NOTE: Not handled at this point
        elif lineBreakdown[0] == "with":
            newPackageImport = lineBreakdown[1]
            seenImport = 1
            if debugBit != 0:
                print("[+] Importing the package {0}".format(newPackageImport))
            # TODO: Do stuff with this information(???)
        # Check if we are seeing an empty line (don't do much of anything)
        elif lineBreakdown[0] == "":
            if debugBit != 0:
                print("[*] Seeing a blank line.... Do nothing")
            if seenImport != 0:
                if debugBit != 0:
                    print("[+] Completed import of packages")
                seenImport = 0
                importingDefs = 0           # <-------------- Repeatative task??? Can remove?
        # Check if we are seeing a comment line
        elif lineBreakdown[0] == "--":          # TODO: Move higher up in the loop to prevent the processing of comments
            if debugBit != 0:   # ~!~
                print("[*] Seeing a comment line.... Do nothing")
            # Check to see if the comment line is the encoded Asset of Importance
            asset_of_importance_pattern = "ASSET_OF_IMPORTANCE"
            if debugBit != 0:   # ~!~
                print("\tLine Breadown:\t{0}\n\t\tSearch for AoI returned [ {1} ]".format(lineBreakdown, re.search(asset_of_importance_pattern, lineBreakdown[1], re.IGNORECASE)))
            if re.search(asset_of_importance_pattern, lineBreakdown[1], re.IGNORECASE):
                if debugBit != 0:
                    print("\tFound the encoded Asset of Importance\n\t\tAoI\t-\t{0}".format(lineBreakdown[2]))
                assetOfImportance = lineBreakdown[2]
        # Check if we are seeing a 'bus' element
        elif lineBreakdown[0] == "bus":
            if debugBit != 0:
                print("[+] Found a 'bus' element\n\tbus:\t{0}".format(lineBreakdown[1]))
            busList.append(lineBreakdown[1])
        # Check if we are seeing a 'data' element
        elif lineBreakdown[0] == "data":
            if debugBit != 0:
                print("[+] Found a 'data' element\n\tdata:\t{0}".format(lineBreakdown[1]))
            dataList.append(lineBreakdown[1])
        # Check if we are seeing a 'device' element
        elif lineBreakdown[0] == "device":
            if lineBreakdown[1] == "implementation":
                if debugBit != 0:
                    print("[+] This is an 'implementation'.... Examine this differently")
                currElement = lineBreakdown[2]
                # Set variable to track that we are examining an implementation
                implementDef = 1
            elif "extends" in lineBreakdown:
                if debugBit != 0:
                    print("[+] This device element is an extension of another <thing>")
            else:           # Default is that we are dealing with an element definition
                currElement = lineBreakdown[1]
                elementDef = 1
            if debugBit != 0:
                print("[+] Found a 'device' element\n\tdevice:\t{0}".format(currElement))
            deviceList.append(currElement)
        # Check if we are seeing a 'system' element
        elif lineBreakdown[0] == "system":          # TODO: Add implementation and extends paths to this conditional
            if lineBreakdown[1] == "implementation":
                if debugBit != 0:
                    print("[+] This is an 'implementation'.... Examine this differently")
                currElement = lineBreakdown[2]
                # Set variable to track that we are examining an implementation
                implementDef = 1
            elif "extends" in lineBreakdown:
                if debugBit != 0:
                    print("[+] This system element is an extension of another <thing>")
            else:           # Default is that we are dealing with a system definition
                currElement = lineBreakdown[1]
                elementDef = 1
            if debugBit != 0:
                print("[+] Found a 'system' element\n\tsystem:\t{0}".format(currElement))
            systemList.append(currElement)
        # Check if we are examining definition information; specifically 'feature' information
        elif lineBreakdown[0] == "features" and elementDef != 0:
            if debugBit != 0:
                print("[+] Beginning to detail <{0}> features".format(currElement))
            elemFeatureDef = 1
            elemFlowDef = 0             # Zero out the other used variables
        # Check if we are examining definition infomation; specifically 'flow' information
        elif lineBreakdown[0] == "flows" and elementDef != 0:
            if debugBit != 0:
                print("[+] Beginning to detail <{0}> flows".format(currElement))
            elemFlowDef = 1
            elemFeatureDef = 0          # Zero out the other used variables
        # Check if we are examining implementation information; specifically 'flow' information
        elif lineBreakdown[0] == "flows" and implementDef != 0:
            if debugBit != 0:
                print("[+] Beginning to detail <{0}> implementation flows".format(currElement))
            elemFlowDef = 1
            elemSubcompDef = 0                                                                      
            elemConnsDef = 0  
        # Check if we are seeing an 'end' keyword
        elif lineBreakdown[0] == "end":
            if debugBit != 0:
                print("[+] Found an 'end' keyword for {0}".format(lineBreakdown[1].rstrip(';')))
            endElement = lineBreakdown[1].rstrip(';')
            if debugBit != 0:
                print("[*] Checking that current element matches end element:\n\tcurrElement:\t{0}\n\tendElement:\t{1}".format(currElement, endElement))
            # Further check what list the currenty examine element is part of       | TODO: Add case for looking for implementations
            if endElement in busList:
                if debugBit != 0:
                    print("[*] End element is a bus")
            elif endElement in dataList:
                if debugBit != 0:
                    print("[*] End element is data")
            elif endElement in deviceList:
                if debugBit != 0:
                    print("[*] End element is a device")
                # TODO: Add a second layer of checks to see if we are examining an implementation vs a high level definition
                if implementDef != 1:       # Dealing with a high level definition
                    # Add information to the deviceFile dictionary      | NOTE: Works.... But also pulling in implementations....
                    deviceFile[currElement] = {             # TODO: Add addition of flowList
                                "Features List": featureList,
                                "Flows List": flowList
                            }
                elif implementDef == 1:     # Dealing with an implementation definition
                    # Add information to the implementationFile     | NOTE: Split up the currElement by '.' to get device/system name and implementation name
                    implementBreakdown = re.split('\.+', currElement)
                    if debugBit != 0:
                        print("[*] Element Implementation Breakdown:\n\tElement Name:\t{0}\n\tImplementation Name:\t{1}".format(implementBreakdown[0], implementBreakdown[1]))
                    implementationFile[implementBreakdown[0]] = {
                            implementBreakdown[1]: {
                                    "Subcomponents List": subcompList,
                                    "Connections List": connList,
                                    "Flows List": flowList
                                }
                            }
                else:
                    print("[-] Something unexpected has happened..... Not seeing a high level or implementation definition")
            elif endElement in systemList:
                if debugBit != 0:
                    print("[*] End element is a system")
                # TODO: Add a second layer of checks to see if we are examining an implementation vs a high level definition
                if implementDef != 1:       # Dealing with a high level definition
                    # Add information to the systemFile dictionary      | NOTE: Works.... But also pulling in implementations....
                    systemFile[currElement] = {             # TODO: Add addition of flowList
                                "Features List": featureList,
                                "Flows List": flowList
                            }
                elif implementDef == 1:     # Dealing with an implementation definition
                    # Add information to the implementationFile     | NOTE: Split up the currElement by '.' to get device/system name and implementation name
                    implementBreakdown = re.split('\.+', currElement)
                    if debugBit != 1:   # ~!~
                        print("[*] Element Implementation Breakdown:\n\tElement Name:\t{0}\n\tImplementation Name:\t{1}".format(implementBreakdown[0], implementBreakdown[1]))
                    implementationFile[implementBreakdown[0]] = {
                            implementBreakdown[1]: {
                                    "Subcomponents List": subcompList,
                                    "Connections List": connList,
                                    "Flows List": flowList
                                }
                            }
            elif endElement == modelName:
                if debugBit != 0:
                    print("[*] Reached the end of the package file")
            else:
                if debugBit != 0:
                    print("[-] Unknown match to the found end element:\t{0}".format(endElement))
            # Reset all the tracking variables and dictionary structures
            currElement = ""        # Clear the current element
            elemFeatureDef = 0
            elemFlowDef = 0
            elementDef = 0
            implementDef = 0
            elemSubcompDef = 0
            elemConnsDef = 0
            featureList = {}        # Clear the current featureList (in prep for next device/system parse)
            flowList = {}           # Clear the current flowList
            subcompList = {}        # Clear the current subcompList
            connList = {}           # Clear the current connList
        # Check if we are looking at feature information
        elif elemFeatureDef == 1 and elementDef != 0:
            if debugBit != 0:
                print("[*] Examining a feature line")
            detailDef = 0
            featureName = ''
            featureDirection = ''
            featureType = ''
            featureConnectionType = ''
            bus_required_access_flag = False
            # Seen it variables (booleans) for specific AADL feature datums
            seen_type_in = False
            seen_type_out = False
            seen_keyword_requires = False
            seen_keyword_access = False
            for featureDatum in lineBreakdown:           # Loop through the array of lineBreakdown
                if debugBit != 0:   # ~!~
                    print("\tFeature Datum: {0}".format(featureDatum))
                if featureDatum == ':':                 # Switching from names to details
                    detailDef = 1
                    if debugBit != 0:
                        print("\t[+] Switching from feature name to feature details")
                elif detailDef != 0:                    # In the detail section of the feature description
                    if debugBit != 0:
                        print("\t[*] Looking at a feature detail")
                    # Examining detail information  |   TODO: Add in all other variations for AADL models   <--- super restricted to expected
                    # TODO: Add in recognition and differentiation between "in", "out", and "in out"
                    #           - idiot fix: carry variable but would require in + out, could be a "seen it" variable with a check at the end of the feature read
                    if featureDatum == "in":
                        featureDirection = featureDatum
                        seen_type_in = True
                    elif featureDatum == "out":
                        featureDirection = featureDatum
                        seen_type_out = True
                    elif featureDatum == "requires":
                        seen_keyword_requires = True
                    elif featureDatum == "access":
                        seen_keyword_access = True
                    elif featureDatum == "data":
                        featureType = featureDatum           # Need a way to check this.... Should match with a known type
                    elif featureDatum == "bus":
                        featureType = featureDatum
                        # TODO: Need method of tracking that if a bus is seen, then at the end set featureConnectionType
                        featureConnectionType = featureDatum            # NOTE: Rough addition of the 'bus' featureConnectionType 
                    elif featureDatum == "port":
                        featureConnectionType = featureDatum
                    elif ';' in featureDatum:           # Looking at the last item in the feature (data/bus type name)
                        if featureType == "data":
                            if debugBit != 0:
                                print("[*] Looking at data type feature")
                            if featureDatum.rstrip(';') in dataList:    # Confirming that the feature is a data type    | NOTE: Should match the featureType
                                featureType = featureDatum.rstrip(';')  # Set the type to the data name
                            else:               # No idea what this thing is
                                print("[-] Unknown data type name....")
                                featureType = "Unknown"
                        # NOTE: This part of the code only examines the Device definitions?
                        elif featureType == "bus":
                            feature_type_bus = featureType
                            if debugBit != 0:
                                print("[*] Looking at bus type feature")
                            if featureDatum.rstrip(';') in busList:     # Confirming that the feature is a bus type     | NOTE: Should match the featureType
                                featureType = featureDatum.rstrip(';')
                                # Checking for the 'requires' and 'access' states of 'bus' definition
                                #print("[!!!!]\tVariable Check:\n\tseen_keyword_requires:\t{0}\n\tseen_keywords_access:\t{1}\n\tfeatureConnectionType:\t{2}\n\tfeature_type_bus:\t{3}\n\tfeatureType:\t{4}".format(seen_keyword_requires, seen_keyword_access, featureConnectionType, feature_type_bus, featureType))
                                if (seen_keyword_requires == True) and (seen_keyword_access == True):
                                    featureConnectionType = feature_type_bus
                                    featureDirection = "in out"
                                    bus_required_access_flag = True        # TODO: Add this into the appropriate dictionary
                                    #print("[!!!] Setting the bus_required_access_flag for item [ {1} ]\n\tbus_required_access_flag:\t{0}\n\tFeature:\t{1}".format(bus_required_access_flag, featureName))
                            else:
                                print("[-] Unknown bus type name....")
                                featureType = "Unknown"
                        else:
                            print("[-] Not sure what type of feature being looked at")
                            if debugBit != 0:
                                print("\tSeeing\t-\tFeatureDatume:\t{0}\n\t\t\tFeatureType:\t{1}".format(featureDatum, featureType))
                elif detailDef == 0:                    # In the name section of the feature description
                    if debugBit != 0:
                        print("\t[*] Looking at a feature name")
                    featureName = featureDatum
            # Check for having seen 'in' and 'out' on the feature, therefore need to ensure that 'featureDirection' is set to "in out"
            if (seen_type_in == True) and (seen_type_out == True):
                featureDirection = "in out"
            if debugBit != 0:           # ~!~
                print("\tFeature: {0}\n\tType: {1}\n\tConnection Type: {2}\n\tDirection: {3}\n\tVariable Test:\n\t\tSeen 'in':\t{4}\n\t\tSeen 'out':\t{5}\n\t\tSeen 'requires':\t{6}\n\t\tSeen 'access':\t{7}\n\t\tRequired Access Flag:\t{8}".format(featureName, featureType, featureConnectionType, featureDirection, seen_type_in, seen_type_out, seen_keyword_requires, seen_keyword_access, bus_required_access_flag))
            # DONE: Find a way to store this information is a database structure
            #       1) Add Feature to featureList
            #       2) Once done adding Features, need to add featureList to deviceList[currElement]    | Done in 'end' case
            #       3) Clear the featureList to prep for the next interation        | Done in the 'end' case?
            #   -> Note: Same diea for doing the flowList
            featureList[featureName] = {
                        "Feature Direction": featureDirection,
                        "Feature Type": featureType,
                        "Feature Connection Type": featureConnectionType,
                        "Bus Required Access Flag": bus_required_access_flag            # NOTE: Added this to track for required access bus elements
                    }
            detailDef = 0
        # Check if we are looking at flow information (for a high level definition)
        elif elemFlowDef == 1 and elementDef != 0:
            if debugBit !=0:
                print("[*] Examining a flow line")
            detailDef = 0
            flowName = ''
            flowDirection = ''
            flowFeature = ''            # Used to track feature that a given flow is connected to
            flowType = ''
            for flowDatum in lineBreakdown:             # Loop through the array of lineBreakdown
                if debugBit != 0:
                    print("\tFlow Datum:\t{0}".format(flowDatum))
                if flowDatum == ":":                    # Switching from names to details
                    detailDef = 1
                    if debugBit != 0:
                        print("\t[+] Switching from flow name to flow details")
                elif detailDef != 0:                    # In the detail section of the flow description
                    if debugBit != 0:
                        print("\t[*] Looking at a flow detail")
                    # Examining detail information  |   TODO: Add in all other variations for AADL models   <--- super restricted to expected
                    if flowDatum == "source":
                        flowDirection = flowDatum
                    elif flowDatum == "sink":
                        flowDirection = flowDatum
                    elif flowDatum == "flow":           # Added mainly to track this information (in case changes in larger AADL model)
                        flowType = flowDatum
                    elif ';' in flowDatum:              # Looking at the last item in the flow (featureName that flowName is connected to)
                        # Check to make sure that the featureName exists in featureList.... Otherwise got a PROBLEM!
                        if flowDatum.rstrip(';') in featureList:    # Confirming that featureName is in the featureList
                            flowFeature = flowDatum.rstrip(';')
                        else:
                            print("[-] Unknown feature that the flow is connected to.....")
                            flowFeature = "Unknown"
                elif detailDef == 0:                    # In the name section of the flow descripion
                    if debugBit != 0:
                        print("\t[*] Looking at a flow name")
                    flowName = flowDatum
            if debugBit != 0:
                print("\tFlow: {0}\n\tDirection: {1}\n\tFeature: {2}\n\tType: {3}".format(flowName, flowDirection, flowFeature, flowType))
            # Add this information to the flowList dictionary structure
            flowList[flowName] = {
                        "Flow Direction": flowDirection,
                        "Flow Type": flowType,
                        "Flow Feature": flowFeature
                    }
            detailDef = 0
        # Check if we are looking at flow informaiton (for an implementation definition)
        elif elemFlowDef == 1 and implementDef != 0:
            if debugBit != 0:
                print("[*] Examining an implementation flow line")
            detailDef = 0
            flowName = ''
            flowDirection = ''
            flowMap = ''
            flowType = ''
            # TODO: Write loop for examining details
            for flowDatum in lineBreakdown:             # Loop through the array of lineBreakdown
                if debugBit != 0:
                    print("\tFlow Datum:\t{0}".format(flowDatum))
                if flowDatum == ":":                    # Switching from names to details
                    detailDef = 1
                    if debugBit != 0:
                        print("\t[+] Switching from flow name to flow details")
                elif detailDef != 0:
                    if debugBit != 0:
                        print("\t[*] Looking at a flow detail")
                    # Examining detail information  |   TODO: Parse the flows details
                    if flowDatum == "source":
                        flowDirection = flowDatum
                    elif flowDatum == "sink":
                        flowDirection = flowDatum
                    elif flowDatum == "flow":
                        flowType = flowDatum
                    elif flowDatum == "->":         # Seeing a continuation of the flow map     |   TODO: Account for <-> flow (???)
                        flowMap += flowDatum        # Add to the flow map; assuming later use of '->' as tokenizer of flow path
                    elif flowDatum == "<->":
                        flowMap += flowDatum
                    elif ';' in flowDatum:          # Hitting the END of the flow map
                        # TODO: Add check that subcomponent element exists.... Otherwise got a PROBLEM!
                        if '.' in flowDatum:
                            if debugBit != 0:
                                print("\t[*] Seeing subcomponent element as last element in flow map")
                        else:
                            if debugBit != 0:
                                print("\t[*] Seeing a feature of the <{0}> element as last element in flow map".format(currElement))
                        # NOTE: Rough addition here; need to fix to be within the element check above
                        flowMap += flowDatum.rstrip(';')        # Note: May need check against 'access' for preventing word-merging
                    # Otherwise assume (? dangerous?) that the flowDatum is an element name     |   TODO: Add check for '.' or not; check elem exists
                    else: 
                        if '.' in flowDatum:
                            if debugBit != 0:
                                print("\t[*] Seeing subcomponent element in flow map")
                        else:
                            if debugBit != 0:
                                print("\t[*] Seeing a feature of the <{0}> element in flow map".format(currElement))
                            # TODO: Add check that element exists in the higher level definition
                        # NOTE: Rough addition here; need to fix to be within the element check above
                        flowMap += flowDatum
                elif detailDef == 0:
                    if debugBit != 0:
                        print("\t[*] Looking at a flow name")
                    flowName = flowDatum
            if debugBit != 0:
                print("\tFlow: {0}\n\tDirection: {1}\n\tType: {3}\n\tMap: {2}".format(flowName, flowDirection, flowMap, flowType))
            # Add this information to the flowList dictionary structure
            flowList[flowName] = {
                        "Flow Direction": flowDirection,
                        "Flow Type": flowType,
                        "Flow Map": flowMap
                    }
            detailDef = 0
        # Check if we are seeing a subcomponent line
        elif lineBreakdown[0] == "subcomponents" and implementDef != 0:
            if debugBit != 0:
                print("[*] Beginning to detail <{0}> subcomponents".format(currElement))
            elemSubcompDef = 1
            elemFlowDef = 0
            elemConnsDef = 0
        # Check if we are seeing a connections line
        elif lineBreakdown[0] == "connections":
            if debugBit != 0:
                print("[*] Beginning to detail <{0}> connections".format(currElement))
            elemConnsDef = 1
            elemFlowDef = 0
            elemSubcompDef = 0
        # Check if we are looking at subcomponent information   | TODO: Parse the subcomponent information
        elif elemSubcompDef == 1 and implementDef != 0:
            if debugBit != 0:
                print("[*] Examining a subcomponent line")
            detailDef = 0
            subcompName = ''
            subcompImplementation = ''
            subcompType = ''
            for subcompDatum in lineBreakdown:          # Loop through the array of lineBreakdown
                if debugBit != 0:
                    print("\tsumcompDatum:\t{0}".format(subcompDatum))
                if subcompDatum == ":":                  # Switching from name to details
                    detailDef = 1
                    if debugBit != 0:
                        print("\t[+] Switching from subcomp name to subcomp details")
                elif detailDef != 0:
                    if debugBit != 0:
                        print("\t[*] Looking at a subcomp detail")
                    # Examining detail information
                    if subcompDatum == "device":
                        subcompType = subcompDatum
                    elif subcompDatum == "bus":
                        subcompType = subcompDatum
                    elif ';' in subcompDatum:           # Dealing with a subcomponent implementation (last element in definition)
                        # TODO: Add check that subcomponent thing exists (?? maybe this is better to check laster?)
                        subcompImplementation = subcompDatum.rstrip(';')
                elif detailDef == 0:
                    if debugBit != 0:
                        print("\t[*] Looking at subcomp name")
                    subcompName = subcompDatum
            if debugBit != 0:
                print("\tSubcomp: {0}\n\tType: {1}\n\tImplementation: {2}".format(subcompName, subcompType, subcompImplementation))
            # Add the subcomponent information to the subcomponentList dictionary
            subcompList[subcompName] = {
                        "Subcomponent Type": subcompType, 
                        "Subcomponent Implementation": subcompImplementation
                    }                             
            detailDef = 0
        # check if we are looking at connections information    | TODO: Parse the connections information
        elif elemConnsDef == 1 and implementDef != 0:
            if debugBit != 0:
                print("[*] Examining a connection line")
            detailDef = 0
            connName = ''
            connType = ''
            connMap = ''
            # TODO: Add loop for parsing the connections information
            for connDatum in lineBreakdown:             # Loop through the array of lineBreakdown
                if debugBit != 0:
                    print("[*] Examining a connection line")
                if connDatum == ":":                    # Switching from name to details
                    detailDef = 1
                    if debugBit != 0:
                        print("\t[+] Switching from connection name to connection details")
                elif detailDef != 0:
                    if debugBit != 0:
                        print("\t[*] Looking at a connection detail")
                    # Examining detail information
                    if connDatum == "port":             # NOTE: Will need to expand to account for larger possibilities in AADL model
                        connType = connDatum
                    elif connDatum == "bus":
                        connType = connDatum
                    # Checks for the different directions that can occur
                    elif connDatum == "->": 
                        connMap += connDatum
                    elif connDatum == "<->":
                        connMap += connDatum
                    elif connDatum == "<-":
                        connMap += connDatum
                    # Checks for bus specific key words
                    elif connDatum == "access":
                        # Do whatever so far
                        print("[!] HOLY access BATMAN!")        # ~!~ TODO: Incorporate the access keyword into the constraints piece of G-T-S
                    elif ';' in connDatum:          # Hitting the END of the connection map                              
                        # TODO: Add check that subcomponent element exists.... Otherwise got a PROBLEM!
                        if '.' in connDatum:
                            if debugBit != 0:
                                print("\t[*] Seeing subcomponent element as last element in connection map")
                        else:                 
                            if debugBit != 0:
                                print("\t[*] Seeing a feature of the <{0}> element as last element in connection map".format(currElement))
                        # NOTE: Rough addition here; need to fix to be within the element check above
                        connMap += connDatum.rstrip(';')
                    # Otherwise assume (? dangerous?) that the connDatum is an element name     |   TODO: Add check for '.' or not; check elem exists                                                                        
                    else:                         
                        if '.' in connDatum:
                            if debugBit != 0:
                                print("\t[*] Seeing subcomponent element in connection map")                       
                        else:                        
                            if debugBit != 0:
                                print("\t[*] Seeing a feature of the <{0}> element in connection map".format(currElement))
                            # TODO: Add check that element exists in the higher level definition
                        # NOTE: Rough addition here; need to fix to be within the element check above
                        connMap += connDatum
                elif detailDef == 0:
                    if debugBit != 0:
                        print("\t[*] Looking at connection name")
                    connName = connDatum
            if debugBit != 0:
                print("\tConn: {0}\n\tType: {1}\n\tMap: {2}".format(connName, connType, connMap))
            connList[connName] = {
                        "Connection Type": connType,
                        "Connection Map": connMap
                    }
            detailDef = 0
        # Check if we are not seeing a 'with' keyword; if not then change the 'importingDefs' variable back to 0 | NOTE: Do differently?
#        elif lineBreakdown[0] != "with" and lineBreakdown[0] != "" and lineBreakdown[0] != "--" and importingDefs != 0:
#            if debugBit != 0:
#                print("[+] Completed the import of external data")
#            importingDefs = 0
        else:       # Something unknown is happeneing
            print("[-] Something unknown is happening.....")
    # Idiot testing of variables
    #print("[?] Feature List data:\n{0}\n[?] Device File data:\n{1}\n[?] System File data:\n{2}".format(featureList, deviceFile, systemFile))
    #pp = pprint.PrettyPrinter(indent=4)
    #pp.pprint(implementationFile)
    # Return output of generated files containing device, system, and implementation defitions
    return deviceFile, systemFile, implementationFile, assetOfImportance

# Function for finding the subcomponet type
#   - NOTE: Function returns False if no match is found
def find_subcomponent_type(implementation_dictionary, element, implementation, subcomponent_name):
    match_subcomponent_type = next((implementation_dictionary[element][implementation]["Subcomponents List"][item]["Subcomponent Type"] for item in implementation_dictionary[element][implementation]["Subcomponents List"] if item == subcomponent_name), False)
    return match_subcomponent_type

# Function for finding the subcomponent implementation
#   - NOTE: Function returns False if no match is found
def find_subcomponent_implementation(implementation_dictionary, element, implementation, subcomponent_name):
    match_subcomponent_implementation = next((implementation_dictionary[element][implementation]["Subcomponents List"][item]["Subcomponent Implementation"] for item in implementation_dictionary[element][implementation]["Subcomponents List"] if item == subcomponent_name), False)
    return match_subcomponent_implementation

# Function for finding a device element feature direction
#   - NOTE: Function returns False if no match is found
def find_device_element_feature_direction(device_dictionary, subcomponent_feature, subcomponent_element_name):
    match_device_element_feature_direction = next((device_dictionary[device]["Features List"][subcomponent_feature]["Feature Direction"] for device in device_dictionary if device == subcomponent_element_name), False)
    return match_device_element_feature_direction

# Function for finding a device element feature type
#   - NOTE: Function returns False if no match is found
def find_device_element_feature_type(device_dictionary, subcomponent_feature, subcomponent_element_name):
    match_device_element_feature_type = next((device_dictionary[device]["Features List"][subcomponent_feature]["Feature Type"] for device in device_dictionary if device == subcomponent_element_name), False)
    return match_device_element_feature_type

# Function for finding a device element feature connection type
#   - NOTE: Function returns False if no match is found
def find_device_element_feature_connection_type(device_dictionary, subcomponent_feature, subcomponent_element_name):
    match_device_element_feature_connection_type = next((device_dictionary[device]["Features List"][subcomponent_feature]["Feature Connection Type"] for device in device_dictionary if device == subcomponent_element_name), False)
    return match_device_element_feature_connection_type

# Function for finding a device element bus required access flag
def find_device_element_feature_bus_required_access_flag(device_dictionary, subcomponent_feature, subcomponent_element_name):
    match_device_element_feature_bus_require_access_flag = next((device_dictionary[device]["Features List"][subcomponent_feature]["Bus Required Access Flag"] for device in device_dictionary if device == subcomponent_element_name), False)
    return match_device_element_feature_bus_require_access_flag

# Function for finding a system feature direction
def find_system_feature_direction(system_dictionary, system_name, system_feature):
    match_system_feature_direction = next((system_dictionary[system_name]["Features List"][item]["Feature Direction"] for item in system_dictionary[system_name]["Features List"] if item == system_feature), False)
    return match_system_feature_direction

# Function for finding a system feature type
def find_system_feature_type(system_dictionary, system_name, system_feature):
    match_system_feature_type = next((system_dictionary[system_name]["Features List"][item]["Feature Type"] for item in system_dictionary[system_name]["Features List"] if item == system_feature), False)
    return match_system_feature_type

# Function for finding a system feature connection type
def find_system_feature_connection_type(system_dictionary, system_name, system_feature):
    match_system_feature_connection_type = next((system_dictionary[system_name]["Features List"][item]["Feature Connection Type"] for item in system_dictionary[system_name]["Features List"] if item == system_feature), False)
    return match_system_feature_connection_type

# Function for finding a system implementation subcomponent type
#def find_system_implementation_subcomponent_type():
    #match_system_implementation_subcomponent_type = next((implementation_dictionary[element][implementation]["Subcomponents List"][item]["Subcomponent Implementation"] for item in implementation_dictionary[element][implementation]["Subcomponents List"] if item == subcomponent_name), False)
    #return match_system_implementation_subcomponent_type

# Function for finding a system implementation subcomponent implementation


# Function for generating the attacktree file
# Input:
#       1) Device Dictionary            \
#       2) System Dictionary             |-- Contains the high level and detailed information about the original AADL model
#       3) Implementation Dictionary    /
#       4) Vulnerability Dictionary
#       5) Output file
#           - Where the attacktree file will be placed
#       6) Asset of Importance (for establishing root of the attack tree)
#       7) Bus Dictionary
#           - Contains the 'bus' connection information
# TODO: Add in hardware specific vulnerabilites that are identified based on 'bus' information (busMap?)
#   - Can use the edge_map.json to check to see if a Bus is required for connectivity
#   - TODO: Create the busMap that contains bus information
def generateAttackTree(deviceFile, systemFile, implementationFile, vulnerabilitiesFile, outputFile, assetOfImportance):
    if debugBit != 0:
        print("[*] Beginning to generate the attacktree file....")
    # Check the the passed variables are not empty
    if debugBit != 0:
        print("[*] Checking that the passed devices, systems, implementations, and vulnerabilities are not empty")
    if deviceFile:              # Check that the deviceFile is NOT empty
        if debugBit != 0:
            print("[+] Devices dictionary is not empty")
    else:
        print("[-] ERROR: Devices dictionary is empty..... Exiting function")
        return
    if systemFile:              # Check that the systemFile is NOT empty
        if debugBit != 0:
            print("[+] Systems dictionary is not empty")
    else:
        print("[-] ERROR: Systems dictionary is empty..... Exiting function")
        return
    if implementationFile:      # Check that the implementationFile is NOT empty
        if debugBit != 0:
            print("[+] Implementations dictionary is not empty")
    else:
        print("[-] ERROR: Implementations dictionary is empty..... Exiting function")
        return
    if vulnerabilitiesFile:      # Check that the vulnerabilitiesFile is NOT empty
        if debugBit != 0:
            print("[+] Vulnerabilities dictionary is not empty")
    else:
        print("[-] ERROR: Vulnerabilities dictionary is empty..... Exiting function")
        return
    # Create the file that the attack tree will be put into
    #attacktreeFile = open("generated.attacktree","w+")
    #attacktreeFile = open(outputFile,"w+")
    # Write attacktree file header
    #attacktreeFile.write('<?xml version="1.0" encoding="UTF-8"?>\n')      # NOTE: Use of ' character to escape " in strings
    # Write the descriptive header for the attack tree
    #   NOTE: A basic 'name' and 'description' is provided      |   TODO: Allow for custom name and description
    #attacktreeFile.write('<attacktree:Model xmi:version="2.0" xmlns:xmi="http://www.omg.org/XMI" xmlns:attacktree="http://www.example.org/attacktree" name="generatedAttackTree" description="Attack tree generated based on provided AADL model that was parsed">\n')
    connection_graph_filename = '/tmp/connection_graph.graph'
    vertex_map_filename = '/tmp/vertex_map.json'
    edge_map_filename = '/tmp/edge_map.json'
    vuln_map_filename = '/tmp/vuln_map.json'
    entry_exit_map_filename = '/tmp/entry_exit_map.json'
    bus_map_filename = '/tmp/bus_map.json'
    # Variable for passing Entry / Exit map to Vulnerability mapping function
    entry_exit_map = {}         # Create basic empty map to hold the return from the imp2attacktree() function
    # Idiot check for expanding TAMSAT capabilities
    if detailDebugBit != 0:     # ~!~
        print("Check on Bare Tree Inputs:\n\tImplementation:\t{0}\n\tDevice:\t{1}\n\tSystem:\t{2}\n\tAoI:\t{3}\n\tConn. Filename:\t{4}\n\tNode Filename:\t{5}\n\tEdge Filename:\t{6}".format(implementationFile, deviceFile, systemFile, assetOfImportance, connection_graph_filename, vertex_map_filename, edge_map_filename))
    # Get the attacktree dictionary map from another function   |   NOTE: Passing the Asset of Importance variable HERE 
    bareAttackTree, connectionGraph, vertexMap, entry_exit_map = imp2attacktree(implementationFile, deviceFile, systemFile, assetOfImportance, connection_graph_filename, vertex_map_filename, edge_map_filename, entry_exit_map_filename, bus_map_filename)     # TODO: Add in the filename information for writing out the connectionMap, vertexMap, and edgeMap variables
    if debugBit != 0:
        print("[*] Bare bones attack tree:\n\t{0}".format(bareAttackTree))
    # Find out which element in the Node Information Map returned by imp2attacktree() is the rootNode Node Type
    aoi = ''
    for vertex in bareAttackTree:
        #print("Vertex:\t[ {0} ]".format(vertex))
        if bareAttackTree[vertex]["Node Type"] == "rootNode":
            #aoi = bareAttackTree[vertex]["Node Type"]
            aoi = vertex
    # Check that an AoI was found
    if aoi == '':
        print("[!] No 'rootNode' was found in the Node Information Map")
    # Create and print out the Vulnerability Map for the Known Vertex Points
    vulnMap, entry_exit_map = connectionGraph.create_and_output_vulnerabilities_map(vertexMap, vulnerabilitiesFile, vuln_map_filename, entry_exit_map)      # TODO: Pass in the entry_exit_nmap and add any entries that are caused by HARDWARE VULNERABILITIES
    # Write out the vulnMap to the vulnerability_map_filename
    with open(vuln_map_filename, 'w') as vulnerability_file:
        json.dump(vulnMap, vulnerability_file)
    # Write out the Entry / Exit map to the entry_exit_map_filename
    json.dump(entry_exit_map, open(entry_exit_map_filename, 'w'))           # Moved from elsewhere in TAMSAT (imp2attacktree) to here so that the vulnerability mapping funciton can add HARDWARE VULNERABLE ELEMENTS to the entry_exit_map
    # Print out the AADL XML attack tree file contents
    connectionGraph.graph_to_full_xml(aoi, bareAttackTree, vulnerabilitiesFile, outputFile)         # Pass the function the outputFile (what later is treated as the attacktreeFile)
    if debugBit != 0:
        print("[*] Completed generating the attacktree file")
    # TODO: NOTE: The rootNode and leaf node got switched...... FIX!!!  <---- Not sure if this is still relevant

# Function to search for matching elements within the vulnerabilites database and return any matches
# Inputs:
#       1) Elements dictionary (the things that will be searched for)
#       2) Vulnerabilities dictionary (the things that will be searched through for matches)
# Output: Dictionary of found elements to matching list
#       - Ex: elem: [match01, match02, .... , match0X]
def findVulnElements(elemDict, vulnsDict):
    if debugBit != 0:
        print("[*] Searching for known vulnerable elements")
    # Create empty dictionary that will contain the found known vulnerable elements
    foundElems = {}
    for elem in elemDict:
        matchList = []      # Create an empty list that will be used for storing matches
        for vulnElem in vulnsDict:
            # Search for a match one-by-one (brute force search) while ignoring case for terms
            match = re.search(elem, vulnElem, re.IGNORECASE)
            if match:       # Check if a match was found
                if debugBit != 0:
                    print("[+] Found {0} in provided vulnerabities dictionary; {0} matched to {1}".format(elem, match.group()))
                matchList.append(match.group())
            else:
                if debugBit != 0:
                    print("[-] Did not match {0} to {1}".format(elem, vulnElem))
        foundElems[elem] = matchList
            # TODO: Start growing the dictionary of found information so that it can be returned
    if debugBit != 0:
        print("[*] Returning dictionary of found vulnerable elements based on presented devices/systems")
    return foundElems

# Function for creating attacktree based on implementation definitions
# Input:    Feeding in all the dictionaries for their use in this function
#       connection_graph_filename       -       File to which the connectionGraph Object will be written to
#       vertex_map_filename             -       File to which the vertexMap dictionary will be written to
#       edge_map_filename               -       File to which the edgeMap dictionary will be written to
#       entry_exit_map_filename         -       File to which the entry_exit_map dictionary will be written to
#       bus_map_filename                -       File to which the bus_map dictionary will be written to         <---- Note: Not currently implemented within the model
# Ouptut:   Node list (root, sub, and edge/leaf nodes) that represents attack tree
#               -> Separate node list for each device/system in implementation dictionary
# TODO: Add in functionality to export the created MAPS into JSON files
def imp2attacktree(implementDict, deviceDict, systemDict, assetOfImportance, connection_graph_filename, vertex_map_filename, edge_map_filename, entry_exit_map_filename, bus_map_filename):
    if debugBit != 0:
        print("[*] Beginning to translate implementation into an attack tree")
    attackGraph = {}        # Generic blank map for constructing a Graph Class Object
    # Nota Bene: Using the empty attackGraph here with the Graph Class to make the starter connectionGraph
    connectionGraph = Graph(attackGraph)        # Graph Object for tracking the most basic structure of the AADL file; purpose is to generate the AADL XML attack tree file later on
    #edgeGraph = Graph(attackGraph)              # Graph Object for tracking the Graph Object edge information (e..g. data type, direction) within the connectionGraph
    #nodeMap = Graph(attackGraph)                # Graph Object for tracking information about all the vertex nodes that are part of the connectionGraph
    # NOTE: The Graph Object doesn't allow for the JSON dictionary insertion, THEREFORE doing a simple Python dictionary item
    vertexMap = {}
    edgeMap = create_edge_map()               # Function call to return the basic edgeMap (JSON Database)
    # Variable for tracking Entry/Exit/Access-way nodes
    entry_exit_map = {}
    # Tracking variables for entry/exit of the AADL model system implementation
    entry_points = []                           # Variable for tracking the Entry points found within the implementation (i.e. in, in out)
    exit_points = []                            # Variable for tracking the Exit points found within the implementation (i.e. out, in out)
    # Variable for tracking the bus elements within system definitions
    #   - TODO: Compare the types of these bus elements (e.g. ethernet, zigbee) to those required by device definitions (e.g. zigbee_bus requires bus access zigbee)
    #           in order to determine:
    #           i)      Use this bus map to determine additional vulnerabilities that can / could be introduced to the vulnerability_map
    #           ii)     Validity of connections between device elements (e.g. Zigbee connecting to Zigbee)
    #   - TODO: Add a check for just the deviceDict to see if the devices have any ADDITIONAL bus mediums that are defined but not used in the device model description
    system_bus_map = {}
    # This section of the code reads through the implementation dictionary to determine the connections between subcomponents
    for elem in implementDict:
        # Examine each implementation for each element in the dictionary
        for imp in implementDict[elem]:
            # Checking that a "Connections List" exists for given element's implementation
            if implementDict[elem][imp]["Connections List"]:       # Connection list exists
                # Variable for containing a list of the existing paths
                foundPaths = []
                seen_inout = False      # Variable pair for tracking in-out aspects of the model
                seen_inout_element  = False     # Variable pair for tracking in-out elements of the model
                if debugBit != 0:
                    print("{0} implementation of {1} has a connection map".format(imp, elem))
                    print("[+] Connection map found; translating into attack tree")
                # Interate through each connection within the "Connections List"
                for conn in implementDict[elem][imp]["Connections List"]:
                    translateMap = []   # Variable used to contain the found elements (device or system Entry/Exit) in the examined connection
                    hardwareMap = []    # Variable used to contain the found elements (bus connected Entry/Exit) in the examined connection
                    inoutPath = []     # Variable pair for tracking in-out aspects of the model
                    #inout_feature_paths = []
                    ## TODO: Add in here the logic for determining the connections between elements, what the original devices are, and add them
                    #       to the connectionsGraph Graph Class object
                    #   - NOTE: Do NOT need to pay attention to the [<]*-[>]* mapping, since the information for each device can be retrieved from 
                    #           the device and system information dictionaries
                    #   - TODO: Create functions for retrieving:
                    #           i)      Conncetion Map element from a connection (conn) item
                    #           ii)     Device Feature Direction for proper adding to the map
                    #           iii)    If the element being examined is a System Feature; and THEREFORE treated as an Entry/Exit point
                    connMap = implementDict[elem][imp]["Connections List"][conn]["Connection Map"]
                    # NOTE: The purpose of the mapBreakdown variable is that multiple elements could be defined within the Connection Map
                    #       and THEREFORE returns an unknown number of elements
                    if debugBit != 0:
                        print("[!] The connections being looked at:\t{0}".format(implementDict[elem][imp]["Connections List"][conn]["Connection Map"]))
                    # Note: The below may be causing the terms "bus access <bus element>" to merge the term "access" with the <bus element>
                    mapBreakdown = re.split('[<]*-[>]*', implementDict[elem][imp]["Connections List"][conn]["Connection Map"])
                    mapElements = len(mapBreakdown)         # Nota Bene: Can expect the same number of nodes to be added to graph as the # of map elements
                    if debugBit != 0:
                        print("[!] WARNING: If NOT using Python 3.6+ then dict will NOT maintain insertion order.... Code RELYS on this!!") # Now using ordered dicts

                    node_connection_dict = []       # Nota Bene: Expectation this list WILL maintain insertion order (required for Graph fidelity)
                    if detailDebugBit != 0:     # ~!~
                        print("[?] Map Breakdown\n\tMap Elements:\t{0}\n\tNo. Elements:\t{1}".format(mapBreakdown, mapElements))
                    ## Now to loop through the items in the mapBreakdown (in order) to add the connections to the Graph Map
                    #   - TODO: Add in directional connection between elements in the map (i.e. -> or <-)
                    ## Within this loop the goals of this function are to:
                    #   - Determine the component devices that make up each connection within the 'Connections List' pulled from the AADL model file
                    for connection_node in mapBreakdown:
                        if debugBit != 0:
                            print("[*]")
                            #add_edge_information_to_edge_map(edgeMap, edge_name, start_node, end_node, is_data, edge_data_type, is_bus, edge_bus_type, is_port, edge_direction, is_entry, is_exit, bus_required_access_flag)
                        ## TODO: Add the edgeMap details over the period of this for-loop
                        #       -> Most likely will need tracking variables that are then combined when the connection to the node_connection Graph Object
                        #           - edge_name:                    Name of the connection in the AADL Model file
                        #           - edge_data_type:               Data type of the connection/edge
                        #           - bus_required_access_flag:     Flag for Bus Required Access in the AADL Model file
                        edge_name = conn                    # Note: The connection/edge name should come from the 'conn' variable
                        edge_start_node = ''                     # Start Node that gets set later when the connection_node Graph Object gets updated
                        edge_end_node = ''                       # End Node that gets set later when the connection_node Graph Object gets updated
                        edge_is_data = None
                        edge_data_type = ''                 # Note: This will come from the 'Connection Type' field of the conn element     | TODO: Add in function to pull out the Connection Type information from implementDict 'Connection Type' field
                        edge_is_bus = None
                        edge_bus_type = ''
                        edge_is_port = None
                        edge_direction = ''
                        edge_is_entry = None
                        edge_is_exit = None
                        bus_required_access_flag = None     # Note: Setting default value for required access flag to None; useful for troubleshooting later
                        ## TODO: Create method for tracking the addition of graph nodes/vertex points
                        #       - Starting assumption that connections will ONLY be between TWO elements
                        #       - NOTE: Will need to figure out how to add them to the graph later
                        ## Look to see what the device type is and the Feature Direction of the device feature
                        # Check if the connection_node is a subcomponent feature (i.e. has a '.' in it) or is a feature of the system (i.e. no '.' in the name)
                        if '.' in connection_node:
                            if debugBit != 0:       # ~!~
                                print("\tExamining the subcomponent feature [ {0} ]".format(connection_node))
                            # Setup variables used for examination of AADL information (Subcomponent Name and Subcomponent Feature)
                            nodeBreakdown = re.split('\.+', connection_node)    # Two element array with [0] Subcomp name & [1] Subcomp connection name
                            subcomponent_name = nodeBreakdown[0]
                            subcomponent_feature = nodeBreakdown[1]
                            if debugBit != 0:       # ~!~
                                print("\tSubcomponent Name:\t\t{0}\n\tSubcomponent Feature:\t\t{1}".format(subcomponent_name, subcomponent_feature))
                            # Check that the subcomponent feature has the expected information (e.g. Subcomponent Type, Subcomponent Implementation)
                            match_subcomponent_type = find_subcomponent_type(implementDict, elem, imp, subcomponent_name)
                            match_subcomponent_implementation = find_subcomponent_implementation(implementDict, elem, imp, subcomponent_name)
                            # Check that the information queried came back as not None
                            if match_subcomponent_type is None:
                                print("[-] No model information found for the Subcomponent [ {0} ]".format(subcomponent_name))
                            elif match_subcomponent_implementation is None:
                                print("[-] No model information found for the Subcomponent Feature Implementation [ {0} ]".format(subcomponent_feature))
                            else:
                                if debugBit != 0:
                                    print("[+] Found the expected model information")
                            if debugBit != 0:       # ~!~
                                print("\tSubcomponent Type:\t\t{0}\n\tSubcomponent Implementation:\t{1}".format(match_subcomponent_type, match_subcomponent_implementation))
                            # Setup variables used for examination of the AADL Subcomponent Feature
                            subcomponent_element_breakdown = re.split('\.+', match_subcomponent_implementation)     # Failure is here
                            #   -> NOTE: If the above fails it could be that the subcomponent names are not being found correctly
                            subcomponent_element_name = subcomponent_element_breakdown[0]
                            subcomponent_element_implementation = subcomponent_element_breakdown[1]
                            if debugBit != 0:       # ~!~
                                print("\t\tName of the Element:\t\t{0}\n\t\tElement's Implementation:\t{1}".format(subcomponent_element_name, subcomponent_element_implementation))
                            ## Determine the Type, Direction, and Connection Type of the Subcomponent Element
                            # Check for the proper subcomponent information based the type of subcomponent (e.g. device, bus)
                            if match_subcomponent_type == "device":         # The subcomponent was founds to be a Type 'device'
                                # Search for matching Device Component from the device dictionary
                                match_device_element_feature_direction = find_device_element_feature_direction(deviceDict, subcomponent_feature, subcomponent_element_name)
                                match_device_element_feature_type = find_device_element_feature_type(deviceDict, subcomponent_feature, subcomponent_element_name)
                                match_device_element_feature_connection_type = find_device_element_feature_connection_type(deviceDict, subcomponent_feature, subcomponent_element_name)
                                # Tracking for Bus Required Access Flag later used in edgeMap
                                match_device_element_feature_bus_required_access_flag = find_device_element_feature_bus_required_access_flag(deviceDict, subcomponent_feature, subcomponent_element_name)
                                if match_device_element_feature_direction is None:
                                    print("[-] No model information found for the Subcomponent Device [ {0} ] Feature Direction".format(subcomponent_element_name))
                                elif match_device_element_feature_type is None:
                                    print("[-] No model information found for the Subcomponent Device [ {0} ] Feature Type".format(subcomponent_element_name))
                                elif match_device_element_feature_connection_type is None:
                                    print("[-] No model information found for the Subcomponent Device [ {0} ] Connection Type".format(subcomponent_element_name))
                                elif match_device_element_feature_bus_required_access_flag is None:
                                    print("[-] No model information found for the Subcomponent Device [ {0} ] Bus Required Access Flag".format(subcomponent_element_name))
                                else:
                                    if debugBit != 0:
                                        print("[+] Found the expected subcomponent device model information")
                                if debugBit != 0: 
                                    print("\t\t\tDevice Feature Direction:\t{0}\n\t\t\tDevice Feature Type:\t\t{1}\n\t\t\tConnection Type:\t\t{2}\n\t\t\tRequired Access:\t\t{3}".format(match_device_element_feature_direction, match_device_element_feature_type, match_device_element_feature_connection_type, match_device_element_feature_bus_required_access_flag))
                                ## TODO: Make use of the Direction, Type, and Connection Type to enrich the vertex / edge information
                                node_connection_dict.append(subcomponent_element_name)
                                # Add the bus required access flag to the edgeMap tracking variable
                                bus_required_access_flag = match_device_element_feature_bus_required_access_flag
                                if match_device_element_feature_connection_type == 'port':      # TODO: Expand this information building; will require additional expansion of the Database files TAMSAT makes from parsing AADL model files
                                    ## Add the device information into the node map Object nodeMap
                                    # First prepare the variables to add into the node map
                                    vertex_name = subcomponent_element_name
                                    is_port = True
                                    port_name = subcomponent_feature
                                    port_data_type = match_device_element_feature_type
                                    port_direction = match_device_element_feature_direction
                                    is_data = True      # TODO: Fix to search for correct information from AADL model; setting default expectation
                                    data_type = match_device_element_feature_type
                                    is_event = True     # TODO: Fix to search for correct information from AADL model; setting default expectation
                                    is_entry = "Unknown"    # TODO: Fix to search for correct information from AADL mode; setting to Unknown for later fixing / tracking    || Can come from variable tracking of lower code?
                                    is_exit = "Unknown"     # TODO: Fix to search for correct information from AADL mode; setting to Unknown for later fixing / tracking    ||  -> Maybe move this information grab into specific functions?
                                    # Call the function to add the vertex and informaiton into the node map
                                    add_vertex_port_to_node_map(vertexMap, vertex_name, is_port, port_name, port_data_type, port_direction, is_data, data_type, is_event, is_entry, is_exit)
                                    # Below this section of the if-statement is a check for data, port, event, and other edgeMap variables
                                    #   - TODO: Add in a check for the is_entry / is_exit variables for improving the edgeMap
                                    # Check the edge_is_data flag against the current ports' is_data flag
                                    edge_is_data = compare_bools_return_update(edge_is_data, is_data)
                                    edge_data_type = compare_data_type_return_update(edge_data_type, data_type)
                                    edge_is_port = compare_bools_return_update(edge_is_port, is_port)
                                    # TODO: Expand this to have marking of directional edges within the edgeMap
                                    edge_direction = compare_direction_return_update(edge_direction, port_direction)
                                ## TDOD: Add a bus match_device_element_feature_connection_type comparison
                                #   - Purpose is to ......... Known when a bus type feature connection appears??? Populate bus information into the edge_map; allow for integration into vulnerability_database
                                elif match_device_element_feature_connection_type == 'bus':
                                    print("\tLooking at Connection Type Bus\n\t\t[ {0} ]".format(match_device_element_feature_connection_type))
                                    # TODO: Update the edge_bus variables that are carried over into the edge_map; OR use this space to UPDATE the bus_map <--- IGNORE using the bus_map, just use the existing vertex_map
                                    #   - What information do I care about?
                                    #       - If the connection between elements is a bus connection
                                    #       - The connecting bus interface
                                    #       - The connecting system subcomponent 
                                    print("\tChecking Variables:\n\t\tSubcomponent Name:\t{0}\n\t\tSubcomponent Feature:\t{1}".format(subcomponent_element_name, subcomponent_feature))
                                    print("\t\t\tDevice Feature Direction:\t{0}\n\t\t\tDevice Feature Type:\t\t{1}\n\t\t\tConnection Type:\t\t{2}\n\t\t\tRequired Access:\t\t{3}".format(match_device_element_feature_direction, match_device_element_feature_type, match_device_element_feature_connection_type, match_device_element_feature_bus_required_access_flag))
                                    # NOTE: The above information comes out of the device_dictionary, related via the subcomponent_feature AND name of the element in the device dictionary
                                    #       (e.g. subcomponent 'ethernet_bus' of element 'server' in the device_dictionary)
                                    # Prepare the variables to add into the vertex map
                                    vertex_name = subcomponent_element_name
                                    is_bus = True
                                    bus_name = subcomponent_feature
                                    bus_type = match_device_element_feature_type
                                    bus_direction = match_device_element_feature_direction
                                    bus_required_flag = match_device_element_feature_bus_required_access_flag
                                    # Call the function to add the vertex and information into the node map
                                    add_vertex_bus_to_node_map(vertexMap, vertex_name, is_bus, bus_name, bus_type, bus_direction, bus_required_flag)
                                else:
                                    print("\tLooking at an Unknown Connection Type\n\t\t[ {0} ]".format(match_device_element_feature_connection_type))
                            else:
                                print("[-] TAMSAT does not know how to handle type [ {0} ] subcomponent element".format(match_subcomponent_type))
                            #matchDeviceType = next((deviceDict[subcomponent_item]["Features List"][item]["Feature Direction"] for item in deviceDict[subcomponent_item]["Features List"] if item == secondary_characteristic), False)
                        # Assumption is that if TAMSAT is not examining a 'device' then it must be a 'system'
                        else:
                            if debugBit != 1:       # ~!~
                                print("\tExamining the system feature [ {0} ]".format(connection_node))
                            # TODO: Add in analysis for system feature information for adding to the Graph Class object
                            #   - Goal: If we are looking at a system feature, then we want to know its Feature Direction, Feature Type, and Conncetion Type
                            #   - NOTE: Need to know the System element that the system feature belongs to
                            # TODO: Check if the feature being examined is a 'bus' element device; Issue is that the system subcomponent feature exists in the Implementation Dictionary, THEREFORE search there
                            #   - If there is a 'system feature', a 'system name', AND a 'system implementation' value THEN need to look in the Implementation Dictionary
                            #   -> For a 'bus' implementation need to grab: subcomponent type AND subcomponent implementation (e.g. bus AND ethernet)
                            # TODO: Check if the feature begin examined is part of a System Implementation or just the System Definition
                            #   -> NOTE: This is KEY when trying to determing the 'bus' connectivity mapping between elements
                            if debugBit != 0:
                                print("\tSystem Name:\t\t\t{0}\n\tSystem Implementation:\t\t{1}".format(elem, imp))
                            # Variable for tracking if looking for a system feature or implementation for later information; NOTE: Set as None for Default for debugging
                            search_for_system_implementation = None         # Maybe switch out for a bus checking variable / boolean
                            # Setup variables used for examination of the AADL System element
                            system_name = elem
                            system_feature = connection_node
                            # Preparing system variables; NOTE: Set to None as the Default for debug tracking
                            match_system_feature_implementation_subcomponent_type = None
                            match_system_feature_implementation_subcomponent_implementation = None
                            match_system_feature_direction = None
                            match_system_feature_type = None
                            match_system_feature_connection_type = None
                            #print("[?] Variable Checking:\n\tsystem_feature:\t\t{0}\n\tsystem_name\t\t{1}\n\tSystem Dictionary Find:\t{2}".format(system_feature, system_name, systemDict[system_name]["Features List"]))
                            # Check to see if the system element / feature being searched for would be in the system dictionary or implementation dictionary; NOTE: Check for system dictionary is checking its Features List for the given system name
                            if (system_feature != '') and (system_feature not in systemDict[system_name]["Features List"]):                # Checking that the system_feature is not empty (i.e. looking at a system subcomponent implementation)  <---- NOT a proper check... misses system feature
                                if detailDebugBit != 0:     # ~!~
                                    print("[!] Searching through the System Implementation Dictionary")         # Check proved that when TAMSAT searches for the 'internal_ethernet' subcomponent, it finds it in the right place
                                    print("\tElement:\t\t{0}\n\tImplementation:\t\t{1}\n\tConnection Node:\t{2}\nImplement Dictionary:\t{3}".format(elem, imp, connection_node, implementDict))
                                # Looking for implementation information
                                match_system_feature_implementation_subcomponent_type = find_subcomponent_type(implementDict, elem, imp, connection_node)
                                match_system_feature_implementation_subcomponent_implementation = find_subcomponent_implementation(implementDict, elem, imp, connection_node)
                                # Set the variable used for check which JSON dictionary to check
                                search_for_system_implementation = True
                                if debugBit != 0:
                                    # Testing print for figuring out the Ethernet problem
                                    print("\t[??] Testing:\n\tmatch_system_feature_implementation_subcomponent_type:\t{0}\n\tmatch_system_feature_implementation_subcomponent_implementation:\t{1}\n\tsearch_for_system_implementation:\t{2}".format(match_system_feature_implementation_subcomponent_type, match_system_feature_implementation_subcomponent_implementation, search_for_system_implementation))
                            else:           # NOTE: This should be the scenario where the system_feature exists within the systemDict AND be within the "Features List"
                                print("[!] Searching through the System Definition Dictionary") 
                                # Looking for system feature information
                                match_system_feature_direction = find_system_feature_direction(systemDict, system_name, system_feature)
                                match_system_feature_type = find_system_feature_type(systemDict, system_name, system_feature)
                                match_system_feature_connection_type = find_system_feature_connection_type(systemDict, system_name, system_feature)
                                # Set the variable used for check which JSON dictionary to check
                                search_for_system_implementation = False
                            # In the case of a system implementation subcomponents that are 'bus' (e.g. ethernet, zigbee) then there is no System Feature information (i.e. Direction, Type, or Connection Type)
                            # Check for System Feature information (i.e. Direction, Type, Connection Type)
                            if match_system_feature_direction is None:
                                print("[-] No model information found for the System Feature [ {0} ] - Searched System Feature Direction".format(system_feature))       # This would NOT exist for a simple bus definition
                            elif match_system_feature_type is None:
                                print("[-] No model information found for the System Feature [ {0} ] - Searched System Feature Type".format(system_feature))
                            elif match_system_feature_connection_type is None:
                                print("[-] No model information found for the System Feature [ {0} ] - Searched System Feature Connection Type".format(system_feature))
                            else:
                                if debugBit != 1:       # ~!~
                                    print("[+] Found the expected system model information - System Feature Definition")
                            # Check for System Implementation Feature information (i.e. Subcomponent Type, Subcomponent Implementation)
                            if match_system_feature_implementation_subcomponent_type is None:
                                print("[-] No model information found for the System Implementation Feature [ {0} ] - Searched System Implementation Subcomponent Type".format(system_feature))
                            elif match_system_feature_implementation_subcomponent_implementation is None:
                                print("[-] No model information found for the System Implementation Feature [ {0} ] - Searched System Implementation Subcomponent Implementation".format(system_feature))
                            else:
                                if debugBit != 1:       # ~!~
                                    print("[+] Found the expected system model information - System Feature Implementation Subcomponent")
                            # Debugging check on variables
                            if detailDebugBit != 0:       # ~!~
                                print("\t\tSystem Feature Direction:\t\t{0}\n\t\tSystem Feature Type:\t\t\t{1}\n\t\tConnection Type:\t\t\t{2}".format(match_system_feature_direction, match_system_feature_type, match_system_feature_connection_type))
                                print("\t\tSystem Feature Implementation Subcomponent Type:\t\t\t{0}\n\t\tSystem Feature Implementation Subcomponent Implementation:\t\t{1}".format(match_system_feature_implementation_subcomponent_type, match_system_feature_implementation_subcomponent_implementation))
                            # Idiot Testing ~!~
                            if detailDebugBit != 0:
                                print("[?] Variable Check:\tmatch_system_feature_direction:\t{0}\n\t\tType:\t{1}".format(match_system_feature_direction, type(match_system_feature_direction)))
                            if match_system_feature_direction is None:
                                if debugBit != 0:
                                    print("[!] Note: Might be dealing with a bus feature (system feature?)")
                            # TODO: Add checks for 'bus' and other component types
                            if detailDebugBit != 0:
                                print("[?] Larger Variable Check:\n\tSystem Name:\t\t\t\t{0}\n\tSystem Feature:\t\t\t\t{1}\n\tMatch System Feature Direction:\t\t{2}\n\tMatch Feature Type:\t\t\t{3}\n\tMatch System Feature Connection Type:\t{4}\n\tMatch System Feature Implementation Subcomponent Type:\t\t\t{5}\n\tMatch System Feature Implementation Subcomponent Implementation:\t{6}".format(system_name, system_feature, match_system_feature_direction, match_system_feature_type, match_system_feature_connection_type, match_system_feature_implementation_subcomponent_type, match_system_feature_implementation_subcomponent_implementation))
                                print("-----\t------ search_for_system_implementation\t:\t{0}\t-----\t-----".format(search_for_system_implementation))
                            # Check to see how the collected System Feature information should be processed
                            if not search_for_system_implementation:            # TAMSAT is NOT looking for System Implementation details
	                            # NOTE: The addition to the Graph connection depends on the Feature Direction of the System Feature
	                            ## TODO: Make use of the Direction, Type, and Connection Type to enrich the vertex / edge information
	                            # TODO: Add in alterations/fixes to the vertexMap and edgeMap based on the in/out/in out check below; NOTE: May need to watch out for entry existence before attempting to alter the information
	                            if ("in" in match_system_feature_direction) and ("out" in match_system_feature_direction):          # NOTE: This has errors when trying to deal with "type 'bool' is not iterable"  | Due to TAMSAT not knowing how to interpret 'bus' AADL
	                                # Scenario where the system feature acts as both an Entry and Exit point within the Graph
	                                if debugBit != 0:
	                                    print("System Feature is Entry/Exit")
	                                node_connection_dict.append("Access-way")           # ~!~ Might be where to introduce Entry/Exit/Access-way information into the (i) Edge Map and (ii) Entry Exit Map
	                            elif match_system_feature_direction == "in":
	                                # Scenario where the system feature acts as only an Entry point within the Graph
	                                if debugBit != 0:
	                                    print("System Feature is an Entry")
	                                node_connection_dict.append("Entry")
	                            elif match_system_feature_direction == "out":
	                                # Scenario where the system feature acts as only an Exit point within the Graph
	                                if debugBit != 0:
	                                    print("System Feature is an Exit")
	                                node_connection_dict.append("Exit")
	                            else:
	                                print("[-] ERROR: TAMSAT found a System Feature Direction that was unexpected [ {0} ] with Feature Direction [ {1} ]".format(system_feature, match_system_feature_direction))
	                            # TODO/NOTE: Currently using "Access-way" to represent nodes that are BOTH Entry & Exit points
	                            #print("[!!!!] Adding an ACCESS-WAY NODE")
	                            #node_connection_dict.append("Access-way")      # NOTE: This step is REQUIRED for the later entry_exit_map building later on in the process || Use this to build the entry_exit_map
                            else:                                               # TAMSAT is looking for System Implementation details (e.g. 'bus' element / component)
                                #print("Well.... shiiiiiit..... bus time")      # TODO: Add addition of bus connection edges to the edge map
                                # Set the neccesary variables that relate to 'bus' elements within the larger edgeMap
                                if match_system_feature_implementation_subcomponent_type == 'bus':
                                    edge_is_bus = True
                                    edge_bus_type = match_system_feature_implementation_subcomponent_implementation
                                else:
                                    print("Huh..... What is a bus that is not a bus-type")      # Currently getting triggered when TAMSAT is looking for a system feature that IS NOT a bus (which is part of the system implementation features; subcomponents)
                        ## Take the collected information and now create/add/update the Graph object with the Connection information
                        if detailDebugBit != 0:
                            print("[?] Node Connection List:\t{0}".format(node_connection_dict))
                        node_connection_dict_length = len(node_connection_dict)
                        if node_connection_dict_length == mapElements:
                            if detailDebugBit != 0:
                                print("[!] Should now be ready to add the Nodes into the Graph")
                                print("\tNode Connection Length:\t{0}\n\tMap Elements Length:\t{1}".format(node_connection_dict_length, mapElements))
                            ## TODO: Add the nodes and their vertex / edges to the Graph
                            #       - Cycle through the items in the node_connection_dict list
                            #       -> Basically want to do connectionGraph.add_edge({node_connection_dict[i-1], node_connection_dict[i]}) for 0 < i <= node_connection_dict_length
                            # Using the enumerate() function to iterate over the list of nodes from the connection map
                            for i, node in enumerate(node_connection_dict):
                                if detailDebugBit != 0:
                                    print("\tIndex:\t{0}\n\tNode:\t{1}".format(i, node))        # <--- NEED LOGIC to fix this shit
                                # Ignore the first index in the loop (avoids list boundry issue)
                                if i != 0:
                                    vertex_source = node_connection_dict[i-1]
                                    vertex_destination = node_connection_dict[i]
                                    # NOTE: Currently do NOT add to Entry/Exit/Access-way to the larger connectionGraph
                                    entry_exit_nodes = {"Entry", "Exit", "Access-way"}
                                    vertex_node = None
                                    vertex_connected = None
                                    if (vertex_source not in entry_exit_nodes) and (vertex_destination not in entry_exit_nodes):
                                        connectionGraph.add_edge({vertex_source, vertex_destination})
                                    else:
                                        if detailDebugBit != 0:
                                            print("[!] Avoiding adding vertexs [ {0} ] [ {1} ] to the connectionGraph".format(vertex_source, vertex_destination))
                                        # TODO: Turn the code below into a function for easier reading / edits down the line
                                        # Check to find which variable is the Entry/Exit/Access-way key
                                        if vertex_source not in entry_exit_nodes:
                                            if debugBit != 0:
                                                print("Vertex Destination is the Entry/Exit/Access-way Node:\t[ {0} ]".format(vertex_destination))
                                            vertex_node = vertex_destination
                                            vertex_connected = vertex_source
                                        elif vertex_destination not in entry_exit_nodes:
                                            if debugBit != 0:
                                                print("Vertex Source is the Entry/Exit/Access-way Nodes:\t[ {0} ]".format(vertex_source))
                                            vertex_node = vertex_source
                                            vertex_connected = vertex_destination
                                        else:
                                            print("[!] Something went horribly wrong!!..... This scenario should have been caught earlier")
                                            vertex_node = False
                                            vertex_connected = False
                                        # Next, check that the found Entry/Exit/Access-way key already exists (or not) in the larger entry_exit_map
                                        if (vertex_node == '') or (not vertex_node):
                                            print(".... Yup.... something is wrong")
                                        if vertex_node not in entry_exit_map:
                                            # Fix the missing Entry/Exit/Access-way issue
                                            entry_exit_map_entry = {
                                                    vertex_node : {}            # NOTE: Currently this seems to default to vertex_node == "Access-way"
                                                }
                                            entry_exit_map.update(entry_exit_map_entry)
                                        # Add the other connecting node to the corresponding entry_exit_map category (i.e. Entry, Exit, Access-way)
                                        neighbour_entry = {
                                                vertex_connected : {
                                                    "Leaf Node" : None             # NOTE: Setting a DEFAULT VALUE of NONE for the Leaf Node; TODO: Perform an update of this information down the road
                                                    }
                                                }
                                        entry_exit_map[vertex_node].update(neighbour_entry)
                                    # Set the start/end nodes for the edgeMap here as well
                                    edge_start_node = vertex_source
                                    edge_end_node = vertex_destination
                            # NOTE: This is where I should begin adding information to the edgeMap
                            # Add information for the edgeMap
                            add_edge_to_edge_map(edgeMap, edge_name)
                            # Add in the other information about the edges to the edgeMap
                            add_edge_information_to_edge_map(edgeMap, edge_name, edge_start_node, edge_end_node, edge_is_data, edge_data_type, edge_is_bus, edge_bus_type, edge_is_port, edge_direction, edge_is_entry, edge_is_exit, bus_required_access_flag)
                        elif node_connection_dict_length < mapElements:
                            if debugBit != 0:
                                print("[!] Still have to keep mapping nodes until done with all in this loop")
                # Now have to go through the found paths and construct the basic attacktree (BAREBONES ATTACK TREE)
                # TODO: Ask the user for what the asset of importance is
                #       Create a dictionary(???) that indicates each root, sub, and leaf node in the found paths
                if detailDebugBit != 0:
                    print("[?] This is what I have found for paths")
                    print(foundPaths)
                    print("[?] Checking on the information from the connectionGraph item")
                    connectionGraph.pretty_print()
                    """
                    print("[?] Second checking after merge with the foundPaths variable")
                    # NOTE: The for loop used below allows all foundPaths to be added to the Graph object, while also accounting
                    #       for the potential of duplicate paths within the foundPaths variable due to how add_edge() works
                    for subPath in foundPaths:
                        connectionGraph.add_edge(subPath)
                    connectionGraph.pretty_print()
                    """
                ### Now I have a working Graph object called 'connectionGraph'
                #       - Make sure to know entry_points, exit_points, and AoI (determined below)
                ## Next is to determine what is the Asset of Importance (AoI)
                foundAoi = 0        # Variable for tracking the Asset of Importance (AoI)
                #prevElem = ''
                #nextElem = ''
                #subNodeLevel = 0    # Variable for tracking the indent level of the subNodes    | NOTE: Will need to pair with total count @ end?
                #countVal = 0        # NOTE: ONLY update countVal if the rootNode has NOT been found; otherwise get error in ordering of root and leaves | MAYBE more messed up than that?? Could be that I "duoble updated" trackNodes list | NOTE: Could re-think and have higher value = leaf?
                # Variable that contains the AoI that will be searched for | Old default set to 'database'
                aoi = '' #'database'    # Will ask the user based on a preset list of items what the AoI should be | Right now set to default based on expected model
                # Create list of unique elements seen in nodes
                uniqueList = []
                if debugBit != 0:
                    print("[*] Creating a unique list of the vertecies within the AADL model\n\tVertices in Map:\t{0}".format(connectionGraph.all_vertices()))
                for vertex in connectionGraph.all_vertices():
                    if vertex not in {"Entry", "Exit", "Access-way"} and vertex not in uniqueList:
                        if debugBit != 0:
                            print("[?] Vertex is NOT Entry, Exit, or Access-way... it is [ {0} ]".format(vertex))
                        uniqueList.append(vertex)
                if detailDebugBit != 0:
                    print("[?] Check the appearance of uniqueList:\n\t\t{0}".format(uniqueList))
                    print("\tCheck the appearance of entry_exit_map:\n\t\t{0}".format(entry_exit_map))
                # Setting of the Asset of Importance for the attack tree
                if assetOfImportance == '':
                    # Ask the user what the Asset of Importance (aoi) will be
                    print('Which of the following items is the Asset of Importance? (e.g. the item being protected)')
                    for item in uniqueList:
                        print("\t{0}".format(item))
                    while aoi not in uniqueList:            # Keep looping until the user response is in the uniqueList of node items
                        aoi = input('Please enter the Asset of Importance: ')
                else:
                    if debugBit != 1:   # ~!~
                        print("\tChecking on Asset of Importance:\n\t\tassetOfImportance\t-\t{0}\n\t\tUnique Item List:\t{1}".format(assetOfImportance, uniqueList))
                    if assetOfImportance not in uniqueList:
                        for item in uniqueList:
                            print("\t{0}".format(item))
                        while aoi not in uniqueList:
                            aoi = input('Incorrect Asset of Importance presented.... Please enter the Asset of Importance: ')
                    else:
                        print("[+] Asset of Importance set to {0}".format(assetOfImportance))
                        aoi = assetOfImportance             # Automatically set the Asset of Importance
                ## Determine path Entry/Exit/Access-way to AoI
                #   - Do I even need to do the below?
                """
                entry_path = graph.find_path(entry_point, aoi)          # Find the path from the expected entry point to the AoI
                exit_path = graph.find_path(aoi, exit_point)            # Find the path from the AoI to the expected exit point
                access_path_in = graph.find_path(access-point, aoi)     # Find the path from the provided access point to the AoI
                access_path_out = graph.find_path(aoi, access-point)    # Find the path from the AoI to the provided access point
                ### NOTE: The paths above only matter if it is REQUIRED to determine the indentation for each point in the Graph object
                """
                #           compared to their path from the rootNode / AoI to each leaf (Entry/Exit/Access-point) subNode
                # Next, will create the nodeMap that will have nodeName, nodeType, and indentLevel
                #   - Nota Bene: This is where previously made list of connections is interpreted into a nodeMap, which then gets produced
                #       into the attackGraph
                nodeMap = {}
                # Use the Graph object function find_depths_from_node() to obtain an accurate nodeMap
                nodeMap = connectionGraph.find_depths_from_node(aoi)        # NOTE: This function also returns an "Access-way" node that is meant to represent an entry path for later attack
                # Set the 'Root Node' flag for the vertexMap nodes
                vertexMap[aoi]['Root Node'] = True
                attackGraph = nodeMap      # TODO: Change how this is done to allow for multiple attackGraphs to be generated???
                if detailDebugBit != 0:
                    print("[?] Check on the maps\n\tnodeMap:\t\t{0}\n\tattackGraph:\t\t{1}".format(nodeMap, attackGraph))
            else:       # No connections list
                if debugBit != 0:
                    print("{0} implementation of {1} does NOT have a connection map".format(imp, elem))
                    print("[-] Connection map not found; skipping attack tree translation")
    if debugBit != 0:
        print("[*] Returning mapped attack tree translated from implementation definition")
        print("[!] WARNING: If NOT using Python 3.6+ then dict will NOT maintain insertion order.... Code RELYS on this!!") # Now using ordered dicts
    connectionGraph.pretty_print()
    # Write out the JSON Mappings of Information out to files; e.g. connectionGraph, vertexMap, edgeMap
    if debugBit != 0:
        print("[*] Testing Conversion from Graph Object to JSON Object\n\tGraph Dict:\t{0}\n\tRegular Dict:\t{1}".format(connectionGraph._graph_dict, connectionGraph.__dict__))
    # Additional check for "extra" defined device buses that are NOT implemented for a defined connection
    if debugBit != 1:       # ~!~
        print("[*] Searching the device dictionary for additional device bus definitions that are not currently implemented in connections (e.g. UART, JTAG)")
    for device_element in deviceDict:
        print("\tExamining device [ {0} ] from the device dictionary".format(device_element))
        # Check each device's 'Features List' to search for SPECIFIC Bus elements
        for device_feature in deviceDict[device_element]['Features List']:
            print("\t\tExamining device feature [ {0} ] from the device [ {1} ] in the device dictionary".format(device_feature, device_element))
            # Check to see if a UART Bus exists for the examined device
            if device_feature == 'uart_bus':
                print("\t\tFound a UART Bus... Now check for specific devices to known if this is a new Entry / Exit attack path point (e.g. ASPEED server)")
                # NOTE: The specific search for ASPEED might be a bit much... BUT one can leverage this logic to include addition / mitigation of UART vulnerability based on knowledge / mitigations
                if device_element == 'aspeed_server':
                    print("\t\t\tConfirmed UART Bus is from the ASPEED server... Adding the additional Entry / Exit point to the entry_exit_map")
                    ## Add the ASPEED server to the Entry / Exit map; which represents the presense of a hardware-based vulnerability "Entry / Exit" to allow an additional attack path
                    # Set the vertex_node type (which matters for the Entry / Exit map); NOTE: "Access-way" is a non-directed form of path traversal
                    vertex_type = "Access-way"
                    ## This is the code that adds the given device_element to the Entry / Exit map
                    #       - Should happen AFTER the decision logic determines that the current  `hardware_access_vulns' vulnerability
                    # Add the new HARDWARE VULNERABLE ELEMENT to the Entry / Exit map
                    if vertex_type not in entry_exit_map:
                        # Fix the missing Entry/Exit/Access-way issue
                        entry_exit_map_entry = {
                            vertex_type : {}
                            }
                        entry_exit_map.update(entry_exit_map_entry)
                    # Add the other connecting node to the corresponding entry_exit_map category (i.e. Entry, Exit, Access-way)
                    # NOTE: The below should only happen in SPECIFIC scenarios... (e.g. ASPEED server)
                    neighbour_entry = {
                        vertex : {
                            "Leaf Node" : None             # NOTE: Setting a DEFAULT VALUE of NONE for the Leaf Node; TODO: Perform an update of this information down the road
                            }
                        }
                    print("[?] Testing new entry to entry_exit_map\n\tMap:\t{0}\n\tEntry:\t{1}".format(entry_exit_map, neighbour_entry))
                    entry_exit_map[vertex_node].update(neighbour_entry)
                    print("[?] Testing for updated entry_exit_map\n\tMap:\t{0}".format(entry_exit_map))
    # TODO: Fix issue of multiple nodes within the connection map; should only have a SINGLE instance of each node in the connectionGraph
    #   - NOTE: Use of .__dict__ since ALL?? Python Objects has a dictionary format which stores the object's attributes
    json.dump(connectionGraph._graph_dict, open(connection_graph_filename, 'w'))        # Write out the connectionGraph to the connection_graph_filename (which is provided to the function)   
    json.dump(vertexMap, open(vertex_map_filename, 'w'))                    # Write out the vertexMap to the vertex_map_filename (which is provided to the function)
    json.dump(edgeMap, open(edge_map_filename, 'w'))                        # Write out the edgeMap to the edge_map_filename (which is provided to the function)
    #json.dump(entry_exit_map, open(entry_exit_map_filename, 'w'))           # TODO: export this map and then write the file later on in the vulnerability map process
    if detailDebugBit != 0:
        print("[?] Function Check for Generated Information\n\tvertexMap:\t{0}\n\tedgeMap:\t{1}".format(vertexMap, edgeMap))
    return attackGraph, connectionGraph, vertexMap, entry_exit_map          # Added export of the entry_exit_map

# Function for returning an entry that matches a desired element from a specific dictionary (TODO)
def findElement():
    print("[*] About to find a provided element in a provided dictionary")
    
    print("[*] Returning the found element")
    return foundElement

# Function for finding a subcomponent within an implementation
# next((implements[elem][imp]["Subcomponents List"][item]["Subcomponent Implementation"] for item in implements[elem][imp]["Subcomponents List"] if item == nodeBreakdown[0]), False)
#   ^ Returns the Subcomponent Implementation for a subcomponent matching the string in nodeBreakdown[0], OTHERWISE returns False (unable to find)
# Function for returnging system with same name as current implementation's system
# next((item for item in systems if item == elem), False)
#   -> Returns 'databaseNetwork'
# Function for returning a system name that contains a feature by the name contained in 'testNode'
# testNode = "user_response"
# next((item for item in systems if testNode in systems[item]["Features List"]), False)
#   ^ Returns the system name that contains the feature "user_response"
# To return the direction of this found system's feature do:
# next((systems[item]["Features List"][testNode]["Feature Direction"] for item in systems if testNode in systems[item]["Features List"]), False)

# Function for finding the entry/exit points in a device/system definition (NOTE: NOT MADE FOR IMPLEMENTATIONS)
# Input: dictionary containing devices/systems to be examined
# Output: dictionary containing map of:
#       elementName: {
#           "entry": [List of Entry Features]
#           "exit": [List of Exit Features]
#           }
# NOTE: Perhaps not a needed function @ this time
def findEntryExit(elemDict):        # NOTE: Make so that it creates a "block" view of the elements?
    if debugBit != 0:
        print("[*] Locating entry and exit points")
    for elem in elemDict:
        # Check if there is a 'Flows List' to perform sanity check on flow and feature direction settings
        if elemDict[elem]["Flows List"]:
            if debugBit != 0:
                print("[+] Element contains a Flows List")
            for flowItem in elemDict[elem]["Flows List"]:
                matchFeature = elemDict[elem]["Flows List"][flowItem]["Flow Feature"]
                if debugBit != 0:
                    print("[*] Comparing Flow and Feature direcitons")
                flowDir = elemDict[elem]["Flows List"][flowItem]["Flow Direction"]
                featureDir = elemDict[elem]["Features List"][matchFeature]["Feature Direction"]
                if debugBit != 0:
                    print("[*] Element: {0}\n\tFeature: {3}\n\tFlow Direction: {1}\n\tFeature Direction: {2}".format(elem, flowDir, featureDir, matchFeature))
                # Perform sanity check on direction information
        else:       # There is an empty 'Flows List'
            if debugBit != 0:
                print("[-] Element does NOT contain a Flows List")
            for featureItem in elemDict[elem]["Features List"]:
                featureDir = elemDict[elem]["Features List"][featureItem]["Feature Direction"]
                if debugBit != 0:
                    print("[*] Element: {0}\n\tFeature: {1}\n\tFeature Direction: {2}".format(elem, featureDir))
    if debugBit != 0:
        print("[*] Returning the found entry and exit points")

# Function to write the JSON data to a file
def saveJSON(jsonData, saveFile):
    if debugBit != 0:
        print("[!] Saving JSON data to the file [{0}]....".format(str(saveFile)))
    with open(saveFile, 'w+') as jsonFile:
        json.dump(jsonData, saveFile, indent=4)

# Function for reading JSON data from a file
def readJSON(jsonFile):
    jsonData = {}
    if debugBit != 0:
        print("[*] Reading JSON data from file [{0}]....".format(str(jsonFile)))
    with open(jsonFile, 'r') as infile:
        jsonData = json.load(infile)
    return jsonData

# Function for generating a test vulnerability database
#   NOTE: This database will contain a list of device & system elements and their corresponding vulnerabilities
#       -> TODO: Eventually need a check to ensure that generated attack trees only have APPROPRIATE vulnerabilities
#           => NOTE: Ask the user for version numbers and additional information for determining appropriate vulns
def genVulnDb(jsonFile):
    if debugBit != 0:
        print("[*] Creating a database file of vulnerabilities")
    # Writing out by hand the example vulnerabilites file
    # TODO: Will need a method for identifying multiple versions to a single element (e.g. database, db, db server, database server to 'Database Server')
    #   -> TODO: Will also need to account for not caring about cases (captial or lowercase)
    vulnsFile = {                       
            "Database Server": {
                "Vulnerability List": {     # Vulnerabilities are listed in the form 'name': 'description'
                    "CVE-2017-7494": "Database credential in clear in webserver code"
                    }
                },
            "Firewall": {
                "Vulnerability List": {
                    "CVE-2018-0009": "Firewall bypass",
                    "CVE-2018-0020": "Denial of Service vulnerability condition"
                    }
                },
            "MySQL Server": {
                "Vulnerability List": {
                    "CVE-2014-0001": "Buffer overflow leading to Denial of Service Execute Code Overflow"
                    }
                },
            "MongoDB Server": {
                "Vulnerability List": {
                    "CVE-2013-3969": "Denial of Service to possible arbitrary code execution"
                    }
                },
            "CouchDB Server": {
                "Vulnerability List": {
                    "CVE-2018-11769": "Code execution and privilege bypass"
                    }
                }
            }
    # Generate the vulnerability database file
    with open(jsonFile, 'w+') as outfile:          # <----- Change into taking the provided vulnerability database location
        json.dump(vulnsFile, outfile, indent=4)
    # NOTE: Do I also need this to export the vulnerability file???
    return vulnsFile        # Returning just incase useful for prelim debugging

# TODO: Need a dictionary of things with known vulnerabilities

# Function for performing test of Model-2-Attacktree
def model2attacktree():
    fileLines = readFile('testFiles/testFirewall.aadl')
    devices, systems, implements, assetOfImportance = parseContent(fileLines)
    outputFile = "test.attacktree"
    testVulns = genVulnDb("vulns.json")
    generateAttackTree(devices, systems, implements, testVulns, outputFile)
    if debugBit != 0:
        print("----------------------------------------")
    #imp2attacktree(implements, devices, systems)

# Function for performing user-defined selection of potential vulnerability database
def user_defined_model2attacktree(modelFile, vulnFile, attacktreeFile):
    fileLines = readFile(modelFile)
    devices, systems, implements, assetOfImportance = parseContent(fileLines)
    outputFile = attacktreeFile
    testVulns = genVulnDb(vulnFile)
    generateAttackTree(devices, systems, implements, testVulns, outputFile)
    if debugBit != 0:
        print("----------------------------------------")

# Function for performing user-interaction lead selection of potential vulnerability database
def user_request_model2attacktree(modelFile, attacktreeFile):
    fileLines = readFile(modelFile)
    devices, systems, implements, assetOfImportance = parseContent(fileLines)
    outputFile = attacktreeFile
    ## User interaction loop 
    # Directory search for .json$ files
    database_list = []
    database_pattern = "*.json*"
    for root, dirs, files in os.walk("./Database/", topdown=False):
        for filename in fnmatch.filter(files, pattern):
            database_list.append(filename)
    # Present the array of databases to user
    for item in database_list:
        print("\t{0}".format(item))
    # Have user choose a database   |   NOTE: Don't forget the idiot check that the 
    while vuln_database not in database_list:
        vuln_database = input('Please select the Vulnerability Database to use: ')
    vuln_file = "./Database/{0}".format(vuln_database)
    testVulns = genVulnDb(vuln_file)
    generateAttackTree(devices, systems, implements, testVulns, outputFile)
    if debugBit != 0:
        print("----------------------------------------")

# Function for deciding on a vulnerabilities database based on user input
def userChooseVulnDb(searchPath):
    print("[*] Having the user determine which vulnerabilities database should be used")
    # Grabbing the list of filenames (assumed to be databases) from the provided searchPath
    dirpath, dirnames, filenames = next(walk(searchPath), (None, None, []))
    # Setup the user decided vulnerabiliy datbase variable
    userVulnDb = ''
    print("[+] User has selected database {0} as the vulnerabilites database to be used".format(userVulnDb))

# Function for Generating the Edges of a Graph
def generate_edges(graph):
    edges = []
    for node in graph:
            for neighbour in graph[node]:
                    edges.append({node, neighbour})
    return edges

# Function for Finding Isolated Nodes within a Graph
def find_isolated_nodes(graph):
    """ Returns set of isolated nodes """
    isolated = set()
    for node in graph:
            if not graph[node]:
                    isolated.add(node)
    return isolated

# Function for Identifying Viable Entry and Exit Graph Paths
#   - Basically compares that the last item in the Entry list (i.e. AoI) is the first
#       item in the Exit list (i.e. AoI)
def check__entry_exit_paths(entry_path, exit_path):
    print("[*] Comparing Entry and Exit paths for viability together (i.e. the AoI items are the same)")
    entry_aoi = entry_path[-1]
    exit_aoi = exit_path[0]
    if entry_aoi == exit_aoi:
        print("[+] Assets of Importance (AoI) match!")
        # TODO: Return the complete path??? Or make a SEPARATE FUNCTION (???)
    else:
        print("[-] Assets of Importance (AoI) do NOT match....")

# Function for taking an AADL model file and outputting the generated attack tree WHEN PROVIDED A SPECIFIC USER DEFINED Asset of Importance
def userProvided_assetOfImportance(inputFile, outputFile, assetOfImportance):
    print("[*] Beginning TAMSAT.....")
    fileLines = readFile(inputFile)
    devices, systems, implements, ignoreMe_assetOfImportance = parseContent(fileLines)      # Note: Troubleshooting 'bus access' issue; need to fix problem here when the information files are being created
    # Check that the expected vulnerability database exists
    #   TODO: Add in database selection to allow for specific use of vulnerability databases for attack tree generation
    vulnDbLocation = "Database/vulnsDb.json"        #   Where to add in request from the user which database to use; could just search the directory and pick one.  Then have code replace the ``vulnsDb.json'' file
    # TODO: Add in a database for 'Bus' / Hardware specific vulnerabilities
    if os.path.exists(vulnDbLocation):
        if debugBit != 0:
            print("[+] Vulnerability Database Exists")
        #testVulns = open(vulnDbLocation, 'r')      # Rewrite so that it opens the file and returns the contents ~!~
        with open(vulnDbLocation, 'r') as read_file:
            testVulns = json.load(read_file)
    else:
        print("[-] Vulnerability Database Not Found..... Generating....")
        testVulns = genVulnDb(vulnDbLocation)
        # Works, but NOT WORKS when relying on an existing database
    generateAttackTree(devices, systems, implements, testVulns, outputFile, assetOfImportance)
    print("[*] Completed TAMSAT!")

# Function for taking an AADL model file and outputting the generated attack tree when assuming that the Asset of Importance is encoded within the inputFile
def main(inputFile, outputFile):
    print("[*] Beginning TAMSAT.....")
    fileLines = readFile(inputFile)
    devices, systems, implements, assetOfImportance = parseContent(fileLines)      # Note: Troubleshooting 'bus access' issue; need to fix problem here when the information files are being created
    # Check that the expected vulnerability database exists
    #   TODO: Add in database selection to allow for specific use of vulnerability databases for attack tree generation
    vulnDbLocation = "Database/vulnsDb.json"        #   Where to add in request from the user which database to use; could just search the directory and pick one.  Then have code replace the ``vulnsDb.json'' file
    # TODO: Add in a database for 'Bus' / Hardware specific vulnerabilities
    if os.path.exists(vulnDbLocation):
        if debugBit != 0:
            print("[+] Vulnerability Database Exists")
        #testVulns = open(vulnDbLocation, 'r')      # Rewrite so that it opens the file and returns the contents ~!~
        with open(vulnDbLocation, 'r') as read_file:
            testVulns = json.load(read_file)
    else:
        print("[-] Vulnerability Database Not Found..... Generating....")
        testVulns = genVulnDb(vulnDbLocation)
        # Works, but NOT WORKS when relying on an existing database
    generateAttackTree(devices, systems, implements, testVulns, outputFile, assetOfImportance)
    print("[*] Completed TAMSAT!")

# Function that allows this script to be imported without automatically running the main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate an attack tree from a provided AADL model file.')
    # Add inputs to the function
    parser.add_argument("inputModel", help="Path and name of the AADL model file")
    parser.add_argument("outputFile", help="Path and name of the generated attack tree file")
    parser.add_argument("--assetOfImportance", help="Asset of Interest (AoI) for the generated attack tree - Note: Optional depending on encoding within inputModel")
    parser.add_argument("-v", "--verbose", action="store_true")
    # Grab the arugments passed to the file
    args = parser.parse_args()
    #print("Args Parsed:\t{0}".format(args))
    parser.parse_args()
    print("[?] Verbosity Level: {0}".format(args.verbose))
    debugBit = args.verbose
    if args.assetOfImportance is not None:
        userProvided_assetOfImportance(args.inputModel, args.outputFile, args.assetOfImportance)
    else:
        main(args.inputModel, args.outputFile)
