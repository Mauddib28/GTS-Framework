#!/usr/bin/env python

'''
 The purpose of this function is to combine the security risk calculation and CVSS score look-up

 Author:        Paul A. Wortman
 Last Edit:     3/24/2022
'''

### Notes / Additions to the Code
#
#   Adding the Graph Class Object to SMART combineScript.py file
# 
# TODO:
#   [x] Add flag for identifying when SMART reads from an XML file versus a Graph Object
#   [x] Determine the attack paths to evaluate with SMART
#   [x] Confirm validity of the given/found attack paths
#   [x] Check found paths against the expected AADL model attack paths
#       [x] Determine logic for how variety of paths are determined
#   [x] Teach SMART how to identify Entry / Exit / Access-way nodes
#       [ ] Teach SMART to "remove" these specialty nodes from the evaluation as desired (e.g. if no CVE / Ps returned)
#   [ ] SMART reads from the Data Type database to associated Data Type / Protocols to any found Entry / Exit / Access-way nodes
#   [x] Teach SMART to import in provided Graph Object from TAMSAT
#
# Note: Commented out the 3D graphing library import and associated code
#
# DREAM ACHEIVED... Fully operational framework
###

'''
 Imports for script
'''
import Calculation.securityRisk     # Import of Security Risk calcuation capabilities
import APILearning.cveGrab          # Import of CVE API for pulling down CVE information from online sources    | OLD VERSION
import XMLParsing.xmlParsing        # Import of parsing tools for XML
import itertools
import Database.ioDatabase          # Import of tools for interacting with SMART JSON database
import numpy as np                  # Imported for creating a range of values
import argparse                     # Imported for parsing of user input/flags
# Added for performing 3D graphing
#from mpl_toolkits.mplot3d import Axes3D
#import matplotlib.pyplot as plt
# Fix for CVE grabbing
import Standards.cveGrab            # Replacement for APILearning.cveGrab function
from Standards.cveGrab import nvdDict   # Import the CVE JSON dictionary from the Standards/cveGrab.py script
from Standards.cveGrab import getCVEyear    # Import the function for returning the associated year to a provided CVE
from Standards.cveGrab import getJSON   # Import the JSON reading function from the Standards/cveGrab.py script
# Pretty Print xml etree objects
#from xml.etree.ElementTree import tostring      # Import tostring() function for etree xml
from lxml import etree                  # Import etree for tostring() function
# Import of JSON for reading in nodeMap, vertexMap, edgeMap style information
import json

'''
 Global Variables
'''
debugBit = 0
detailDebugBit = 0
#cveJSONlocation = "./Standards/"        # Note: Do NOT need this since the call to getJSON() includes the ./Standards/ sub-directory in the path

'''
 Class Definitions
'''

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
            if x in self._graph_dict:
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

    # Internal Class Function for Finding the CVEs relating to a Path between Two Nodes within the Graph
    # Input: Include normal pathing + the vulnerability map
    # Output: Path of Node and Path of CVEs; both are LEAF-to-ROOT order
    def find_path_cves(self, start_vertex, end_vertex, vulnerability_map, vuln_path=None):
        """ find a path from start_vertex to end_vertex 
            in graph """
        if vuln_path == None:
            vuln_path = []
        graph = self._graph_dict
        if detailDebugBit != 1:     # ~!~
            print("[?] Variable Check:\n\tvuln_path:\t{0}\n\tvuln_map:\t{1}\n\tstart_vertex:\t{2}".format(vuln_path, vulnerability_map, start_vertex))
        # Add the associated CVEs to the first node in the path
        vuln_path = vuln_path + [vulnerability_map[start_vertex]["Vulnerability List"]]
        if start_vertex == end_vertex:
            return vuln_path
        if start_vertex not in graph:
            return None
        for vertex in graph[start_vertex]:      # TODO: Add a check to skip Entry, Exit, Acess-wau points
            if vertex not in vuln_path:
                extended_path = self.find_path_cves(vertex, 
                                               end_vertex, vulnerability_map, 
                                               vuln_path)
                if extended_path: 
                    return extended_path
        return None

    # Function to find and return an inner attack path combination set
    # Input: root of the tree
    # Output: List of node names for different attack path combinations based on the root and found leaf nodes
    # TODO: Add the entry_exit_map file OR structure to this function
    def find_attack_paths_node_names(self, root, vulnMap, entry_exit_map=None, pathing_switch=None):
        print("[*] Finding the Attack Paths and Nodes Nodes")
        print("[?] Variable check:\n\tRoot:\t\t\t{0}\n\tVuln Map:\t\t{1}\n\tEntry/Exit Map:\t\t{2}\n\tPathing Switch:\t{3}".format(root, vulnMap, entry_exit_map, pathing_switch))
        leaf_nodes = self.find_leaf_nodes(root)
        pathing_switch = 0          # 0 = BruteForce, 1 = Set Path, 2 = Constraint Path
        # TODO: Use the leaf_nodes returned to update the entry_exit_map
        #   - TODO: In the event of pathing switch '1', then use the entry_exit_map to follow the specific AADL Model Entry/Exit/Access-way nodes found from TAMSAT
        if not entry_exit_map:              # No entry_exit_map was passed
            print("[-] No entry/exit map provided.... Assuming BruteForce calculation")
            pathing_switch = 0
        else:
            print("[+] Entry/Exit map provided! Assuming Path Directed calculation")
            pathing_switch = 1
        # TODO: Have a check here if looking for a (i) bruteforce, (ii) set path, (iii) constraint pathed attacks
        if pathing_switch == 0:
            print("[*] Producing a BruteForce attack path based on found LEAF nodes and performing Cartesian Product (?)")
            attack_paths_nodes, attack_paths_cves = self.return_leaf_to_root_inner_attack_path_combinations(root, leaf_nodes, vulnMap)          # NOTE: This is the call for "BruteForce" path finding
            return attack_paths_nodes, attack_paths_cves
        # Set path scenario
        elif pathing_switch == 1:
            print("[*] Producing a Path Directed attack path based on.....")
            # Create variable array that will contains the "New" LEAF nodes to be used in evaluation
            new_leaf_nodes = []
            # Check to see if SMART should (i) BruteForce solutions based on Entry/Exit nodes OR (ii) only produce solutions for a SPECIFIC SET of attack paths
            # TODO: Create a function that:
            #   i)      Walks through the entry_exit_map to find any existing Entry/Exit/Access-way nodes
            #   ii)     Updates the contents of the entry_exit_map to show which nodes are LEAF nodes; Not important.... but more a full circle of its original purpose
            #   iii)    Generates a new "leaf_nodes" array that contains all the correct Entry/Exit locations
            # TODO: Perform update of the "Leaf Node" information within the entry_exit_map
            #   - NOTE: Complication here..... 
            #for leaf_node in leaf_nodes:
                #try:
                #    entry_exit_map
            ## Brute Force evaluation of the Path Directed attack paths generation
            for entry_exit in entry_exit_map:
                if entry_exit == "Entry":
                    # Do the Entry Point Stuff
                    # TODO: Write a function for performing the "Leaf Node" update (makes it easier to call and cleaner code)
                    print("[*] Examining the Entry entries")
                    for item in entry_exit_map[entry_exit]:
                        print("\tItem entry:\t{0}".format(item))
                        entry_exit_map = update_entry_exit_map_entry_leaf_node_flags(entry_exit_map, entry_exit, leaf_nodes)
                        # Add the entry to the new_leaf_nodes array
                        new_leaf_nodes.append(item)
                elif entry_exit == "Exit":
                    # Do the Exit Point Stuff
                    print("[*] Examining the Exit entries")
                    for item in entry_exit_map[entry_exit]:
                        print("\tItem entry:\t{0}".format(item))
                        entry_exit_map = update_entry_exit_map_entry_leaf_node_flags(entry_exit_map, entry_exit, leaf_nodes)
                        # Add the entry to the new_leaf_nodes array
                        new_leaf_nodes.append(item)
                elif entry_exit == "Access-way":
                    # Do the Access-way Point Stuff
                    print("[*] Examining the Access-way entries")
                    for item in entry_exit_map[entry_exit]:
                        print("\tItem entry:\t{0}".format(item))
                        entry_exit_map = update_entry_exit_map_entry_leaf_node_flags(entry_exit_map, entry_exit, leaf_nodes)
                        '''
                        # Perform the update
                        if item in leaf_nodes:
                            entry_exit_map[entry_exit][item]["Leaf Node"] = True
                        else:
                            entry_exit_map[entry_exit][item]["Leaf Node"] = False
                        '''
                        # Add the entry to the new_leaf_nodes array
                        new_leaf_nodes.append(item)
                print("[*] Producing a BruteForce attack path based on Path Directed LEAF nodes and performing Cartesian Product (?)")
                if detailDebugBit != 0:
                    print("[?] Variable check:\n\tNew Leaf Nodes:\t{0}".format(new_leaf_nodes))
                attack_paths_nodes, attack_paths_cves = self.return_leaf_to_root_inner_attack_path_combinations(root, new_leaf_nodes, vulnMap)          # NOTE: This is the call for "BruteForce" path finding
            ## TODO: Add in a check for performing a "set path" evaluation
            #   - Set where the entry points for the paths will be
            #   - Set where the exit points for the paths will be
            # NOTE: MAY need to make a new variant of the 'return_leaf_to_root_inner_attack_path_combinations()' function which allows for a SET PATH to be provided/decided upon
        ## TODO: Add in the CONSTRAINT PATHED ATTACK logic for additional evaluation functionality
        else:
            print("[-] ERROR: Unknown pathing_switch value.... Unable to produce attack path nodes and attack path cves")
        try:
            print("[?] Data Check:\n\tRoot Node:\t\t{0}\n\tLeaf Nodes:\t\t{1}\n\tAttack Path Nodes:\t{2}\n\tAttack Path CVEs:\t{3}".format(root, leaf_nodes, attack_paths_nodes, attack_paths_cves))
            print("[?] Variable Change Check:\n\tEntry/Exit Map:\t{0}".format(entry_exit_map))
        except:
            print("[-] ERROR: Not all data has been prepared..... FIGURE OUT THIS PROBLEM!!!")      # <---- Currently because once the function enters the pathing_switch == 1 area, the attack_paths_nodes|cves have NOT been generated yet
        return attack_paths_nodes, attack_paths_cves

    # Function to return all the leaves of the current graph based on a root node
    # Input: root of the tree
    # Output: List of Attack Paths
    def find_leaf_nodes(self, root):
        leaf_nodes = self.depth_first_search(root) 
        return leaf_nodes
        
    # Function to return a list of the potential attack path combinations for a given graph
    #   -> NOTA BENE: The return of this function is equivalent to the Inner Attack Path Combination Set
    # Input:                
    #       Root    -   Root of the tree to be traversed for attack path combination set
    #       Leaves  -   List of Leaf Nodes within the Root Node oriented attack tree
    # Output: Inner Attack Path Combination Set; a list of the potential attack path combinations in sets relating to the graph nodes
    def return_leaf_to_root_inner_attack_path_combinations(self, root, leaf_nodes, vulnMap):
        ## Testing Finding All the Leaf-to-Root Attack Paths
        #leaf_nodes = graph.depth_first_search('Database')
        #root = AoI             
        attack_paths = []
        vuln_paths = []
        for leaf in leaf_nodes:                                                           
            print("[*] Checking path from LEAF [ {0} ] to ROOT [ {1} ]".format(leaf, root))
            # NOTE: The attack_paths variable being constructred here is the Inner Attack Path Combination Set                                                                                          
            attack_paths.append(self.find_path(leaf, root))                                         
            # NOTE: Also produce the vulnerabilities list being constructured in the same Inner Attack Path Combination Set format
            vuln_paths.append(self.find_path_cves(leaf, root, vulnMap))
        print("[+] End check on attack_paths variable:\n\tattack_paths:\t\t{0}\n\tattack_cves:\t\t{1}".format(attack_paths, vuln_paths))
        return attack_paths, vuln_paths

    # Function to print a Depth First Search of the graph
    # Input: root of DFS being performed
    # Output: List of leaf nodes
    def depth_first_search(self, root):
        # Create the list used for DFS tracking
        visited, queue = [], []     # Both set to initially empty
        leaf_nodes = []             # Array of leaf nodes found
        # Variable used for tracking LEAF nodes in the Graph
        #leaf_node_flag = False
        # Get the list of adjacent vertex points around the root node
        neighbour_nodes = self._graph_dict[root]
        # Add root node to visited
        visited.append(root)
        # For each sub node call the recursive search with the visited and queue lists
        for vertex_node in neighbour_nodes:
            # Add nieghbours to queue
            queue.append(vertex_node)
            # Call the dfs_recusive_search function with the necessary variables and update the visited and queue graph objects
            visited, queue, leaf_nodes = self.dfs_recursive_search(vertex_node, visited, queue, leaf_nodes)
            # Remove the node from the queue list since the recursion has been called
            queue.remove(vertex_node)
        # End of the DFS function
        print("[+] Completed Depth First Search")
        if detailDebugBit != 0:
            print("\tVariable Dump:\n\t\tVisited:\t{0}\n\t\tQueue:\t\t{1}\n\t\tLeaf Nodes:\t{2}".format(visited, queue, leaf_nodes))
        return leaf_nodes

    # Function for performing the Depth First Search Recursion on the graph
    def dfs_recursive_search(self, root, visited, queue, leaf_nodes):
        # Add the current root node to the visited list
        visited.append(root)
        # Idiot check for a LEAF node       ||      Ideally want to know if there are NO nieghbours that are unvisited; then probably hit a LEAF
        different_nodes = [node for node in self._graph_dict[root] if node not in visited]
        # Check if there are different_nodes
        if different_nodes:         # different_nodes is empty
            if debugBit != 0:
                print("[+] There is overlap BUT some differences")
        else:
            if debugBit != 0:
                print("[!] There are NO NEW nodes.... LEAF node? [ {0} ]".format(root))
                # TODO: Have this function add to the "leaf_list"       <----   This will work with finding attack paths later on ~!~
                print("\tLength of neighbours:\t{0}\n\tNeighbours:\t{1}".format(len(self._graph_dict[root]), self._graph_dict[root]))
            if detailDebugBit != 0:
                if root == 'server':
                    print("[?] Why is 'server' getting added as a LEAF node?\n\tRoot:\t\t\t{0}\n\tVisited:\t\t\t{1}\n\tQueue:\t\t\t{2}\n\tLeaves:\t\t\t{3}\n\tDifferent Nodes:\t\t{4}".format(root, visited, queue, leaf_nodes, different_nodes))
            leaf_nodes.append(root)
            # Check to see if the number of nieghbours in the UNDIRECTED GRAPH is ONE (i.e. expected LEAF NODE)
            if len(self._graph_dict[root]) <= 1:
                print("[+] Adding leaf node [ {0} ]".format(root))
            else:
                print("[-] Looks like a leaf, but node [ {0} ] has multiple nieghbour nodes".format(self._graph_dict[root]))
        # For each of the adjacent vertex points around the root node
        for vertex_node in self._graph_dict[root]:
            # If this node has NOT been visited then add to queue
            if vertex_node not in visited:
                # Add unvisited node to queue
                queue.append(vertex_node)
                # Make the recursive logic call
                visited, queue, leaf_nodes = self.dfs_recursive_search(vertex_node, visited, queue, leaf_nodes)
                # Remove the now visited node from the queue
                queue.remove(vertex_node)
            else:
                print("[-] Node [ {0} ] has already been visited".format(vertex_node))
        # Remove this node from the queue
        print("[+] Completed DFS Recursive Search from [ {0} ]".format(root))
        # Return the updated lists
        return visited, queue, leaf_nodes

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

# Function for updating the entry_exit_map for "Leaf Nodes"
def update_entry_exit_map_entry_leaf_node_flags(entry_exit_map, entry_exit_subentry, leaf_nodes):
    print("[*] Updating the Entry/Exit map entries for 'Leaf Node'")
    for item in entry_exit_map[entry_exit_subentry]:
        if detailDebugBit != 0:
            print("\tItem entry:\t{0}".format(item))
        # Perform the update
        if item in leaf_nodes:
            entry_exit_map[entry_exit_subentry][item]["Leaf Node"] = True
        else:
            entry_exit_map[entry_exit_subentry][item]["Leaf Node"] = False
    # Return the updated map
    return entry_exit_map

## Functions Dealing with Creation, Reading, and Testing of Graph Objects within SMART

# Function for Creating and Returning a Basic Test Graph
def create_test_graph_object():
    # Example Test Graph for Testing
    #   Nota Bene: Each connection in the graph below represents a connection in EACH direction
    #       - THEREFORE if the edge is defined for BOTH nodes (e.g. Database, Server) then TWO
    #           edges will be produced in the print out of the generate_edges() function
    testGraph = { 'Database' : {'Server'},
                'Server' : {'Application', 'Database', 'Sensor'},
                'Sensor' : {'Server'},
                'Application' : {'GUI', 'Server'},
                'GUI' : {'Application'}
    }
    return testGraph

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

# Function for Testing the check__entry_exit_paths() function
def test_entry_exit_check():
	# Testing for Creating Entry to AoI to Exit Graph Pathing
	Entry = "GUI"
	Exit = "GUI"
	AoI = "Database"
	
	print("[*] Finding path that enters at {0}, moves to AoI ({1}), and leaves via exit ({2})".format(Entry, AoI, Exit))
	entry_path = graph.find_path(Entry, AoI)
	exit_path = graph.find_path(AoI, Exit)
	print(entry_path + exit_path)
	check__entry_exit_paths(entry_path, exit_path)
	
	Entry2 = "Sensor"
	Exit2 = "Application"
	AoI2 = "GUI"
	print("[*] Finding path that enters at {0}, move to AoI ({1}), and leaves via exit ({2})".format(Entry2, AoI2, Exit2))
	entry_path2 = graph.find_path(Entry2, AoI2)
	exit_path2 = graph.find_path(AoI, Exit2)
	print(entry_path2, exit_path2)
	check__entry_exit_paths(entry_path2, exit_path2)


'''
 Function Definitions
'''

'''
 Example CVE list from multie branch example
    ____________R____________
    |       |       |       |   
   sn1     sn2     sn3     sn4
   |                        |
   |                        |
  ssn1                     ssn2

 Prodcued Leaf List:
    ['/rootNode/subNodes[1]/subNodes', '/rootNode/subNodes[2]', '/rootNode/subNodes[3]', '/rootNode/subNodes[4]/subNodes']

 Produced CVE List:
    [[['CVE-2018-1000168'], ['CVE-2018-1000032'], ['CVE-2018-1000153']], [['CVE-2018-1000300'], ['CVE-2018-1000153']], [['CVE-2018-1000039'], ['CVE-2018-1000153']], [['CVE-2018-1000032', 'CVE-2018-1000039', 'CVE-2018-1000168', 'CVE-2018-1000301'], ['CVE-2018-1000301'], ['CVE-2018-1000153']]]
    -> For ease of understanding, basically have:
        '/rootNode/subNodes[1]/subNodes'    -   [['CVE-2018-1000168'], ['CVE-2018-1000032'], ['CVE-2018-1000153']]
        '/rootNode/subNodes[2]'             -   [['CVE-2018-1000300'], ['CVE-2018-1000153']]
        '/rootNode/subNodes[3]'             -   [['CVE-2018-1000039'], ['CVE-2018-1000153']]
        '/rootNode/subNodes[4]/subNodes'    -   [['CVE-2018-1000032', 'CVE-2018-1000039', 'CVE-2018-1000168', 'CVE-2018-1000301'], ['CVE-2018-1000301'], ['CVE-2018-1000153']]
        => Nota Bene: These CVE lists are backwards from leaf to root

    Example of cleaning lists:
        for list in cveList:
            print("List: " + str(list))     # Gets breakdown of each CVE list for each leaf path
        -> One more for-loop grabs each sub item
            -   Create separate path list
                For each sublist in list:
                    if len(sublist) == 1:
                        append single item to larger list
                    else:
                        group together each item in a '()' boundary marked list(? is this the best way to do it?)
                return edited paths
                ????
                PROFIT!
'''
###
# Functions for interacting with the Database       | USE THESE TO LOOK UP VALUES FOR ENTERIES
###
# Function for reading in the asset database
def readAssetDb():
    print("[*] Reading in the Assets Database")
    return Database.ioDatabase.readJSON('./Database/assetValDb.json')

# Function for reading in the costs database
def readCostDb():
    print("[*] Reading in the Costs Database")
    return Database.ioDatabase.readJSON('./Database/costValDb.json')

# Function for reading in the risk database
def readRiskDb():
    print("[*] Reading in the Risks Database")
    return Database.ioDatabase.readJSON('./Database/riskValDb.json')

# Function for collecting Ps values
def getPsVal(jsonData, vulnName):
    entryData = Database.ioDatabase.findEntry(jsonData, vulnName)
    return Database.ioDatabase.retProbOfSuccess(entryData)

# Function for collecting Ca values
def getCaVal(jsonData, vulnName):
   entryData = Database.ioDatabase.findEntry(jsonData, vulnName)
   return Database.ioDatabase.retCostOfAttack(entryData)

# Function for collecting Impact values
def getImpact(jsonData, assetName):
    entryData = Database.ioDatabase.findEntry(jsonData, assetName)
    return Database.ioDatabase.retImpact(entryData)

# Function for collecting Attack Value
def getAtkrVal(jsonData, assetName):
    entryData = Database.ioDatabase.findEntry(jsonData, assetName)
    return Database.ioDatabase.retAtkrVal(entryData)

# Function for collecting Scale Amount
def getScaleAmnt(jsonData, assetName):
    entryData = Database.ioDatabase.findEntry(jsonData, assetName)
    return Database.ioDatabase.retScaleAmnt(entryData)

# Function for collecting Alpha value
def getAlpha(jsonData, assetName):
    entryData = Database.ioDatabase.findEntry(jsonData, assetName)
    return Database.ioDatabase.retAlpha(entryData)

# Function for collecting Inital Cost value
def getInitCost(jsonData, elemName):
    entryData = Database.ioDatabase.findEntry(jsonData, elemName)
    return Database.ioDatabase.retCostOfInit(entryData)

# Function for collecting Cost of Maintainence value
def getCmVal(jsonData, elemName):
     entryData = Database.ioDatabase.findEntry(jsonData, elemName)
     return Database.ioDatabase.retCostOfMain(entryData)

# Function for collecting Cost of Operaiton value
def getCoVal(jsonData, elemName):
    entryData = Database.ioDatabase.findEntry(jsonData, elemName)
    return Database.ioDatabase.retCostOfOper(entryData)

# Function for updating risk database
def updateRiskDb(jsonData, vulnName, probOfSuccess, costOfAttack):
    print("[*] Adding entry to the Risks Database")
    Database.ioDatabase.updateEntry_riskDb_userless(jsonData, vulnName, probOfSuccess, costOfAttack)
    print("[!] Updated entries in the Risks Database")

# Function for reading in a list of CVEs; to then update the risk database
#   Note: Should give option to provide a default value AND grab risk value from online
def importCVEsToRiskDb(jsonData, cvesFile):
    print("[*] Importing CVEs to Risk Database")
    with open(cvesFile) as cveFile:
        lines = [line.rstrip() for line in cveFile]
    for cve in lines:
        print("[*] CVE to be added - {0}".format(cve))
        cveID = cve
        cveProbOfSuccess = APILearning.cveGrab.main(cveID)
        cveCostOfAttack = str(2)
        updateRiskDb(jsonData, cveID, cveProbOfSuccess, cveCostOfAttack)
    print("[+] Completed importing CVEs to Risk Database")
#entryData = 
#cve-ProbOfSuccess = APILearning.cveGrab.main(cveID)

###
# Bringing in databases for code
###
# Read in database files as global variables
riskDatabase = readRiskDb()
costDatabase = readCostDb()
assetDatabase = readAssetDb()

# Read in all the CVE databases
print("[*] Reading in GLOBAL databases")
## Fake CVE Database reads
#cve9999 = {}
## Real CVE Database reads
cveRecent = getJSON(nvdDict["Recent"]) 
cve2021 = getJSON(nvdDict["2021"])
cve2020 = getJSON(nvdDict["2020"])
cve2019 = getJSON(nvdDict["2019"])
cve2018 = getJSON(nvdDict["2018"])
cve2017 = getJSON(nvdDict["2017"])
cve2016 = getJSON(nvdDict["2016"])
cve2015 = getJSON(nvdDict["2015"])
cve2014 = getJSON(nvdDict["2014"])
cve2013 = getJSON(nvdDict["2013"])
cve2012 = getJSON(nvdDict["2012"])
cve2011 = getJSON(nvdDict["2011"])
cve2010 = getJSON(nvdDict["2010"])
cve2009 = getJSON(nvdDict["2009"])
cve2008 = getJSON(nvdDict["2008"])
cve2007 = getJSON(nvdDict["2007"])
cve2006 = getJSON(nvdDict["2006"])
cve2005 = getJSON(nvdDict["2005"])
cve2004 = getJSON(nvdDict["2004"])
cve2003 = getJSON(nvdDict["2003"])
cve2002 = getJSON(nvdDict["2002"])
print("[!] Completed reading in GLOBAL databaess")
# Create a dictionary based on the above JSON data
cveDict = {
        # Fake CVE search for dealing with Entry/Exit/Access-way nodes
        #"9999": cve9999,
        # Normal CVE search
        "Recent": cveRecent,
        "2021": cve2021,
        "2020": cve2020,
        "2019": cve2019,
        "2018": cve2018,
        "2017": cve2017,
        "2016": cve2016,
        "2015": cve2015,
        "2014": cve2014,
        "2013": cve2013,
        "2012": cve2012,
        "2011": cve2011,
        "2010": cve2010,
        "2009": cve2009,
        "2008": cve2008,
        "2007": cve2007,
        "2006": cve2006,
        "2005": cve2005,
        "2004": cve2004,
        "2003": cve2003,
        "2002": cve2002
}


###
# Functions for the rest of the code
###

# Function for reading in attack tree files and producing a Security Risk function
#def        ### Depreciated?
    # Clean-up the CVE information so that each path is evaluated separately

# Function for returning a list of probabilities based on a provided CVE list
#   - NOTE: Handles empty CVE lists and produces empty PS lists
def generatePSpath(elementCVEList):
    pathProbList = []
    if debugBit != 0:
        print("\tInput Master CVE List: " + str(elementCVEList))
    # Create loop to grab each CVE List for the separate leaf-to-root paths
    for subCVElist in elementCVEList:       # Note: Issue with sublists NOT being sublists but the larger list
        if debugBit != 0:
            print("Sub List: " + str(subCVElist))
        # Need to create separate probability values for each path item
        subCVEList_PS = []
        # Note: any for loop at this nested level will be all the vulnerabilities for a given node
        for nodeCVEs in subCVElist:
            nodeProb = 1    # Allows for cumulative multiplication of the found probabilities from CVE information
            if debugBit != 0:
                print("nodeCVE: {0}".format(nodeCVEs))
            innerCVEList_PS = []
            for nodeCVE in nodeCVEs:    # looping through each CVE found for a given node in the path list
                #nodeProb *= float(Standards.cveGrab.main(nodeCVE))/10   # Produce a product of each CVE's CVSS score (porbability of risk) for a given node
                #innerCVEList_PS.append(float(Standards.cveGrab.main(nodeCVE))/10)
                cveYear = getCVEyear(nodeCVE)
                cveDatabase = cveDict[cveYear]
                innerCVEList_PS.append(float(Standards.cveGrab.main(nodeCVE, cveDatabase))/10)
            subCVEList_PS.append(innerCVEList_PS)   # Append the found Probability of Success (PS) to a list [representing the differening PS for a given path]
            if debugBit != 0:
                print("[?] Sub-Check; subCVEList_PS: {0}".format(subCVEList_PS))
                if not subCVEList_PS:       # The PS List is Empty
                    print("\t! WE GOT AN EMPTY PS LIST !")
        pathProbList.append(subCVEList_PS)  # Creates a set of probabilities for each path that was examined in this loop
        if debugBit != 0:
            print("[?] Check; pathProbList: {0}".format(pathProbList))
    if debugBit != 0:
        print("[*] Created probabilities list for each path")
    return pathProbList

# Function for calculating the total path PS list of probabilities based on a provided PS list
def calcPSpath(elementCVEList):
    pathProbList = []
    if debugBit != 0:
        print("\tInput Master CVE List: " + str(elementCVEList))
    # Create loop to grab each CVE List for the separate leaf-to-root paths
    for subCVElist in elementCVEList:       # Note: Issue with sublists NOT being sublists but the larger list
        if debugBit != 0:
            print("Sub List: " + str(subCVElist))
        # Need to create separate probability values for each path item
        subCVEList_PS = []
        # Note: any for loop at this nested level will be all the vulnerabilities for a given node
        for nodeCVEs in subCVElist:
            nodeProb = 1    # Allows for cumulative multiplication of the found probabilities from CVE information
            if debugBit != 0:
                print("nodeCVE: {0}".format(nodeCVEs))
            for nodeCVE in nodeCVEs:    # looping through each CVE found for a given node in the path list
                #nodeProb *= float(Standards.cveGrab.main(nodeCVE))/10   # Produce a product of each CVE's CVSS score (porbability of risk) for a given node
                cveYear = getCVEyear(nodeCVE)
                cveDatabase = cveDict[cveYear]
                nodeProb *= float(Standards.cveGrab.main(nodeCVE, cveDatabase))/10   # Produce a product of each CVE's CVSS score (porbability of risk) for a given node
            subCVEList_PS.append(nodeProb)   # Append the found Probability of Success (PS) to a list [representing the differening PS for a given path]
            if debugBit != 0:
                print("[?] Sub-Check; subCVEList_PS: {0}".format(subCVEList_PS))
        pathProbList.append(subCVEList_PS)  # Creates a set of probabilities for each path that was examined in this loop
        if debugBit != 0:
            print("[?] Check; pathProbList: {0}".format(pathProbList))
    if debugBit != 0:
        print("[*] Created probabilities list for each path")
    return pathProbList

# Function for returning a list of attacker costs based on a provided CVE list
# Input expected as follows:                    |   NOTE: Maybe just need to pass in a different input?
#       [[Path #1 Nodes],[Path #2 Nodes],.....,[Path #N Nodes]]
#               |
#               |   <--- Epanding the 'Path #1 Nodes' Set
#               |
#   [[Ca CVE #1 Node #1, Ca CVE #2 Node #1,....., Ca CVE #N Node #1],...,[Ca CVE #1 Node #N,...,Ca CVE #N Node #N]]
def generateAttackCostpath(elementCVEList):
    pathAttackCostList = []
    # Create loop to grab each CVE List for the separat leaf-to-root paths
    for subCVElist in elementCVEList:
        subCVEList_AttackCost = []
        # Note: any for loop at this nested level will be all the vulnerabilities for a given node
        for nodeCVEs in subCVElist:
            nodeCostOfAttack = 0    # Allows for summation of the user supplied attack costs from CVE information
            nodeCaList = []
            for nodeCVE in nodeCVEs:    # looping through each CVE found for a given node in the path list
                if getCaVal(riskDatabase, nodeCVE) is not None:       # Check that Ca could be found in Risk Database
                    nodeCostOfAttack = float(getCaVal(riskDatabase, nodeCVE))           # TODO: Fix issue where this does not appear to be called
                else:
                    nodeCostOfAttack = float(input('What is the cost of attack for ' + str(nodeCVE) + ': '))
                nodeCaList.append(nodeCostOfAttack)
            #subCVEList_AttackCost.append(nodeCostOfAttack)
            subCVEList_AttackCost.append(nodeCaList)
        pathAttackCostList.append(subCVEList_AttackCost)
    if debugBit != 0:
        print("[*] Created attack costs list for each path")
    return pathAttackCostList


# Function for calculating the sum attack cost of supplied costs of attack per path
# Input expected as follows:
#       [[Path #1 Cas],[Path #2 Cas],.......,[Path #N Cas]]
#               |
#               |   <--- Translation of list
#               |
#   [[Sum Ca Path #1], [Sum Ca Path #2], ......., [Sum Ca Path #N]]
def calcAttackCostpath(elementCVEList):
    pathAttackCostList = []
    # Create loop to grab each CVE List for the separat leaf-to-root paths
    for subCVElist in elementCVEList:
        subCVEList_AttackCost = []
        # Note: any for loop at this nested level will be all the vulnerabilities for a given node
        for nodeCVEs in subCVElist:
            nodeCostOfAttack = 0    # Allows for summation of the user supplied attack costs from CVE information
            for nodeCVE in nodeCVEs:    # looping through each CVE found for a given node in the path list
                if getCaVal(riskDatabase, nodeCVE) is not None:       # Check that Ca could be found in Risk Database
                    nodeCostOfAttack += float(getCaVal(riskDatabase, nodeCVE))
                else:
                    nodeCostOfAttack += float(input('What is the cost of attack for ' + str(nodeCVE) + ': '))
            subCVEList_AttackCost.append(nodeCostOfAttack)
        pathAttackCostList.append(subCVEList_AttackCost)
    if debugBit != 0:
        print("[*] Created attack costs list for each path")
    return pathAttackCostList

# Function for returning a list of initial cost information based on element node names [BASED ON USER SUPPLIED INPUT]
def getGraphElementsInitCost(elementNameList): 
    pathElemList_initCost = []
    for subElemList in elementNameList:
        subElemList_initCost = []
        for nodeElem in subElemList:
            if debugBit != 0:
                print("Element: " + nodeElem)
            if getInitCost(costDatabase, nodeElem) is not None:        # Check if entry exists in Costs Database
                subElemList_initCost.append(float(getInitCost(costDatabase, nodeElem)))
            else:
                subElemList_initCost.append(float(input('What is the initial cost for ' + str(nodeElem) + ': ')))
        pathElemList_initCost.append(subElemList_initCost)
    return pathElemList_initCost

# Function for returning a list of impact information based on element node names [BASED ON USER SUPPLIED INPUT]
def getGraphElementsImpact(elementNameList):
    pathElementList_Impact = []
    for subElemList in elementNameList:
        subElemList_impact = []
        for nodeElem in subElemList:
            # NOTE: Setting the database below to 'riskDatabase' would effectively make this function ONLY user supplied data
            if getImpact(assetDatabase, nodeElem) is not None:     # Check that Impact value is found in Asset Database
                subElemList_impact.append(float(getImpact(assetDatabase, nodeElem)))
            else:
                subElemList_impact.append(float(input('What is the impact for ' + str(nodeElem) + ': ')))
        pathElemList_Impact.append(subElemList_impact)
    return pathElementList_Impact

'''
# Function for returning a list of attacker ocst information based on element node names [BASED ON USER SUPPLIED INPUT]
# Note: This does NOT do what I need....... Need to perform summation for each path
#   -> Write similar to 'calcPSpath()' function?
def getGraphElementsAttackCost(elementNameList):
    pathElementList_attackCost = []
    for subElemList in elementNameList:
        subElemList_attackCost = []
        for nodeElem in subElemList:
            subElemList_attackCost.append(float(input('What is the attack cost for ' + str(nodeElem) + ': ')))
        pathElementList_attackCost.append(subElemList_attackCost)
    return pathElementList_attackCost
# Note: the above function is not useful
'''

# Function for summing together SR values based on some basic values
#   -> NOTE: This function is ONLY purposed for producing a 3D graph of values
def sumSRTest(graphPSList, path_alpha, attackVal, graphAttackCostList, impactVal, graphInitCostList, path_scaleAmount):
    pathList_SecurityRisk = []
    for subList in range(len(graphPSList)):
        pathList_SecurityRisk.append(Calculation.securityRisk.pathCostCalc(graphPSList[subList], path_alpha, attackVal, graphAttackCostList[subList], impactVal, graphInitCostList[subList], 70000, 2450, path_scaleAmount))
    sumSR = 0
    for SRitem in pathList_SecurityRisk:
        sumSR += SRitem
    return sumSR


## Function for creating a series of different values based on changes to Attack Value (A) and Impact (I)
## Input:    Attack graph file, Vector of A values, Vector of I values
## Output:   Vector of SR values
#def graph3DRisk(filepath):
#    print("[*] ---------- Working to Create a 3D Graph ------------ [*]")
#    #path_scaleAmount = int(input('What is the scale amount for the values being supplied by the user (e.g. 1000): '))  # Ask for after getting the attack graph root node
#    graphTree = XMLParsing.xmlParsing.readAttackTree(filepath)
#    # Get the set of paths to the leafs (e.g. suNodes)
#    graphxpath = XMLParsing.xmlParsing.findLeafs(graphTree.getroot()[0])  # Passing the rootNode to get all existing leafs
#    graphCVEList = XMLParsing.xmlParsing.buildCVEList(graphxpath, graphTree)   # NOTE: No need for "root paths" since a product of PoS is taken
#    graphNameList = XMLParsing.xmlParsing.buildNameList(graphxpath, graphTree)
#    graphPSList = []
#    graphAttackCostList = []
#    for subPaths in graphCVEList:
#        attackPaths = list(itertools.product(*subPaths))
#        atkPathsPS = calcPSpath([attackPaths])
#        atkPathsCA = calcAttackCostpath([attackPaths])
#        graphPSList.append(*atkPathsPS)
#        graphAttackCostList.append(*atkPathsCA)
#    # NOTE: Moved the below initCost to the above "every path combination" loop |   NOTE: WRONG ABOUT THIS!!
#    graphInitCostList = getGraphElementsInitCost(graphNameList)
#    # Prepare values for user requests
#    rootNodeTag = graphTree.getroot()[0].tag
#    rootNodeName = graphTree.getroot()[0].get('name')
#    ##
#    # Collecting scale information about target asset from code Database    | WORKS :D TODO: If not found, ask for value and add; then check & change
#    #       -> Turn the if-else statement question into a function??, would take a string mask and a function to test??
#    ##
#    # Try to find the scale amount information from the assetDatabase
#    if getScaleAmnt(assetDatabase, rootNodeName) is not None:     # Check if the asset exists within the Asset Database
#        path_scaleAmount = int(getScaleAmnt(assetDatabase, rootNodeName))
#    else:       # Could NOT find the value within the Asset Database, therefore asking the user for the information
#        path_scaleAmount = int(input('What is the scale amount for the values being supplied by the user (e.g. 1000): '))
#    # Try to find the impact amount informatio from the assetDatabase
#    if getImpact(assetDatabase, rootNodeName) is not None:      # Check if the asset exists within the Asset Database
#        path_impact = float(getImpact(assetDatabase, rootNodeName))
#    else:
#        path_impact = float(input('What is the impact for ' + str(rootNodeTag) + ' ' + str(rootNodeName) + '(0.0 to 99.9): '))
#    # Try to find the attack value informaiton from the assetDatabase
#    if getAtkrVal(assetDatabase, rootNodeName) is not None:       # Check if the asset exists within the Asset Database
#        path_attackValue = float(getAtkrVal(assetDatabase, rootNodeName))
#    else:
#        path_attackValue = float(input('What is the attack value for ' + str(rootNodeTag) + ' ' + str(rootNodeName) + '(0.0 to 99.9): '))
#    # Try to find the alpha value information from the assetDatabase
#    if getAlpha(assetDatabase, rootNodeName) is not None:       # check if the asset exsists within the Asset Database
#        path_alpha = float(getAlpha(assetDatabase, rootNodeName))
#    else:
#        path_alpha = float(input('What is the alpha value for the attack graph: '))
#    if debugBit != 0:
#        print("[*] Calling security risk script with varaibles")
#    '''
#     Note: Input to the function below must be in a specific order
#        - item_PS
#        - item_alpha
#        - item_attackValue
#        - item_attackCost
#        - item_impact
#        - item_ci
#        - item_cost_maintenance
#        - item_cost_operation
#        - item_scaleAmount
#    '''
#    if debugBit != 0:
#        print("[?] Function Input Breakdown (FIB)..... combineScript::graphToRisk")
#        print("\tGraph PS:\t\t" + str(graphPSList) + "\n\tPath Alpha:\t\t" + str(path_alpha) + "\n\tPath AtkVal:\t\t" + str(path_attackValue) + "\n\tGraph Ca:\t\t" + str(graphAttackCostList) + "\n\tPath Impact:\t\t" + str(path_impact) + "\n\tGraph Ci:\t\t" + str(graphInitCostList) + "\n\tPath Scale:\t\t" + str(path_scaleAmount))
#    # Create range values for Attack Value (A) and Impact (I)
#    range_attackValue = np.arange(path_attackValue - 10, path_attackValue + 10, 0.5)
#    range_impact = np.arange(path_impact - 10, path_impact + 10, 0.5)
#    # Expand to larger ranges for graphing (e.g. X-Values - In repeating, but growing order, Y-Values - Repeating the same base range len() times
#    #   -> NOTE: Each of the following lists are of the same length
#    range_attackValue = [i for i in range_attackValue for _ in range_attackValue]   # Create list of repeated values growing from min to max    \____
#    range_impact = list(range_impact) * len(range_impact)                           # Create list of repeating values                           /    Works!!!
#    # Develop the additional points needed for the graphing (Going to scatter plot first)
#    #zs = [pathList_SecurityRisk.append(Calculation.securityRisk.pathCostCalc(graphPSList[subList], path_alpha, valA, graphAttackCostList[subList], valI, graphInitCostList[subList], 70000, 2450, path_scaleAmount)) for valA,valI in zip(range_attackValue, range_impact)]
#    zs = [sumSRTest(graphPSList, path_alpha, attackVal, graphAttackCostList, impactVal, graphInitCostList, path_scaleAmount) for attackVal,impactVal in zip(range_attackValue, range_impact)]   # Works like this for a line in 3D space.... how do I make a surface?
#    if debugBit != 0:
#        print("[?] Test output for function")
#        print("\tAttack Value Range: {0}\n\t\tLength: {3}\n\tImpact Value Range: {1}\n\t\tLength: {4}\n\tZ Values: {2}\n\t\tLength: {5}".format(range_attackValue, range_impact, zs, len(range_attackValue), len(range_impact), len(zs)))
#    '''
#    # Old test for creating different Z-axis values
#    testList = []   # Using this to create a list of SR Values based on change in Attack Value (A)
#    # First: Test loop of Attack Values
#    for attackVal in range_attackValue:
#        pathList_SecurityRisk = []
#        # Loop through each path of items to calculate the security risk per path
#        #   Nota Bene: Expectation is that the size of the lists is the same!! It should be based on how the code is written
#        for subList in range(len(graphPSList)):
#            pathList_SecurityRisk.append(Calculation.securityRisk.pathCostCalc(graphPSList[subList], path_alpha, attackVal, graphAttackCostList[subList], path_impact, graphInitCostList[subList], 70000, 2450, path_scaleAmount))  # Ensure that scaling is the SAME!!!
#        print("List of different path security risk values: " + str(pathList_SecurityRisk))
#        # NEED: Next summation of all the path security risk values to obtain the overall security risk
#        sumSR = 0
#        for SRitem in pathList_SecurityRisk:
#            sumSR += SRitem
#        print("[!] Total SR Value: " + str(sumSR))
#        testList.append(sumSR)
#    print("[!] Range of SR: " + str(testList))
#    # Output test
#    testRange = np.arange((path_attackValue - 10), path_attackValue + 10, 0.5)      # Create range of values 
#    print("[?] Test Range: " + str(testRange))
#    testRange2 = np.arange(path_impact - 10, path_impact + 10, 0.5)
#    print("[?] Test Range2: " +str(testRange2))
#    '''
#    # NEED: Get this function to return a list of not just the attackSR, but also the impactSR
#    #   -> Try to map a 3D graph using impact + attack value        | FIGURE OUT HOW THE FUCK TO DO THIS
#    # Creating the 3D graph space
#    fig = plt.figure()
#    ax = fig.add_subplot(111, projection='3d')
#    # Adding in the points of data
#    ax.scatter(range_attackValue, range_impact, zs)     # Scatter graphing of data (to test that this will work)
#    # Labeling the Axis
#    ax.set_xlabel('Attack Value')
#    ax.set_ylabel('Impact Value')
#    ax.set_zlabel('Security Risk')
#    # Show the graph
#    plt.show()
#    return zs #testList     # Returns a list of SR values based on changing of Attack Value (A)

# Function for reading an attack graph and returning the calculated security risk
# NOTE: Need to fix so that this can calculate security risk for a SINGLE NODE!!! (e.g. root node)  <---- TODO? Not needed for automation? Trivial?
def graphToRisk(filepath):
    if debugBit != 0:
        print("[*] ---------- Calculating Security Risk based on passed Attack Graph ------------ [*]")
    #path_scaleAmount = int(input('What is the scale amount for the values being supplied by the user (e.g. 1000): '))  # Ask for after getting the attack graph root node
    graphTree = XMLParsing.xmlParsing.readAttackTree(filepath)
    # Get the set of paths to the leafs (e.g. suNodes)
    graphxpath = XMLParsing.xmlParsing.findLeafs(graphTree.getroot()[0])  # Passing the rootNode to get all existing leafs
    graphCVEList = XMLParsing.xmlParsing.buildCVEList(graphxpath, graphTree)   # NOTE: No need for "root paths" since a product of PoS is taken
    graphNameList = XMLParsing.xmlParsing.buildNameList(graphxpath, graphTree)
    #graphPSList = calcPSpath(graphCVEList)  # NOTE: Check that this is being done correctly!!!! | SPOILER: It's not
    graphPSList = []
    graphAttackCostList = []
    #graphInitCostList = []
    if debugBit != 0:
        print("[?] Test.... Structure of CVE List")
        print("\tCVE List: " + str(graphCVEList))
        print("\tLength: " + str(len(graphCVEList)))
    for subPaths in graphCVEList:
        if debugBit != 0:
            print("SubPath: " + str(subPaths))
        if debugBit != 0:
            print("\tLength: " + str(len(subPaths)))
        attackPaths = list(itertools.product(*subPaths))
        atkPathsPS = calcPSpath([attackPaths])
        atkPathsCA = calcAttackCostpath([attackPaths])
        #atkPathsCI = getGraphElementsInitCost([*attackPaths])   # Wrong place to do Ci for paths?
        graphPSList.append(*atkPathsPS)
        graphAttackCostList.append(*atkPathsCA)
        #graphInitCostList.append(*atkPathsCI)       # Get error: TypeError: append() takes exactly one argument (2 given)
    # NOTE: Moved the below initCost to the above "every path combination" loop |   NOTE: WRONG ABOUT THIS!!
    graphInitCostList = getGraphElementsInitCost(graphNameList)
    '''
    print("[?] Test.... Structure of Element Names List")
    print("\tName List: " + str([graphNameList]))
    print("\tLength: " + str(len([graphNameList])))
    for subPaths in [graphNameList]:        # WRONG, this doesn't need to be done the same way, it just requires a sum based on the name list
        drint("SubPath: " + str(subPaths))
        print("\tLength: " + str(len(subPaths)))
        attackPaths = list(itertools.product(*subPaths))
        print("Attack Path of Element Nodes:\t" + str(attackPaths))
        atkPathsCI = getGraphElementsInitCost([*attackPaths])
        graphInitCostList.append(*atkPathsCI)
    print("\tCi List: " + str(graphInitCostList))
    '''
    # Change this so that we calculate a summation of Cost of Attack
    #graphAttackCostList = calcAttackCostpath(graphCVEList)    #getGraphElementsAttackCost(testCVEList)
    # Prepare values for user requests
    rootNodeTag = graphTree.getroot()[0].tag
    rootNodeName = graphTree.getroot()[0].get('name')
    ##
    # Collecting scale information about target asset from code Database    | WORKS :D TODO: If not found, ask for value and add; then check & change
    #       -> Turn the if-else statement question into a function??, would take a string mask and a function to test??
    ##
    # Try to find the scale amount information from the assetDatabase
    if getScaleAmnt(assetDatabase, rootNodeName) is not None:     # Check if the asset exists within the Asset Database
        path_scaleAmount = int(getScaleAmnt(assetDatabase, rootNodeName))
    else:       # Could NOT find the value within the Asset Database, therefore asking the user for the information
        path_scaleAmount = int(input('What is the scale amount for the values being supplied by the user (e.g. 1000): '))
    # Try to find the impact amount informatio from the assetDatabase
    if getImpact(assetDatabase, rootNodeName) is not None:      # Check if the asset exists within the Asset Database
        path_impact = float(getImpact(assetDatabase, rootNodeName))
    else:
        path_impact = float(input('What is the impact for ' + str(rootNodeTag) + ' ' + str(rootNodeName) + '(0.0 to 99.9): '))
    # Try to find the attack value informaiton from the assetDatabase
    if getAtkrVal(assetDatabase, rootNodeName) is not None:       # Check if the asset exists within the Asset Database
        path_attackValue = float(getAtkrVal(assetDatabase, rootNodeName))
    else:
        path_attackValue = float(input('What is the attack value for ' + str(rootNodeTag) + ' ' + str(rootNodeName) + '(0.0 to 99.9): '))
    # Try to find the alpha value information from the assetDatabase
    if getAlpha(assetDatabase, rootNodeName) is not None:       # check if the asset exsists within the Asset Database
        path_alpha = float(getAlpha(assetDatabase, rootNodeName))
    else:
        path_alpha = float(input('What is the alpha value for the attack graph: '))
    if debugBit != 0:
        print("[*] Calling security risk script with varaibles")
    '''
     Note: Input to the function below must be in a specific order
        - item_PS
        - item_alpha
        - item_attackValue
        - item_attackCost
        - item_impact
        - item_ci
        - item_cost_maintenance
        - item_cost_operation
        - item_scaleAmount
    '''
    if debugBit != 0:
        print("[?] Function Input Breakdown (FIB)..... combineScript::graphToRisk")
        print("\tGraph PS:\t\t" + str(graphPSList) + "\n\tPath Alpha:\t\t" + str(path_alpha) + "\n\tPath AtkVal:\t\t" + str(path_attackValue) + "\n\tGraph Ca:\t\t" + str(graphAttackCostList) + "\n\tPath Impact:\t\t" + str(path_impact) + "\n\tGraph Ci:\t\t" + str(graphInitCostList) + "\n\tPath Scale:\t\t" + str(path_scaleAmount))
    pathList_SecurityRisk = []
    # Loop through each path of items to calculate the security risk per path
    #   Nota Bene: Expectation is that the size of the lists is the same!! It should be based on how the code is written
    for subList in range(len(graphPSList)):
        pathList_SecurityRisk.append(Calculation.securityRisk.pathCostCalc(graphPSList[subList], path_alpha, path_attackValue, graphAttackCostList[subList], path_impact, graphInitCostList[subList], 70000, 2450, path_scaleAmount))  # Ensure that scaling is the SAME!!!
    if debugBit != 0:
        print("List of different path security risk values: " + str(pathList_SecurityRisk))
    # NEED: Next summation of all the path security risk values to obtain the overall security risk
    return pathList_SecurityRisk

# Function for formatting output about a SMART evaluation completed for a given attack tree model
# TODO: Update this function to include the minimum versions of this same information; see Main code
def smartOutput_formatted(inputFile, outputFile, pathList_SecurityRisk, modelCVEList, maxPathVar, maxSubPathVar, maxPathSRSeen, maxSubPathSRSeen, minPathVar, minSubPathVar, minPathSRSeen, minSubPathSRSeen, path_scaleAmount, testNameList, total_combinations):
    summaryFile = open(outputFile, "w")
    summaryFile.write("List of different path security risk values: " + str(pathList_SecurityRisk) + "\n")
    # NEED: Next summation of all the path security risk values to obtain the overall security risk
    # NEED: Identify corresponding CVE combination for most expensive path
    summaryFile.write("[+] =============================================================== [+]\n\t\tSummary of {0} SMART Evaluation\n".format(str(inputFile)))
    summaryFile.write("\tMost Expensive/Risky Subpath:\t\t{0}\n".format(pathList_SecurityRisk[maxPathVar]))
    try:
        summaryFile.write("\tAssociated CVEs to Max SR Path:\t\t{0}\n".format(list(itertools.product(*modelCVEList[maxPathVar]))[maxSubPathVar]))
    except IndexError:
        summaryFile.write("\tAssociated CVEs to Max SR Path:\t\t{0}\n".format("No vulnerable attack path.... Index Error Occurred"))
    summaryFile.write("\tMaximum SR Seen from Subpath:\t\t{0}\n".format(maxPathSRSeen))
    summaryFile.write("\tMaxium SR Subpath - Total Cost:\t\t{0}\n".format(maxSubPathSRSeen * path_scaleAmount))
    summaryFile.write("\tItem in Potential Path Tuple SR:\t{0}\n".format(maxPathVar))
    summaryFile.write("\tItem in Product Array of Max SR:\t{0}\n".format(maxSubPathVar))
    summaryFile.write("\t-----------------------------------------------------------------\n")
    summaryFile.write("\tLeast Expensive/Risky Subpath Tuple:\t\t{0}\n".format(pathList_SecurityRisk[minPathVar]))
    try:
        summaryFile.write("\tAssociated CVEs to Min SR Subpath:\t\t{0}\n".format(list(itertools.product(*modelCVEList[minPathVar]))[minSubPathVar]))
    except IndexError:
        summaryFile.write("\tAssociated CVEs to Min SR Subpath:\t\t{0}\n".format("No vulnerable attack path.... Index Error Occurred"))
    summaryFile.write("\tMinimum SR Seen from Subpath Tuple:\t\t{0}\n".format(minPathSRSeen))
    summaryFile.write("\tMinimum SR Subpath - Total Cost:\t\t{0}\n".format(minSubPathSRSeen * path_scaleAmount))
    summaryFile.write("\tItem in Potential Path Tuple SR:\t{0}\n".format(minPathVar))
    summaryFile.write("\tItem in Product Array of Min SR:\t{0}\n".format(minSubPathVar))
    summaryFile.write("\t-----------------------------------------------------------------\n")
    summaryFile.write("\n\n\tFull Path List Security Risk Evaluation Generated Output:\t{0}\n".format(pathList_SecurityRisk))
    summaryFile.write("\tTotal Number of Potential Attack Paths:\t{0}\n".format(total_combinations))
    summaryFile.write("\tAttack Path Combinations Elements:\t{0}\n".format(testNameList))
    summaryFile.write("[+] =============================================================== [+]\n")
    summaryFile.close()

# Function for reading in a provided AADL Graph Object file, vertex map filename, edge map filename, and vulnerability map filename
# Input:
#       aadl_graph_file     -   Filename for the AADL Graph Object
#       vertex_map_filename -   Filename for the Vertex Map
#       edge_map_filename   -   Filename for the Edge Map
#       vulnerability_map_filename  -   Filename for the Vulnerability Map
# Output:
#       read_graph          -   JSON dictionary containing the read graph information
#       vulnMap             -   JSON dictionary containing the read vulnerability map information
#       vertexMap           -   JSON dictionary containing the read vertex map information
#       edgeMap             -   JSON dictionary containing the read edge map information
def graph_files_read_and_return(aadl_graph_file, vertex_map_filename, edge_map_filename, vulnerability_map_filename):
    # Read in the Graph Object from the inputFile
    read_graph = json.load(open(aadl_graph_file))     # NOTE: This branch of SMART is expecting an inputFile that points to the AADL Graph Object dictionary file from TAMSAT
    # Read in the Vulnerability Map from the vulnerability_map_filename
    vulnMap = json.load(open(vulnerability_map_filename))
    # Read in the Vertex Map from the vertex_map_filename
    vertexMap = json.load(open(vertex_map_filename))
    # Read in the Edge Map from the edge_map_filename
    edgeMap = json.load(open(edge_map_filename))
    return read_graph, vulnMap, vertexMap, edgeMap

# Function for finding the rootNode of a provided vertexMap
# Input:
#       vertexMap           -   JSON Dictionary that acts as a mapping of the vertex that exist within the AADL Graph
# Output:
#       rootNode            -   Name of the rootNode that exists within the vertexMap; NOTE: Assumption is one exists, or returns as None
def find_root_node(vertexMap):
    # Find the rootNode of the vertexMap
    rootNode = None
    for vertex in vertexMap:
        if vertexMap[vertex]['Root Node']:      # This node is the root node
            rootNode = vertex
        else:                                   # This node is NOT the root node
            print("[-] Node [ {0} ] is not the Root Node".format(vertex))
    return rootNode

# Function for reading a given Graph Object map into SMART from TAMSAT
#   - NOTE: First pass has this function ONLY produce a single path (i.e. combination of ALL nodes in the map); Node lists for paths should go LEAF-to-ROOT
#       -> NOTE: This should produce a list of lists that represent
#   -> NOTE: This function MAY REQUIRE passing of an Asset of Importance variable
# Input:
#       - Graph Object representing the AADL Model (e.g. AADL XML File in Graph form)
#       - Node Map containing information about the Vertex Points within the AADL Model
#       - Edge Map containing information about the Edges within the AADL Model
# Output:
#       testCVEList         -   List of CVEs relating to the Nodes in the Graph Object        \_  Old output from first attempt to function the AADL XML read to SMART variables
#       testNameList        -   List of Names relating to the Nodes in the Graph Object       /
#       testPSList          -   List of Probabilities of Success relating to the Nodes in the Graph Object
#       testInitCostList    -   List of Initial Costs relating to the Nodes in the Graph Object
#       testAttackCostList  -   List of Attack Costs relating to the CVEs related to the Nodes in the Graph Object
#       path_scaleAmount    -   The amount of scaling that is required for certain values (e.g. ca, ps) to match the scale of Monetary cost used in SMART
#       path_impact         -   The Impact value encurred by a successful attack on the Asset of Importance; NOTE: Same regardless fo attack path
#       path_attackValue    -   The Attack Value related to the given Asset of Importance (i.e. The Value of the AoI to the Attacker); NOTE: Same regardless of attack path
#       path_alpha          -   The Alpha tuning variable used in the SMART evaluation of the attack path(s) examined; NOTE: Same regardless of attack path
def read_in_aadl_graph_object(inputFile, vertex_map_filename, edge_map_filename, vulnerability_map_filename, entry_exit_map_filename=None):
    print("[*] Reading in the AADL Graph Object")
    # Make call to and return variables relating to AADL Graph Object and supporting databases
    read_graph, vulnMap, vertexMap, edgeMap = graph_files_read_and_return(inputFile, vertex_map_filename, edge_map_filename, vulnerability_map_filename)
    # Read in the entry_exit_map and return the necessary JSON object
    if entry_exit_map_filename:         # An entry/exit map filename was passed
        print("[*] Reading in the Entry/Exit map")
        entry_exit_map = json.load(open(entry_exit_map_filename))
    else:
        print("[-] No Entry/Exit map provided")
        entry_exit_map = None
    # Convert that read inputFile into a Graph Object
    aadl_graph = Graph(read_graph)
    # Find the ROOT node and any LEAF nodes
    rootNode = find_root_node(vertexMap)
    #rootNode = ''                   # Search through the vertexMap for which is a root node
    #root = 'database'
    root = rootNode
    # Next need to determine the root node name (i.e. Asset of Importance (AoI))
    rootNodeName = root
    rootNodeTag = 'rootNode'
    # Make call to the AADL Graph generation of variables function
    testCVEList, testNameList, testPSList, testInitCostList, testAttackCostList, path_scaleAmount, path_impact, path_attackValue, path_alpha = generate_aadl_graph_evaluation(root, vulnMap, aadl_graph, entry_exit_map)
    # Return the generated information back to the original calling process
    return testCVEList, testNameList, testPSList, testInitCostList, testAttackCostList, path_scaleAmount, path_impact, path_attackValue, path_alpha

# Function for generating the Evaluation Variables from an AADL Graph Object
# Input:
#       root                -   Root node name for the path generation
#       vulnMap             -   Vulnerability Map that contains the associated CVEs to Graph vertex points
#       aadl_graph          -   AADL Graph Object that contains the AADL model representation
#       entry_exit_map      -   Entry/Exit Map that contains the associated entry and exit vertex points within the AADL Graph; NOTE: Can be passed, or assumed not present
# Output:
#       testCVEList         -   List of CVEs relating to the Nodes in the Graph Object        \_  Old output from first attempt to function the AADL XML read to SMART variables
#       testNameList        -   List of Names relating to the Nodes in the Graph Object       /
#       testPSList          -   List of Probabilities of Success relating to the Nodes in the Graph Object
#       testInitCostList    -   List of Initial Costs relating to the Nodes in the Graph Object
#       testAttackCostList  -   List of Attack Costs relating to the CVEs related to the Nodes in the Graph Object
#       path_scaleAmount    -   The amount of scaling that is required for certain values (e.g. ca, ps) to match the scale of Monetary cost used in SMART
#       path_impact         -   The Impact value encurred by a successful attack on the Asset of Importance; NOTE: Same regardless fo attack path
#       path_attackValue    -   The Attack Value related to the given Asset of Importance (i.e. The Value of the AoI to the Attacker); NOTE: Same regardless of attack path
#       path_alpha          -   The Alpha tuning variable used in the SMART evaluation of the attack path(s) examined; NOTE: Same regardless of attack path
def generate_aadl_graph_evaluation(root, vulnMap, aadl_graph, entry_exit_map=None):
    '''
    # Use the path find function to get a path from each LEAF to the ROOT node
        # Combine each into a larger list (Ex:  [   [   [node_i], [node_1], ... , [root_node]  ], [    [node_y], [node_2], .... , [root_node] ], ... ... , [  [node_2], [node_4], ... , [root_node] ]   ])
        #                                            -- Inner Attack Path Combination Set 1 --      -- Inner Attack Path Combination Set 2 --                -- Inner Attack Path Combination Set n --
        #                                           |---                                                    Outter Attack Path Set of Cominations 1                                                 --|
        inner_attack_path_combination = find_path(start_vertex, end_vertex)
    '''
    if entry_exit_map:
        print("[*] An Entry/Exit Map was provided")
        print("Contents of Entry/Exit Map:\n\t{0}".format(entry_exit_map))
    else:
        print("[-] No Entry/Exit Map was provided")
        entry_exit_map = None
    # Default variables being set due to artifacts from AADL XML code
    rootNodeTag = 'rootNode'
    rootNodeName = root
    # TODO: Add in a check for which type of attack path generation is being done ("BruteForce" or "Path Directional")
    # Create a list of all the CVEs in the attack paths from LEAVE-to-ROOT
    testNameList, testCVEList = aadl_graph.find_attack_paths_node_names(root, vulnMap, entry_exit_map)          # NOTE: Generates the list using an internal Graph Object Class function    ( "BruteForce" method )
    if detailDebugBit != 0:
        print("[?] Testing testname List:\t{0}\n\tType:\t{1}".format(testNameList, type(testNameList)))
    # Generate the list of CVEs related to each of the nodes in the testNameList variable
    # Create a list of all the nodes in the attack paths from LEAVES-to-ROOT
    #testCVEList = []            # TODO: Create function to determine the CVEs associated with each node; Maybe this comes from TAMSAT?      <-------- *** FOCUS ON THIS NEXT!!! Rest of code is set for working; missing this piece
    # ^^^^^ NOTE: WILL need to create a new function for performing this action.... Old way relys on etree structure; NEED new method of finding information (vertexMap with added vulnerabilities information???)
    #   - TODO: Create function that finds the root of the Node Map
    print("[+] Done reading in the AADL Graph Object")
    print("[*] Preparing to generate the necessary variables for SMART")
    # Generate the list of Probabilities of Success for the nodes in the attack paths
    testPSList = generatePSpath(testCVEList)
    # Generate the list of Initial Costs for the nodes in the attack paths
    testInitCostList = getGraphElementsInitCost(testNameList)
    # Generate the list of the Attack Costs for the CVEs related to the nodes in the attack paths
    testAttackCostList = generateAttackCostpath(testCVEList)
    # Generate the path Scale Amount used within SMART evaluation
    # Try to find the scale amount information from the assetDatabase
    if getScaleAmnt(assetDatabase, rootNodeName) is not None:     # Check if the asset exists within the Asset Database
        path_scaleAmount = int(getScaleAmnt(assetDatabase, rootNodeName))
    else:       # Could NOT find the value within the Asset Database, therefore asking the user for the information
        path_scaleAmount = int(input('What is the scale amount for the values being supplied by the user (e.g. 1000): '))
    # Generate the path Impact value used within SMART evaluation
    # Try to find the impact amount informatio from the assetDatabase
    if getImpact(assetDatabase, rootNodeName) is not None:      # Check if the asset exists within the Asset Database
        path_impact = float(getImpact(assetDatabase, rootNodeName))
    else:
        path_impact = float(input('What is the impact for ' + str(rootNodeTag) + ' ' + str(rootNodeName) + '(0.0 to 99.9): '))
    # Generate the path Attack Value associated with the AoI used within SMART evaluation
    # Try to find the attack value informaiton from the assetDatabase
    if getAtkrVal(assetDatabase, rootNodeName) is not None:       # Check if the asset exists within the Asset Database
        path_attackValue = float(getAtkrVal(assetDatabase, rootNodeName))
    else:
        path_attackValue = float(input('What is the attack value for ' + str(rootNodeTag) + ' ' + str(rootNodeName) + '(0.0 to 99.9): '))
    # Generate the path Alpha value used within SMART evaluation
    # Try to find the alpha value information from the assetDatabase
    if getAlpha(assetDatabase, rootNodeName) is not None:       # check if the asset exsists within the Asset Database
        path_alpha = float(getAlpha(assetDatabase, rootNodeName))
    else:
        path_alpha = float(input('What is the alpha value for the attack graph: '))
    print("[+] Returning the generated SMART variables")
    if detailDebugBit != 0:
        print("[?] Variable Check:\n\t\ttestNameList:\t\t\t{0}\n\t\ttestCVEList:\t\t\t{1}\n\t\ttestPSList:\t\t\t{2}\n\t\ttestInitCostList:\t\t{3}:\n\t\ttestAttackCostList:\t\t{4}\n\t\tpath_scaleAmount:\t\t{5}\n\t\tpath_impact:\t\t\t{6}\n\t\tpath_attackValue:\t\t{7}\n\t\tpath_alpha:\t\t\t{8}".format(testNameList, testCVEList, testPSList, testInitCostList, testAttackCostList, path_scaleAmount, path_impact, path_attackValue, path_alpha))
    # NOTE TODO: Fix the 'testTree' return issue here (ensure that it is actually required moving forward)
    return testCVEList, testNameList, testPSList, testInitCostList, testAttackCostList, path_scaleAmount, path_impact, path_attackValue, path_alpha

# Function for reading a given AADL Graph File into SMART from TAMSAT
# Input:
#       - AADL XML File representing the AADL Model (e.g. Graph Object in AADL XML File form)
# Output:
#       testTree            -   XML Tree that is Produced from the                            \     # NOTE: Might not need to export the 'testTree' variable anymore (???) ~!~
#       testCVEList         -   List of CVEs relating to the Nodes in the Graph Object        |-  Old output from first attempt to function the AADL XML read to SMART variables
#       testNameList        -   List of Names relating to the Nodes in the Graph Object       /
#       testPSList          -   List of Probabilities of Success relating to the Nodes in the Graph Object
#       testInitCostList    -   List of Initial Costs relating to the Nodes in the Graph Object
#       testAttackCostList  -   List of Attack Costs relating to the CVEs related to the Nodes in the Graph Object
#       path_scaleAmount    -   The amount of scaling that is required for certain values (e.g. ca, ps) to match the scale of Monetary cost used in SMART
#       path_impact         -   The Impact value encurred by a successful attack on the Asset of Importance; NOTE: Same regardless fo attack path
#       path_attackValue    -   The Attack Value related to the given Asset of Importance (i.e. The Value of the AoI to the Attacker); NOTE: Same regardless of attack path
#       path_alpha          -   The Alpha tuning variable used in the SMART evaluation of the attack path(s) examined; NOTE: Same regardless of attack path
def read_in_aadl_xml_file(inputFile):
    if debugBit != 0:
        print("[!] --------- NEED: Example attack graph to read in ------------ [!]\n\t\t~!~ Generate example from AADL")
    testTree = XMLParsing.xmlParsing.readAttackTree(inputFile)  # Test allowing user provided file to main function
    # Get the set of paths to the leafs (e.g. suNodes)
    testxpath = XMLParsing.xmlParsing.findLeafs(testTree.getroot()[0])  # Passing the rootNode to get all existing leafs
    if detailDebugBit != 0:
        print("[?] Testing Variables in combbineScript::main()\n\ttestxpath:\t{0}\n\ttestTree:\t{1}".format(testxpath, testTree))
        print("\tetree XML:\n{0}".format(etree.tostring(testTree, pretty_print=True).decode('UTF-8')))
    testCVEList = XMLParsing.xmlParsing.buildCVEList(testxpath, testTree)   # NOTE: No need for "root paths" since a product of PoS is taken
    testNameList = XMLParsing.xmlParsing.buildNameList(testxpath, testTree)
    #return testTree, testCVEList, testNameList
    testPSList = generatePSpath(testCVEList)                                # NOTE: This line should create two lists; one containing CVEs and one produced that is the ps along those lists
    # Nota Bene: Could have the above function return two arrays; one of the various CVEs associated with a path and the other with the Ps associated with a path
    testInitCostList = getGraphElementsInitCost(testNameList)
    #testAttackCostList = calcAttackCostpath(testCVEList)    #getGraphElementsAttackCost(testCVEList)
    testAttackCostList = generateAttackCostpath(testCVEList)
    # Will need to perform the summation and products for each path
    if debugBit != 0:
        print("[?] --------- Comparing Generated CVE and PS Lists --------- [?]\n\tCVE List:\t{0}\n\tPS List:\t{1}\n".format(testCVEList, testPSList))      # Check to compare data

    # Prepare values for user requests
    rootNodeTag = testTree.getroot()[0].tag
    rootNodeName = testTree.getroot()[0].get('name')
    # HERE is where the user interaction is being requested; NEED to replace with automated functionality
    # Try to find the scale amount information from the assetDatabase
    if getScaleAmnt(assetDatabase, rootNodeName) is not None:     # Check if the asset exists within the Asset Database
        path_scaleAmount = int(getScaleAmnt(assetDatabase, rootNodeName))
    else:       # Could NOT find the value within the Asset Database, therefore asking the user for the information
        path_scaleAmount = int(input('What is the scale amount for the values being supplied by the user (e.g. 1000): '))

    # Try to find the impact amount informatio from the assetDatabase
    if getImpact(assetDatabase, rootNodeName) is not None:      # Check if the asset exists within the Asset Database
        path_impact = float(getImpact(assetDatabase, rootNodeName))
    else:
        path_impact = float(input('What is the impact for ' + str(rootNodeTag) + ' ' + str(rootNodeName) + '(0.0 to 99.9): '))
    # Try to find the attack value informaiton from the assetDatabase
    if getAtkrVal(assetDatabase, rootNodeName) is not None:       # Check if the asset exists within the Asset Database
        path_attackValue = float(getAtkrVal(assetDatabase, rootNodeName))
    else:
        path_attackValue = float(input('What is the attack value for ' + str(rootNodeTag) + ' ' + str(rootNodeName) + '(0.0 to 99.9): '))
    # Try to find the alpha value information from the assetDatabase
    if getAlpha(assetDatabase, rootNodeName) is not None:       # check if the asset exsists within the Asset Database
        path_alpha = float(getAlpha(assetDatabase, rootNodeName))
    else:
        path_alpha = float(input('What is the alpha value for the attack graph: '))
    print("[+] Returning the generated SMART variables")
    if debugBit != 0:
        print("[?] Variable Check:\n\t\ttestNameList:\t\t\t{0}\n\t\ttestCVEList:\t\t\t{1}\n\t\ttestPSList:\t\t\t{2}\n\t\ttestInitCostList:\t\t{3}:\n\t\ttestAttackCostList:\t\t{4}\n\t\tpath_scaleAmount:\t\t{5}\n\t\tpath_impact:\t\t\t{6}\n\t\tpath_attackValue:\t\t{7}\n\t\tpath_alpha:\t\t\t{8}".format(testNameList, testCVEList, testPSList, testInitCostList, testAttackCostList, path_scaleAmount, path_impact, path_attackValue, path_alpha))
    return testTree, testCVEList, testNameList, testPSList, testInitCostList, testAttackCostList, path_scaleAmount, path_impact, path_attackValue, path_alpha

# Function for running the main part of the attack graph evaluation script
#   - NOTE: The function variables have some defaults set to None || False
## TODO: Have the Graph related information be passed as variables to the main() function
def main(inputFile, outputFile, xml_eval_flag=False, graph_eval_flag=False, connection_graph_filename=None, vertex_map_filename=None, edge_map_filename=None, vuln_map_filename=None):
    print("[*] ---------- Total Attack Graph Security Calculation Script ------------ [*]")
    xml_eval_flag = False
    graph_eval_flag = True          # NOTE: Will need to default to False; no done in the function call
    # Check to see which version of the evaluation is wanted to be performed
    if xml_eval_flag and not graph_eval_flag:               # XML Flag is True and Graph Flag is False
        if debugBit != 0:
            print("[!!!] Starting read_in_aadl_xml_file()")
        # Function call to obtain all the necessary variables from SMART from a provided AADL XML input file
        testTree, testCVEList, testNameList, testPSList, testInitCostList, testAttackCostList, path_scaleAmount, path_impact, path_attackValue, path_alpha = read_in_aadl_xml_file(inputFile)
    elif not xml_eval_flag and graph_eval_flag:             # XML Flag is False and Graph Flag is True
        if debugBit != 0:
            print("[!!!] Starting read_in_aadl_graph_object() call")
        # Test variables    | Only really needed for AADL Graph Evaluation
        #   - TODO: Make these not hardcoded addresses but variables that get passed to the function
        connection_graph_filename = '/tmp/connection_graph.graph'
        vertex_map_filename = '/tmp/vertex_map.json'
        edge_map_filename = '/tmp/edge_map.json'
        vuln_map_filename = '/tmp/vuln_map.json'
        entry_exit_map_filename = '/tmp/entry_exit_map.json'
        # Function call to obtain all the necessary veraibles from SMART from a provided AADL Graph Object input file
        #   - NOTE: Drop of 'trestTree' item since this is an artifact of the AADL XML conversion process
        testCVEList, testNameList, testPSList, testInitCostList, testAttackCostList, path_scaleAmount, path_impact, path_attackValue, path_alpha = read_in_aadl_graph_object(connection_graph_filename, vertex_map_filename, edge_map_filename, vuln_map_filename, entry_exit_map_filename)
    else:
        print("[-] ERROR: Unclear which form of evaluation is desired.... SMART evaluation variables have NOT been prepared\n\tXML Flag:\t\t{0}\n\tGraph Flag:\t{1}".format(xml_eval_flag, graph_eval_flag))
    # Function call to collect the cost of attack for each vulnerability in the attack graph
    if debugBit != 0:
        print("[*] Calling security risk script with varaibles")
    '''
     Note: Input to the function below must be in a specific order
        - item_PS
        - item_alpha
        - item_attackValue
        - item_attackCost
        - item_impact
        - item_ci
        - item_cost_maintenance
        - item_cost_operation
        - item_scaleAmount
    '''
    #Calculation.securityRisk.main([testCVSS], 1, 20, 7, 11.7, [6000, 13000], 70000, 2450, 1000)
    #Calculation.securityRisk.main(item_PS, 1, 20, 7, 11.7, [6000, 13000], 70000, 2450, 1000)
    pathList_SecurityRisk = []
    trackPathVar = 0
    maxPathSRSeen = 0
    maxPathVar = 0
    maxSubPathSRSeen = 0
    maxSubPathVar = 0
    minPathSRSeen = -1
    minPathVar = 0
    minSubPathSRSeen = 0
    minSubPathVar = 0
    ## Variables for the cost_of_operation and cost_of_maintenance
    cost_of_operation = 2450            # Ex: Cost of powering/operating the system     \___ NOTE: These values do NOT need to be scaled
    cost_of_maintenance = 70000         # Ex: Cost of employee to maintain the system   /
    # TODO: Add in structure of tracking the most ``expensive'' attack path
    #   - NOTE: If the path_ps and CVE_list arrays are of the SAME SIZE, then it should just be tracking a single ``array location value'' to determine the most detrimental path
    # Loop through each path of items to calculate the security risk per path
    #   Nota Bene: Expectation is that the size of the lists is the same!! It should be based on how the code is written
    for subList in range(len(testPSList)):                      # <---------    Nota Bene: This testPSList is a list of path_ps for each attack path, therefore only need to track at THIS LEVEL to find highest cost path
        # Calculate security risk value for each path based on the provided lists of probabilitiy of success & initial costs for each element
        #Calculation.securityRisk.main(testPSList[subList], 1, 20, 7, 11.7, testInitCost[subList], 70000, 2450, 1000)  # This call works
        # Calling the function directly instead of using the main() function        | Below is the best example function call
        #pathList_SecurityRisk.append(Calculation.securityRisk.pathCostCalc(testPSList[subList], path_alpha, path_attackValue, testAttackCostList[subList], path_impact, testInitCostList[subList], 70000, 2450, path_scaleAmount))  # Ensure that scaling is the SAME!!!
        # Version that REMOVES the Cost of Operation (e.g. makes the value 0) & Cost of Maintainence (???)
        #pathList_SecurityRisk.append(Calculation.securityRisk.pathCostCalc(testPSList[subList], path_alpha, path_attackValue, testAttackCostList[subList], path_impact, testInitCostList[subList], 70000, 0, path_scaleAmount))  # Ensure that scaling is the SAME!!!
        #pathList_SecurityRisk.append(Calculation.securityRisk.pathCostCalc(testPSList[subList], path_alpha, path_attackValue, testAttackCostList[subList], path_impact, testInitCostList[subList], 0, 2450, path_scaleAmount))  # Ensure that scaling is the SAME!!!
        #pathList_SecurityRisk.append(Calculation.securityRisk.pathCostCalc(testPSList[subList], path_alpha, path_attackValue, testAttackCostList[subList], path_impact, testInitCostList[subList], 0, 0, path_scaleAmount))  # Ensure that scaling is the SAME!!!
        ## NOTA BENE: Check that this section is being done correctly, other create a user provided vs 'automatic' version of operation
        # Call to the function for performing the Security Risk Calculation for each subList in the larger Probabilities of Success Attack Path List
        pathList_SecurityRisk.append(Calculation.securityRisk.pathCostCalc(testPSList[subList], path_alpha, path_attackValue, testAttackCostList[subList], path_impact, testInitCostList[subList], cost_of_maintenance, cost_of_operation, path_scaleAmount))  # Ensure that scaling is the SAME!!!
        '''
          NEED:  Write code to perform summation of cost of attacks for vulnerabilities in attack path [Note: similar to prob of success, but summation NOT product]
            -> Fix to make use of list for calculatsions
        '''
        # Debug output to check values                                  # <=============== This is where we can interpret the contents of the Subpath variables; NOTE: Each entry contains information for Max SR + Item and Min SR + Item ONLY for the specific PATH combination
        subPathSR = pathList_SecurityRisk[trackPathVar][0]
        subPathMaxSR = pathList_SecurityRisk[trackPathVar][1]
        subPathMaxSRitem = pathList_SecurityRisk[trackPathVar][2]
        # TODO: Add the min version of variables for tracking
        subPathMinSR = pathList_SecurityRisk[trackPathVar][3]           # <----- Note: These are getting stuck with the subPathMaxSR value....
        subPathMinSRitem = pathList_SecurityRisk[trackPathVar][4]
        if debugBit != 0:   # ~!~       TODO: Add in a better check for confirming index array out of bounds
            print("[?] Loop Test:\n\tSub List:\t{0}\n\tFull List:\t{1}".format(subList, testPSList))
            print("[?] --------- Max SR Path Check --------- [?]\n\ttrackPathVar:\t{0}\n\tmaxPathSRSeen:\t{1}\n\tpathSRreturn:\t{2}\n\tMax pathSR:\t{3}\n\tMax pathSR #:\t{4}\n".format(trackPathVar, maxPathSRSeen, pathList_SecurityRisk[trackPathVar], subPathMaxSR, subPathMaxSRitem))
            print("[?] --------- Min SR Path Check --------- [?]\n\ttrackPathVar:\t{0}\n\tminPathSRSeen:\t{1}\n\tpathSRreturn:\t{2}\n\tMin pathSR:\t{3}\n\tMin pathSR #:\t{4}\n".format(trackPathVar, minPathSRSeen, pathList_SecurityRisk[trackPathVar], subPathMinSR, subPathMinSRitem))
        # Check to see what the highest SR seen is      || Nota Bene: This is the Max SR Path at the HIGHEST LEVEL!! TODO: Create function to determine most expensive sub-path under each set
        if subPathSR > maxPathSRSeen:
            maxPathSRSeen = subPathSR
            maxPathVar = trackPathVar
            maxSubPathSRSeen = subPathMaxSR
            maxSubPathVar = subPathMaxSRitem
        if minPathSRSeen == -1:
            minPathSRSeen = subPathSR
            minPathVar = trackPathVar
            # TODO: Add minSubPathSRSeen + Var to output; may require adding it to the pathCostCalc function
            minSubPathSRSeen = subPathMinSR
            minSubPathVar = subPathMinSRitem
        elif subPathSR < minPathSRSeen:
            minPathSRSeen = subPathSR
            minPathVar = trackPathVar
            # TODO: Add in min verison of variables
            minSubPathSRSeen = subPathMinSR
            minSubPathVar = subPathMinSRitem
        trackPathVar += 1
    if detailDebugBit != 0:
        print("Figure this out....\n\tCVE List:\t{1}\n\tMax Path:\t{2}\n\tMin Path:\t{3}\n\tTest Itertools:\t{0}".format(itertools.product(*testCVEList[maxPathVar]), testCVEList, testCVEList[maxPathVar], testCVEList[minPathVar]))
        print("List of different path security risk values: " + str(pathList_SecurityRisk))
    # NEED: Next summation of all the path security risk values to obtain the overall security risk
    print("[?] Testing:\n\tmaxPathVar:\t{0}\n\tmaxSubPathVar:\t{1}\n\ttestCVEList:\t{2}".format(maxPathVar, maxSubPathVar, testCVEList))
    print("\tAttack Path Elements:\t{0}".format(testNameList))
    print("\tNumber of Potential Attack Path Combinations:\t{0}".format(len(list(itertools.product(*testCVEList)))))        ## NOTE: This provides a high level look at the potenital attack path combinations; should be accurate
    track_outter_combinations = 0
    track_inner_combinations = 0
    total_combinations = 0              # Variable for holding the total number of attack paths
    for outter_list in list(itertools.product(*testCVEList)):
        track_outter_combinations += 1
        track_inner_combinations += len(list(itertools.product(*outter_list)))
    total_combinations = track_outter_combinations + track_inner_combinations
    print("\tNumber of Total Potential Attack Paths:\t{0}".format(total_combinations))
    print("\tminPathVar:\t{0}\n\tminSubPathVar:\t{1}".format(minPathVar, minSubPathVar))
    try:
        print("\tTesting Max CVE:\t{0}".format(testCVEList[maxPathVar][maxSubPathVar]))
    except IndexError:
        print("\tTesting Max CVE:\t{0}".format("No max CVE... Index Error"))
    try:
        print("\tTesting Min CVE:\t{0}".format(testCVEList[minPathVar][minSubPathVar]))
    except IndexError:
        print("\tTesting Min CVE:\t{0}".format("No min CVE.... Index Error"))
    try:
        print("\tTest Itertools Max:\t{0}".format(list(itertools.product(*testCVEList[maxPathVar]))[maxSubPathVar]))
    except IndexError:
        print("\tTest Itertools Max:\t{0}".format("No vulnerable attack path... Index Error"))          # NOTA BENE: These excepts are for the instance that a complete path DOES NOT EXIST, and NOT when a Pa drops to ZERO
    try:
        print("\tTest Itertools Min:\t{0}".format(list(itertools.product(*testCVEList[minPathVar]))[minSubPathVar]))
    except IndexError:
        print("\tTest Itertools Min:\t{0}".format("No vulnerable attack path... Index Error"))
    # NEED: Identify corresponding CVE combination for most expensive path
    print("[+] =============================================================== [+]\n\t\tSummary of {0} SMART Evaluation".format(str(inputFile)))
    # Print out the Maximum SR Tuple and Subpath information
    print("\tMost Expensive/Risky Subpath Tuple:\t\t{0}".format(pathList_SecurityRisk[maxPathVar]))
    try:
        print("\tAssociated CVEs to Max SR Subpath:\t\t{0}".format(list(itertools.product(*testCVEList[maxPathVar]))[maxSubPathVar]))       # NOTE: This use of itertools.product(*n_sets) creates an n-fold Cartesian product
    except IndexError:
        print("\tAssociated CVEs to Max SR Subpath:\t\t{0}".format("No vulnerable attack path... Index Error"))       # NOTE: This use of itertools.product(*n_sets) creates an n-fold Cartesian product
    print("\tMaximum SR Seen from Subpath Tuple:\t\t{0}".format(maxPathSRSeen))
    print("\tMaximum SR Subpath - Total Cost:\t\t{0}".format(maxSubPathSRSeen * path_scaleAmount))
    print("\tItem in Potential Path Tuple SR:\t{0}".format(maxPathVar))
    print("\tItem in Product Array of Max SR:\t{0}".format(maxSubPathVar))
    print("\t-----------------------------------------------------------------")
    # Print out the Minimum SR Tuple and Subpath information
    print("\tLeast Expensive/Risky Subpath Tuple:\t\t{0}".format(pathList_SecurityRisk[minPathVar]))
    try:
        print("\tAssociated CVEs to Min SR Subpath:\t\t{0}".format(list(itertools.product(*testCVEList[minPathVar]))[minSubPathVar]))
    except IndexError:
        print("\tAssociated CVEs to Min SR Subpath:\t\t{0}".format("No vulnerable attack path... Index Error"))
    print("\tMinimum SR Seen from Subpath Tuple:\t\t{0}".format(minPathSRSeen))
    print("\tMinimum SR Subpath - Total Cost:\t\t{0}".format(minSubPathSRSeen * path_scaleAmount))
    print("\tItem in Potential Path Tuple SR:\t{0}".format(minPathVar))
    print("\tItem in Product Array of Min SR:\t{0}".format(minSubPathVar))
    print("\t-----------------------------------------------------------------")
    print("\n\n\tFull Path List Security Risk Evaluation Generated Output:\t{0}".format(pathList_SecurityRisk))
    print("\tTotal Number of Potential Attack Paths:\t{0}".format(total_combinations))
    print("\tAttack Path Combinations Elements:\t{0}".format(testNameList))
    print("[+] =============================================================== [+]")
    ## Writing the same print above but to an output file
    smartOutput_formatted(inputFile, outputFile, pathList_SecurityRisk, testCVEList, maxPathVar, maxSubPathVar, maxPathSRSeen, maxSubPathSRSeen, minPathVar, minSubPathVar, minPathSRSeen, minSubPathSRSeen, path_scaleAmount, testNameList, total_combinations)
    return pathList_SecurityRisk

# Function for running test suite to make sure that the code is still functioning as expected
#   -> NOTE: This is based on the values calculated during inital code writing and testing
#       - Directory full of Test Files: TestFiles/
def sanityTest():
    print("[*] Running sanity test for SMART software....")
    print("--------------------------------------------")
    print("\tBeginning test of easyDoS.attacktree")
    test01 = graphToRisk('TestFiles/easyDoS.attacktree')
    print("\tBeginning test of easyDoSEdit.attacktree")
    test02 = graphToRisk('TestFiles/easyDoSEdit.attacktree')
    print("--------------------------------------------")
    print("\tBeginning test of easyDoSFixed.attacktree")
    test03 = graphToRisk('TestFiles/easyDoSFixed.attacktree')
    print("--------------------------------------------")
    print("\tBeginning test of threeTreeTest.attacktree")
    test04 = graphToRisk('TestFiles/threeTreeTest.attacktree')
    print("--------------------------------------------")
    print("\tBeginning test of threeTreeTest.var01.attacktree")
    test05 = graphToRisk('TestFiles/threeTreeTest.var01.attacktree')
    print("--------------------------------------------")
    print("\tBeginning test of threeLineTest.attacktree")
    test06 = graphToRisk('TestFiles/threeLineTest.attacktree')
    print("--------------------------------------------")
    print("\tBeginning test of threeLineTest.var01.attacktree")
    test07 = graphToRisk('TestFiles/threeLineTest.var01.attacktree')
    print("--------------------------------------------")
    print("\tBeginning test of threeLineTest.var02.attacktree")
    test08 = graphToRisk('TestFiles/threeLineTest.var02.attacktree')
    print("--------------------------------------------")
    print("\tBeginning test of threeTreeTest.var02.attacktree")
    test09 = graphToRisk('TestFiles/threeTreeTest.var02.attacktree')
    print("--------------------------------------------")
    print("\tBeginning test of fourYTest.attacktree")
    test10 = graphToRisk('TestFiles/fourYTest.attacktree')
    print("--------------------------------------------")
    print("\tBeginning test of fourYTest.var01.attacktree")
    test11 = graphToRisk('TestFiles/fourYTest.var01.attacktree')
    print("--------------------------------------------")
    print("\tBeginning test of fourYTest.var02.attacktree")
    test12 = graphToRisk('TestFiles/fourYTest.var02.attacktree')
    print("--------------------------------------------")
    print("\tBeginning test of fiveTreeTest.attacktree")
    test13 = graphToRisk('TestFiles/fiveTreeTest.attacktree')
    print("--------------------------------------------")
    print("\tBeginning test of fiveTreeTest.var01.attacktree")
    test14 = graphToRisk('TestFiles/fiveTreeTest.var01.attacktree')
    print("--------------------------------------------")
    print("\tBeginning test of fiveTreeTest.var02.attacktree")
    test15 = graphToRisk('TestFiles/fiveTreeTest.var02.attacktree')
    print("--------------------------------------------")
    print("\tBeginning test of fiveTreeTest.var03.attacktree")
    test16 = graphToRisk('TestFiles/fiveTreeTest.var03.attacktree')
    print("--------------------------------------------")
    print("[*] Printing findings from sanity testing:")
    print("\tTest 01:\t" + str(test01))
    print("\tTest 02:\t" + str(test02))
    print("\tTest 03:\t" + str(test03))
    print("\tTest 04:\t" + str(test04))
    print("\tTest 05:\t" + str(test05))
    print("\tTest 06:\t" + str(test06))
    print("\tTest 07:\t" + str(test07))
    print("\tTest 08:\t" + str(test08))
    print("\tTest 09:\t" + str(test09))
    print("\tTest 10:\t" + str(test10))
    print("\tTest 11:\t" + str(test11))
    print("\tTest 12:\t" + str(test12))
    print("\tTest 13:\t" + str(test13))
    print("\tTest 14:\t" + str(test14))
    print("\tTest 15:\t" + str(test15))
    print("\tTest 16:\t" + str(test16))
    print("[*] Completed sanity test for SMART software")

# Function that allows this script to be imported without automatically running the main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Evaluate an attack tree to determine security risk.')
    # Add inputs to the function
    parser.add_argument("inputAttackTree", help="Path and name of the Attack Tree file")
    parser.add_argument("outputSummaryFile", help="Path and name of the Summary File to be Output")
    parser.add_argument("-v", "--verbose", action="store_true")
    # Grab the arguments passed to the file
    args = parser.parse_args()
    parser.parse_args()
    print("[?] Verbosity Level: {0}".format(args.verbose))
    debugBit = args.verbose
    main(args.inputAttackTree, args.outputSummaryFile)
