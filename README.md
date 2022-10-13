# GTS-Framework
Combination of GAM-TAMSAT-SMART into a framework for the exploration of design space via security risk analysis with a monetary metric.

The goal of this framework is to:
1. Lower the bar of entry for individuals working on Secure Design Exploration
2. Provide a determinisitic method of producing a monetary risk metric for the design
3. Give a publically accessible repository of databases that address the lack of expenses relating to defender/attacker roles
4. Automate the process to ensure comparability of designs given use of the same initial variable values within the framework

## Security Model Aversarial Risk-based Tool (SMART)
The purpose of the SMART tool is to analyze the contributions of risk towards a single Asset of Importance (AoI) and produce a monetary metric representing the Security Risk of a given Design (represented as an attack tree format).

Excerpt from Thesis: 
> This tool is focused on the evaluation of an AADL model representation (i.e. AADL XML file, Graph Object + helper files). 
> The tool requires a series of variables that represent costs and value assessments relating to defender and attacker. 
> It should be noted that determining these values can be a complicated if not a potentially impossible task. 
> ... 
> The end evaluation of the AADL model’s Security Risk is a monetary value in USD.

## Translation of AADL Model to Security Attack Tree (TAMSAT)
The purpose of the TAMSAT tool is to convert an Architecture Analysis & Design Language (AADL) model into the attack tree format that is fed into SMART.  The main aspect of TAMSAT is that it performs the vulnerabilitiy analysis of the design components and places those associations into the attack tree output.

Excerpt from Thesis:
> This tool is focused on the interpretation and translation of AADL model files into a structure that can then be passed along to the SMART tool (for evaluation of the Security Risk). 
> The current state of the TAMSAT tools allow for translation of the AADL model into either an AADL XML form or as a Python Graph Object with helper files.

## Generation of AADL Models (GAM)
The purpose of the GAM tool is to generate a series of design models based on an initial input file from the user.  These input paramters are used to define the design space to be explored, as well as any constraints placed on the design by the user.

Excerpt from Thesis:
> This tool is focused on the generation of AADL models based on some preconceived user requirements. 
> The tool is written to provide AADL models that contain the bus, data, device, and system definitions that represent the intended model (e.g. IoT Home)

# Current State of the Tool
A basic Proof-of-Concept for the entire framework has been produced and can be run from beginning to end.

In order to improve the functionality of the framework one should:
1. Update the SMART databases with the appropriate cost and probability values for various components
2. Update the contents of the TAMSAT databases relating to vulnerabilities (software and hardware)
3. Update the GAM component databases to expand the potential design space that can be explored by the framework
