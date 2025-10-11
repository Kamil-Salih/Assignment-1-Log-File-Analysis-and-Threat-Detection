'''
Title: Log File Analysis and Threat Detection
Student name: Kamil Salih
Student number: C00307549
Group: CW_KCCYB_B
Last updated: 11/10/2025
Description: A Python script that automates detection of common attack patterns in a log file.
'''

logfile= "CA1_project.log"

#1.	Parse log file line by line

with open(logfile, 'r') as f:
    for line in f:
        print(line.strip())