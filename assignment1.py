'''
Title: Log File Analysis and Threat Detection
Student name: Kamil Salih
Student number: C00307549
Group: CW_KCCYB_B
Last updated: 11/10/2025
Description: A Python script that automates detection of common attack patterns in a log file.
'''

from collections import defaultdict #...(part 2)
counts = defaultdict(int)           # Create a dictionary to keep track of IPs (part 2)


logfile= "CA1_project.log"


def ip_parse(line): #part 2
    """
    looks for the substring ' from ' and returns the following IP address.
    Returns None if no matching substring found.
    """
    if " from " in line:
        parts = line.split() # splits the line into tokens, seperates by spaces by default
        try:
            anchor = parts.index("from")    # Find the position of the token "from", our anchor
            ip = parts[anchor+1]          # the from value will be next token, anchor+1
            return ip.strip(',:;]')             # strip any trailing punctuation

        except (ValueError, IndexError):
            return None

    return None



#1.	Parse log file line by line

with open(logfile, 'r') as f:
    for line in f:
        print(line.strip())

print("\n")

#2.	Detect and count failed login attempts, grouping by source IP.

with open(logfile) as f1:
    for line in f1:
        if "Failed password" in line or "Invalid user" in line:
            # extract ip
            ip = ip_parse(line)
            if ip:
                counts[ip] += 1

with open('failed_counts.txt', 'w') as f2:
    f2.write("ip,failed_count")
    f2.write("\n")
    for ip in counts:
        f2.write(f"{ip},{counts[ip]}")
        f2.write("\n")

with open('failed_counts.txt', 'r') as f3:
    contents = f3.read()
    print(contents)