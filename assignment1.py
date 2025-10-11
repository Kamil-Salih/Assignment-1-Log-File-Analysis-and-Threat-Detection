'''
Title: Log File Analysis and Threat Detection
Student name: Kamil Salih
Student number: C00307549
Group: CW_KCCYB_B
Last updated: 11/10/2025
Description: A Python script that automates detection of common attack patterns in a log file.
'''

#Imports
from collections import defaultdict #...(part 2)
from datetime import datetime #...(part 3)
from datetime import timedelta #...(part 3)

#Variables
counts = defaultdict(int)           # Create a dictionary to keep track of IPs (part 2)
logfile= "CA1_project.log"
incidents = []
window = timedelta(minutes=10)


#Functions
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




def parse_auth_line(line): #part 3
    """
    Parse an auth log line and return (timestamp, ip, event_type)
    Example auth line:
    Mar 10 13:58:01 host1 sshd[1023]: Failed password for invalid user admin from 203.0.113.45 port 52344 ssh2
    We will:
     - parse timestamp (assume year 2025)
     - extract IP (token after 'from')
     - event_type: 'failed' if 'Failed password', 'accepted' if 'Accepted password', else 'other'
    """
    parts = line.split()
    # timestamp: first 3 tokens 'Mar 10 13:58:01'
    ts_str = " ".join(parts[0:3])
    try:
        ts = datetime.strptime(f"2025 {ts_str}", "%Y %b %d %H:%M:%S")
    except Exception:
        ts = None
    ip = None
    event_type = "other"
    if "Failed password" in line:
        event_type = "failed"
    elif "Accepted password" in line or "Accepted publickey" in line:
        event_type = "accepted"
    if " from " in line:
        try:
            idx = parts.index("from")
            ip = parts[idx+1]
        except (ValueError, IndexError):
            ip = None
    return ts, ip, event_type



#Main code

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

print("\n")

#3.	Identify possible brute-force attacks (≥ 5 failed logins from one IP within 10 minutes).

if __name__ == "__main__":
    per_ip_timestamps = defaultdict(list)
    with open(logfile) as f:
        for line in f:
            ts, ip, event = parse_auth_line(line)
            if ts and ip and event == "failed":   # checks that ts and ip are not null, and that event=="failed"
                per_ip_timestamps[ip].append(ts)


    for ip in per_ip_timestamps: #added part
        per_ip_timestamps[ip].sort()

    # quick print
    for ip, times in per_ip_timestamps.items():
        print(ip, len(times))


for ip, times in per_ip_timestamps.items():
    times.sort()
    n = len(times)
    i = 0
    while i < n:
        j = i
        while j + 1 < n and (times[j+1] - times[i]) <= window:
            j += 1
        count = j - i + 1
        if count >= 5:
            incidents.append({
                "ip": ip,
                "count": count,
                "first": times[i].isoformat(),
                "last": times[j].isoformat()
            })
            # advance i past this cluster to avoid duplicate overlapping reports:
            i = j + 1
        else:
            i += 1

print("\n")
print(f"Detected {len(incidents)} brute-force incidents")

for incident in incidents[:5]:
    print(incident)
