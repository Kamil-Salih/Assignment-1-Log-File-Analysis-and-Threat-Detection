'''
Title: Log File Analysis and Threat Detection
Student name: Kamil Salih
Student number: C00307549
Group: CW_KCCYB_B
Last updated: 12/10/2025
Description: A Python script that automates detection of common attack patterns in a log file.
'''

#Imports
from collections import defaultdict #...(part 2)
from datetime import datetime #...(part 3)
from datetime import timedelta #...(part 3)
import json #...(part 3)
import matplotlib.pyplot as plt

#Variables
counts = defaultdict(int)           # Create a dictionary to keep track of IPs (part 2)
logfile= "CA1_project.log"
incidents = []
window = timedelta(minutes=10)
total_successful_logins=0 #part 5
total_failed_logins=0 #part 5
total_logins=0 #part 5
ips = [] #part 5
unique_ips = [] #part 5
failed_attempt_counts = defaultdict(int) #part 7


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


with open("bruteforce_incidents.txt", "w") as f: #New change!
    json.dump(incidents, f, indent=2)
print("\n")
print(f"Saved {len(incidents)} incidents to bruteforce_incidents.txt")


#4.	Output results into a structured report.

print("\n")

with open("structured_report.txt", "w") as f5:
    f5.write("Failed Login Counts")
    f5.write("\n")
    with open("failed_counts.txt", "r") as f_counts: #file failed counts
        f5.write(f_counts.read())
    
    f5.write("\n")
    f5.write("Brute-force Incidents")
    f5.write("\n")
    with open("bruteforce_incidents.txt", "r") as f_incidents: #file bruteforce incidents
        f5.write(f_incidents.read())

print("Created structured_report.txt, it stores failed counts and brute-force incidents.")


#5.	Create a detailed statistical summary of the provided log file. (eg. Total number of logins, by day, unique IPs, Geolocations etc whatever you can think of) 

#Total number of logins
with open(logfile, "r") as f:
    for line in f:
        if "Accepted" in line:
            total_successful_logins=total_successful_logins+1
        elif "Invalid" in line or "Failed" in line:
            total_failed_logins=total_failed_logins+1

total_logins=total_successful_logins+total_failed_logins
print("\n")

with open("logins.txt", "w") as f_logins: #file unique IPs
    f_logins.write("Logins")
    f_logins.write("\n")
    f_logins.write(f"Total logins: {total_logins}")
    f_logins.write("\n")
    f_logins.write(f"Total successful logins: {total_successful_logins}")
    f_logins.write("\n")
    f_logins.write(f"Total failed logins: {total_failed_logins}")
    f_logins.write("\n")

print("Created logins.txt, it stores total logins, total successful logins, and total failed logins")


#unique IPs

with open(logfile, "r") as f:
        for line in f:
            ip=ip_parse(line.strip())
            if ip:
                unique_ips.append(ip)

unique_ips = set(unique_ips)


print("\n")

with open("unique_ips.txt", "w") as f_unique: #file unique IPs
    f_unique.write("Unique IP Addresses")
    f_unique.write("\n")
    for ip in sorted(unique_ips):
        f_unique.write(ip)
        f_unique.write("\n")

print(f"Found {len(unique_ips)} unique IPs and saved to unique_ips.txt")


with open("statistical_summary.txt", "w") as f6:
    f6.write("\n")
    with open("logins.txt", "r") as f_logins: #file logins
        f6.write(f_logins.read())
    
    f6.write("\n")

    with open("unique_ips.txt", "r") as f_unique_ips: #file unique IPs
        f6.write(f_unique_ips.read())

print("\n")
print("Created statistical_summary.txt, it stores logins and unique IPs.")


#Part 6 (skipped)


#7.	Visualise findings (bar chart of attacker IPs).

for ip, timestamps in per_ip_timestamps.items():
    failed_attempt_counts[ip] = len(timestamps)

def top_n(counts_dict, n=10):
    return sorted(counts_dict.items(), key=lambda kv: kv[1], reverse=True)[:n]

top_10_attacker_ips = top_n(failed_attempt_counts, n=10)

#clears variables ips and counts from previous use
ips = []
counts = []

for ip, failed_count in top_10_attacker_ips:
    ips.append(ip)
    counts.append(failed_count)


plt.figure(figsize=(15,10))
plt.bar(ips, counts)
plt.title("Top 10 attacker IPs")
plt.xlabel("IP")
plt.ylabel("Failed attempts")
plt.tight_layout()
plt.savefig("top_attackers.png")
plt.show()
