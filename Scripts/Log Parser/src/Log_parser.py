#Import required module for regular expressions
import re 
#Import CSV module for CSV export feature
import csv 
#Import JSON module for JSON export feature
import json

#Risk classification thresholds
HIGH_RISK_THRESHOLD = 21
MEDIUM_RISK_THRESHOLD = 5
FREQUENCY_THRESHOLD = 10 

#Extract IPv4 addresses from a single log entry
def extract_ip(line):
    pattern = r"\d+\.\d+\.\d+\.\d+"
    ips = re.findall(pattern, line)
    return ips 

#Analyse each detected source IP and assign a risk classification
def analyse_risk(ip_events):

    #Track the number of IPs assigned to each risk category
    risk_counts = {
        "HIGH" : 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    #Analyse each detected source IP
    for ip, events in ip_events.items():
        #Retrieve the failed password count for the current source IP
        failed_passwords = events["Failed password"]

        #Classify the source IP based on failed password thresholds
        if failed_passwords >= HIGH_RISK_THRESHOLD:
            risk = "HIGH"
        elif failed_passwords >= MEDIUM_RISK_THRESHOLD:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        # Store the calculated risk level for the current source IP
        events["Risk"] = risk

        # Update the overall count for the assigned risk category
        risk_counts[risk] +=1 

    return ip_events, risk_counts 
        

# Process the authentication log
def process_log(file_path):

    # Track SSH event totals
    counts = {
        "error": 0,
        "Failed password": 0,
        "Disconnecting": 0
    }

    # Track occurrences of IP addresses
    ip_counts = {}

    # Track SSH authentication events associated with each source IP
    ip_events = {}

    # Open and process the authentication log
    with open(file_path) as file:

        # Process each line of the authentication log
        for line in file:

            # Count authentication errors and associate them with source IP addresses
            if "error" in line:
                counts["error"] += 1
                ips = extract_ip(line)

                # Store error events for each detected source IP
                if ips:
                    if ips[0] not in ip_events:
                        ip_events[ips[0]] = {
                            "Failed password": 0,
                            "error": 1
                        }
                    else:
                        ip_events[ips[0]]["error"] += 1

                    # Track how many times each source IP appears in the log
                    if ips[0] in ip_counts:
                        ip_counts[ips[0]] += 1
                    else:
                        ip_counts[ips[0]] = 1

            # Count failed password events and associated IP addresses
            if "Failed password" in line:
                counts["Failed password"] += 1
                ips = extract_ip(line)

                # Store failed password events for each detected source IP
                if ips:
                    if ips[0] not in ip_events:
                        ip_events[ips[0]] = {
                            "Failed password": 1,
                            "error": 0
                        }
                    else:
                        ip_events[ips[0]]["Failed password"] += 1

                    # Track how many times each source IP appears in the log
                    if ips[0] in ip_counts:
                        ip_counts[ips[0]] += 1
                    else:
                        ip_counts[ips[0]] = 1

            # Count disconnecting events detected in the authentication log
            if "Disconnecting" in line:
                counts["Disconnecting"] += 1
    
    # Return the processed log data
    return counts, ip_counts, ip_events 

def export_csv(ip_events,filename):
    with open(filename, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            "Source IP", 
            "Failed Passwords", 
            "Errors", 
            "Risk"])
        for ip, events in ip_events.items():
            writer.writerow([
                ip,
                events["Failed password"],
                events["error"],
                events["Risk"]
            ])

def export_json(ip_events, filename):
    with open(filename,"w") as file: 
        json.dump(ip_events,file, indent=4)


#Run the function and receive its results
counts, ip_counts, ip_events = process_log(
    "Scripts/Log Parser/Samples/Auth.log"
    )
ip_events,risk_counts = analyse_risk(ip_events)

print("=== SSH Event Summary ===\n")

print(f"Errors: {counts['error']}")
print(f"Failed Passwords: {counts['Failed password']}")
print(f"Disconnecting Events: {counts['Disconnecting']}\n")

#Display an overall summary of classified threat levels
print("=== Threat Assessment ===\n")
print("Risk Classification")
print("--------------------\n")
print("HIGH: 21+ Failed Passwords")
print("MEDIUM: 5-20 Failed Passwords")
print("LOW: 1-4 Failed Passwords\n")

#Display the total number of IPs within each risk category
print(f"High Risk IPs: {risk_counts['HIGH']}")
print(f"Medium Risk IPs: {risk_counts['MEDIUM']}")
print(f"Low Risk IPs: {risk_counts['LOW']}")

print("\n=== High Frequency Source IPs (10+ Events) ===")
#Display frequently observed source IPs ordered by event frequency
for ip, count in sorted(ip_counts.items(), key=lambda item: item[1], reverse=True):
    if count > FREQUENCY_THRESHOLD:  #Only display source IPs observed more than ten times 
       print(f"{ip}: {count}")

print("\n=== IP Activity Report === ")
#Display detailed activity for each source IP ordered by failed password count
for ip, events in sorted(ip_events.items(), key=lambda item: item[1]["Failed password"], reverse=True):
    #Retrieve stored event totals for the current source IP
    failed_passwords = events["Failed password"]
    
    #Only display source IPs with multiple failed password attempts
    if failed_passwords >1:
       print("============================")
       print(f"Source IP: {ip}\n")
       print(f"Risk: {events['Risk']}\n")
       print(f"Failed Passwords: {events['Failed password']}")
       print(f"Errors: {events['error']}\n")
       
print("-------------------")
#Indicate that log analysis has completed
print("Analysis Complete\n")

#Export analysis results as CSV file
export_csv(ip_events, "analysis_results.csv")

#Export analysis results as JSON file
export_json(ip_events,"analysis_results.json")