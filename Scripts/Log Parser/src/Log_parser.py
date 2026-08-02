#Import required module for regular expressions
import re 

#Extract IPv4 addresses from a single log entry
def extract_ip(line):
    pattern = r"\d+\.\d+\.\d+\.\d+"
    ips = re.findall(pattern, line)
    return ips 

#Open and process the authentication log
with open("Scripts/Log Parser/Samples/Auth.log") as file:
     #Track SSH event totals
     counts = {"error": 0, "Failed password": 0, "Disconnecting": 0}
     #Track occurences of IP adresses
     ip_counts = {}
     #Track occurrences of extracted IP addresses
     ip_events = {}
    
     #process each line of the authentication log 
     for line in file: 
     #Count authentication errors and associate them with source IP addresses
       if "error" in line:
           counts["error"] += 1
           ips = extract_ip(line)
           #Store error events for each detected source IP
           if ips:
              if ips[0] not in ip_events:
                  ip_events[ips[0]] = {
                      "Failed password" : 0,               
                      "error": 1
                  }
              else:
                  ip_events[ips[0]]["error"] +=1
            #Track how many times each source IP appears in the log
              if ips[0] in ip_counts:
                     ip_counts[ips[0]] +=1
              else:
                    ip_counts[ips[0]] = 1

       #Count failed password events and associated IP addresses
       if "Failed password" in line:
            counts["Failed password"] += 1
            ips = extract_ip(line)
            #Store failed password events for each detected source IP
            if ips:
               if ips[0] not in ip_events:

                   ip_events[ips[0]] = {

                       "Failed password":1,
                       "error":0
                   }
               else:
                     ip_events[ips[0]]["Failed password"] +=1 
            #Track how many times each source IP appears in the log
               if ips[0] in ip_counts:
                   ip_counts[ips[0]] +=1 
               else:
                    ip_counts[ips[0]] = 1
                    
    #Count disconnecting events detected in the authentication log
       if "Disconnecting" in line:
           counts["Disconnecting"] += 1
                  
                  
#Display a summary of all detected SSH authentication events
print("=== SSH Event Summary ===\n")

print(f"Errors: {counts['error']}")
print(f"Failed Passwords: {counts['Failed password']}")
print(f"Disconnecting Events: {counts['Disconnecting']}")
#display the occurence count for each detected IP address
print("\n=== Repeated IP Addresses === ")
#iterate through each IP address and display its occurence count
for ip, count in ip_counts.items():
    if count > 1:  #if an IP address occures more than once 
       print(f"{ip}: {count}")
#Display SSH activity associated with each detected source IP
print("\n=== IP Activity Report === ")
#Display source IPs with repeated failed password attempts
for ip, events in ip_events.items():
    if events["Failed password"] >1:
       print("============================")
       print(f"Source IP: {ip}\n")
       print(f"Failed Passwords: {events['Failed password']}")
       print(f"Errors: {events['error']}")

  