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
    
     #process each line of the authentication log 
     for line in file: 
       if "error" in line:
           counts["error"] += 1
           ips = extract_ip(line)
           if ips:
              if ips[0] in ip_counts:
                  ip_counts[ips[0]] +=1 
              else:
                   ip_counts[ips[0]] = 1

       #Count failed password events and associated IP addresses
       if "Failed password" in line:
            counts["Failed password"] += 1
            ips = extract_ip(line)
            if ips:
               if ips[0] in ip_counts:
                  ip_counts[ips[0]] +=1 
               else:
                   ip_counts[ips[0]] = 1

       if "Disconnecting" in line:
           counts["Disconnecting"] += 1
           ips = extract_ip(line)
           if ips:
              if ips[0] in ip_counts:
                  ip_counts[ips[0]] +=1 
              else:
                   ip_counts[ips[0]] = 1
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

