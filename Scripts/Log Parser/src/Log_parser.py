import re

def extract_ip(line):
    pattern = r"\d+\.\d+\.\d+\.\d+"
    ips = re.findall(pattern, line)
    return ips 

with open("Scripts/Log Parser/Samples/Auth.log") as file:
     counts = {"error": 0, "Failed password": 0, "Disconnecting": 0}
     for line in file: 
       if "error" in line:
           counts["error"] += 1
           ips = extract_ip(line)
           print(ips)

       if "Failed password" in line:
            counts["Failed password"] += 1
            ips = extract_ip(line)
        
       if "Disconnecting" in line:
           counts["Disconnecting"] += 1
           ips = extract_ip(line)
print(counts)

