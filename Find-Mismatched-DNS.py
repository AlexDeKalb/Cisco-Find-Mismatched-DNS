import re
import socket
from netmiko import ConnectHandler

def connect_to_switch(hostname, username, password):
    device = {
        'device_type': 'cisco_ios',
        'ip': hostname,
        'username': username,
        'password': password,
    }
    return ConnectHandler(**device)

def get_arp_table(connection):
    arp_output = connection.send_command('show ip arp')
    return parse_arp_table(arp_output)

def parse_arp_table(arp_output):
    arp_table = []
    lines = arp_output.split("\n")

    for line in lines:
        if "Internet" in line:
            columns = re.split('\s+', line.strip())
            ip, mac = columns[1], columns[3]
            arp_table.append((ip, mac))

    return arp_table

def find_ips_for_macs(arp_table, mac_list):
    results = []

    for mac in mac_list:
        found = False
        for ip, mac_in_table in arp_table:
            if mac.lower() == mac_in_table.lower():
                results.append((mac, ip))
                found = True
                break
        if not found:
            results.append((mac, None))

    return results

def convert_mac_address_format(mac_address):
    mac_address = mac_address.replace(":", "")
    mac_address = mac_address.lower()
    formatted_mac = ""
    
    for i in range(0, len(mac_address), 4):
        formatted_mac += mac_address[i:i+4] + "."
    
    return formatted_mac[:-1]

def convert_mac_to_dns_format(mac_address):
    mac_address = mac_address.replace(":", "").replace(".", "")
    mac_address = mac_address.lower()
    return f"rpi-{mac_address}.scp-lab.dev-charter.net"

def get_dns_ip(mac_address):
    dns_name = convert_mac_to_dns_format(mac_address)
    #print(f"Looking up DNS for: {dns_name}")
    try:
        ip = socket.gethostbyname(dns_name)
        return ip
    except socket.gaierror:
        return None

if __name__ == "__main__":
    hostname = '10.54.1.1'
    username = 
    password = 

    mac_list = ["e4:5f:01:c6:64:71","e4:5f:01:ae:96:23","e4:5f:01:ab:5e:eb","e4:5f:01:c6:63:7d","e4:5f:01:a5:85:88","e4:5f:01:ae:94:3d","e4:5f:01:ab:4b:ec","e4:5f:01:ae:93:f5","e4:5f:01:e3:37:88","e4:5f:01:ae:d4:f3","e4:5f:01:92:ac:06","e4:5f:01:cb:03:3a","e4:5f:01:ab:62:db","e4:5f:01:80:bf:89","e4:5f:01:8d:3f:15","e4:5f:01:9c:e6:ae","e4:5f:01:c6:64:2f","e4:5f:01:ab:4d:cf","e4:5f:01:ab:1d:15","e4:5f:01:9c:e5:9d","e4:5f:01:ae:5d:c3","e4:5f:01:9a:a6:08","e4:5f:01:ab:5d:b6","e4:5f:01:c6:64:39","e4:5f:01:d5:fd:f0","e4:5f:01:ca:cb:fc","e4:5f:01:ae:94:df","e4:5f:01:e3:35:84","e4:5f:01:d5:fd:9f","e4:5f:01:a8:9b:78","e4:5f:01:c6:64:7e","e4:5f:01:65:ac:bd","e4:5f:01:60:1f:2f","e4:5f:01:ae:98:75","e4:5f:01:d5:fb:f7","e4:5f:01:ce:d4:55","e4:5f:01:ab:60:dd","e4:5f:01:ae:93:b6","e4:5f:01:d6:de:a4","e4:5f:01:d5:fc:69","dc:a6:32:a4:22:d6","e4:5f:01:88:af:ab","e4:5f:01:80:c0:22","e4:5f:01:ab:50:30","e4:5f:01:ab:5e:d9","e4:5f:01:ae:98:a8","e4:5f:01:d5:e8:27","e4:5f:01:d5:f9:be","e4:5f:01:e3:37:3d","e4:5f:01:80:c0:43","e4:5f:01:79:34:15","e4:5f:01:80:c0:b8","e4:5f:01:60:24:f0","e4:5f:01:80:3c:8f","e4:5f:01:80:c0:6a","e4:5f:01:80:c0:d3","e4:5f:01:80:bd:a3","e4:5f:01:88:bc:64","e4:5f:01:8d:3f:bd","e4:5f:01:79:32:95","e4:5f:01:8d:3c:6a","e4:5f:01:8c:e4:3d","e4:5f:01:79:33:df","e4:5f:01:88:b5:9a","e4:5f:01:79:31:de","e4:5f:01:79:33:39","e4:5f:01:79:32:da","e4:5f:01:80:bc:ad","e4:5f:01:8d:37:14","e4:5f:01:8d:00:31","e4:5f:01:8d:00:3d","e4:5f:01:79:34:0c","e4:5f:01:9a:a5:e3","e4:5f:01:a5:81:b3","e4:5f:01:ae:c3:29","e4:5f:01:8c:e3:dd","e4:5f:01:b3:da:3b","e4:5f:01:a5:82:d3","dc:a6:32:a4:21:bc","e4:5f:01:ae:94:d6","e4:5f:01:ae:93:fe","e4:5f:01:ab:58:28","e4:5f:01:60:24:15","e4:5f:01:d5:d7:45","e4:5f:01:ab:5b:4f","e4:5f:01:ae:98:75","e4:5f:01:ae:93:85","e4:5f:01:ab:5b:4f","e4:5f:01:ae:b4:14","e4:5f:01:ae:41:c7","e4:5f:01:ae:d2:d4","e4:5f:01:aa:17:3d","e4:5f:01:ae:b4:8f","e4:5f:01:ae:b4:35","e4:5f:01:92:ad:05","e4:5f:01:8d:37:d5","e4:5f:01:ae:8b:31","e4:5f:01:9a:a5:a1","e4:5f:01:aa:17:2b","e4:5f:01:c6:64:20","e4:5f:01:ae:90:bf","e4:5f:01:74:c4:e4","e4:5f:01:9a:a6:27","e4:5f:01:88:b6:e4","e4:5f:01:ab:4e:0f","e4:5f:01:74:c5:1b","e4:5f:01:ab:4d:1c"]

    # Convert MAC addresses to the required format
    mac_list = [convert_mac_address_format(mac) for mac in mac_list]

    connection = connect_to_switch(hostname, username, password)
    arp_table = get_arp_table(connection)
    switch_results = find_ips_for_macs(arp_table, mac_list)

    print("Comparing IP addresses from the switch and DNS resolution:")
    for mac, switch_ip in switch_results:
        dns_ip = get_dns_ip(mac)
        if switch_ip == dns_ip:
            print(f"{mac} -> Match: Switch IP: {switch_ip}, DNS IP: {dns_ip}")
        else:
            print(f"{mac} -> Mismatch: Switch IP: {switch_ip}, DNS IP: {dns_ip}")
