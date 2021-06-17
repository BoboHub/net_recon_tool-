# REFERENCES:
# Python.org - Optparse library: https://docs.python.org/2/library/optparse.html
# StackOverflow - How to get network interface: https://stackoverflow.com/questions/3837069/how-to-get-network-interface-card-names-in-python
# Scapy - usage: https://scapy.readthedocs.io/en/latest/usage.html
# GeeksForGeeks - find ip address: https://www.geeksforgeeks.org/python-program-find-ip-address/
# StackOverflow - ip address from the nic: https://stackoverflow.com/questions/24196932/how-can-i-get-the-ip-address-from-nic-in-python
# StackOverflow  - getting first three bites of an ip: https://stackoverflow.com/questions/23258092/getting-the-first-three-bytes-of-an-ip-address
# GeeksForGeeks - remove duplicate values from the dict: https://www.geeksforgeeks.org/python-remove-duplicate-values-in-dictionary/
# StackOverflow- remove duplicate values from the list: https://stackoverflow.com/questions/8749158/removing-duplicates-from-dictionary
# ##############################################################################################
# Assignment 1
# CIT/Scripting for Cybersecurity - Semester 1
# B.F.
################################################################################################
import socket
import subprocess
from scapy.all import *
import psutil
import netifaces as ni

def active_recon(iface):
    #getting the interface IP address
    ni.ifaddresses(iface)
    ip_address = ni.ifaddresses(iface)[ni.AF_INET][0]['addr']
    print("Interface IP address: >>> " + ip_address)
    #creating an subnet staring from 0
    ip_subnet = ip_address[:ip_address.rfind(".")] + "."
    print("Subnet: >>> "+ ip_subnet + "0/24")
    print("-------------------------------")
    ans_list = []
    full_list = []
    #looping in range 254 to target 254 addresses
    for ping in range(0, 254):
        address = ip_subnet + str(ping)
        #using sr1 function to send out ARP requests in given subnet on given interface with successful returns
        ans = sr1(ARP(pdst=address), iface=iface, timeout = 2, verbose = 0,)
        #if successful store in list
        if ans:
            ans_list.append("\n[+] Host found at: " + address)
            full_list = (', '.join(map(str, ans_list)))
    #prit the fetched list
    if full_list:
        print("Fetched addresses: ")
        print(full_list)
    else:print("[-] No host found on subnet "+ ip_subnet + "0/24!")

def passive_scan(pkt):
    my_addresses = {}
    result = {}
    #sniffing for packets that contain apr and filtering by 1 (is-at)
    if ARP in pkt and pkt[ARP].op in (1,): #is-at
        #fatiching the MAC and IP and creating a key value pair in dictionary
        mac_address = pkt.sprintf("%ARP.hwsrc%")
        ip_address = pkt.sprintf("%ARP.psrc%")
        my_addresses[mac_address] = ip_address
        if my_addresses:
            #remove duplicate key value pairs
            for key, value in my_addresses.items():
                if value not in result.values():
                    result[key] = value
            print(result)
        #if my_addresses:
            #print(my_addresses)

'''
Remove duplicate TEST 1:
 for i in my_addresses:
            if my_addresses[i] == ip_address and mac_address:
                my_addresses[i] = "Duplicate deleted"
        print(my_addresses)
'''

#simple function to get all interfaces
def get_all_interfaces():
    interfaces = ni.interfaces()
    full_list = (', '.join(map(str, interfaces)))
    print("Available interfaces: \n" + full_list)

#simple help function
def help():
    print(
        "Help - usage of the program : "
        "\n(1) ./net_recon.py <interface option> <interface> <command option> "
        "\n(*) EXAMPLE: net_recon.py -i eth0 -a /OR/ net_recon.py --interface lo -p "
        "\n(2) <interface option> usage: '-i' or '--interface' "
        "\n(3) <interface> usage: e.g. lo, eth0 "
        "\n(4) <command option> usage: '-p' or '--passive' "
        "\n(5) <command option> usage: '-a' or '--active' "
        "\n(***) show all available interfaces: -all -all -ai "
    )
    exit()
# simple sys.argv function taking 4 arguments including the script
def main ():
    if len(sys.argv) == 4:
        iface_option = sys.argv[1]
        iface = sys.argv[2]
        option = sys.argv[3]
    else:
        return help()

    print("Your are capturing on interface: >>> " + iface)

    # validate the user input with predefined options
    # iface would have to be validate dynamically against current interfaces or hardcoded
    # I didn't hard code it because I don't know your interfaces
    if ((iface_option == "-i") or (iface_option == "--interface")) and iface and ((option == "-a") or (option == "--active")):
        return active_recon(iface)

    elif ((iface_option == "-i") or (iface_option == "--interface")) and iface and ((option == "-p") or (option == "--passive")):
        print("Listening for 30 seconds...")
        print("Listening...")
        return passive_scan(sniff(iface=iface, prn=passive_scan, filter="arp", store=0, timeout=30))

    elif (iface_option == "-all") and iface == "-all" and ((option == "-ai") or (option == "--everything")):
        return get_all_interfaces()

    else:
        return help()

main()


