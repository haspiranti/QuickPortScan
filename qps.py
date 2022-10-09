#!/usr/bin/python3

import subprocess

import os
import sys
import time
import socket
import threading
from queue import Queue
from datetime import datetime
from pyfiglet import figlet_format


def convert_time(end, start):
    sec = end - start
    min = sec // 60
    sec = sec % 60
    hour = min // 60
    min = min % 60
    return f"Time elapsed: {int(hour)}:{int(min)}:{int(sec)}"

class Arguments():

    def __init__(self):
        self.arguments = sys.argv
        self.accepted_arguments = ["-p", "-ap", "-s", "-f", "-v", "-h", "--help"]


    def port_range(self):
        """Scans either individual or a range of ports on the target."""
        
        # empty port list to grab chosen ports.
        ports = []

        try:
            # checks where the "-p" option is and looks for the port range listed after it. 
            for a, b in enumerate(self.arguments):
                if b == "-p":
                    # splits the port range string by comma
                    for i in self.arguments[a+1].split(","):
                        # if the number is a static number then add to the port list
                        if i.isnumeric():
                            ports.append(int(i))
                        # if the number is a range then add all numbers within the range to the list.
                        elif "-" in i:
                            i = i.split("-")
                            for n in range(int(i[0]),(int(i[1])+1)):
                                ports.append(n)
                        else:
                            pass
                # scan all ports on the target
                elif b == "-ap":
                    # range does not count the last number so 65536 is used as the last port instead.
                    for n in range(1, 65536):
                        ports.append(n)
            # if no specific port option is selected then scan the top 1000 port numbers. 
            if "-p" not in self.arguments and "-ap" not in self.arguments:
                with open('/lib/quickportscan.1.0/top_1000_ports.txt','r') as file:
                    port_list = file.read().split(',')
                    for i in port_list:
                        ports.append(int(i))
                    file.close()
        except Exception:
            print("Syntax error. Please refer to the help page ['--help'] for additional information.")
            quit()
        return ports


    def verify_options(self):
        """the options function analyzes the arguments that were input by the user, 
        verifies no contraditions, and then returns supplied scan options."""

        options = set()
        contradiction_message = "Contradicting arguments. Please refer to the help page ['--help'] for additional information."

        if "-h" in self.arguments or "--help" in self.arguments:
            with open('/lib/quickportscan.1.0/help_page.txt','r') as file:
                contents = file.read()
                print(contents)
                quit()

        for x in self.arguments:
            if x in self.accepted_arguments:
                # verifies that both the "select port range" and "all port" mode are not chosen
                if "-p" in self.arguments and "-ap" not in self.arguments:
                    options.add("-p")
                elif "-ap" in self.arguments and "-p" not in self.arguments:
                    options.add("-ap")
                elif "-p" in self.arguments and "-ap" in self.arguments:
                    print(contradiction_message)
                    break
                # verifies that both the "slow scan" and "fast scan" mode are not chosen
                if "-s" in self.arguments and "-f" not in self.arguments:
                    options.add("-s")
                elif "-f" in self.arguments and "-s" not in self.arguments:
                    options.add("-f")
                elif "-s" in self.arguments and "-f" in self.arguments:
                    print(contradiction_message)
                    break
                elif "-s" not in self.arguments and "-f" not in self.arguments:
                    options.add("-n")
                if "-v" in self.arguments:
                    options.add("-v")
            # checks if any invalid options are being attempted.
            elif x not in self.accepted_arguments and x[0] == "-":
                print(f"Invalid option ['{x}']. Please refer to the help page ['--help'] for additional information.")
                quit()
        return list(options)


    def verify_target(self):
        """verify_target verifies that the target IP address is a 
        compatible IP address or hostname and returns an IP address."""
        try:
            # tries to convert the hostname into an IP address. does not
            # do anything if address is already in IPv4 format. 
            target = socket.gethostbyname(self.arguments[1])
            return target
        except Exception as e:
            # if the help page is requested then don't throw the hostname error.
            if self.arguments[1] == "-h" or self.arguments == "--help":
                return None
            else:
                # if hostname is not valid, print the error. 
                print(e, f"'{self.arguments[1]}'")
                return None          
    

class Scanner():

    def __init__(self, target, ports, options):
        self.target = target
        self.ports = ports
        self.options = options
        self.q = Queue()


    def listargs(self):
        print(f"target: {self.target}")
        print(f"ports: {self.ports}")
        print(f"options: {self.options}")
    
    
    def scan_port(self, port):
        """Scan the given port on the target address."""
        # create a new socket using the given family
        # AF_INET is IPv4 and SOCK_STREAM is TCP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # set a timeout on blocking socket operations
        # argument resembles seconds
        s.settimeout(1)

        global open_ports

        try:
            s.connect((self.target, port))
            open_ports.append(port)
            if "-v" in self.options:
                print(f"{port} is open")
            return True
        except:
            return False


    def thread(self):
        while True:
            port = self.q.get()
            self.scan_port(port)
            self.q.task_done()


    def start(self):
        """the start function takes all of the verification and finally runs the port scanner
        based on the supplied arguments."""

        # if normal mode is selected then scan ports normally.
        if "-n" in self.options:
            for _ in range(1):
                t = threading.Thread(target=self.thread)
                t.daemon = True
                t.start()
            for i in self.ports:
                self.q.put(i)
            self.q.join()
        # if slow mode is selected then sleep for 2 seconds after every port scan.
        elif "-s" in self.options:
            for _ in range(1):
                t = threading.Thread(target=self.thread)
                t.daemon = True
                t.start()
            for i in self.ports:
                self.q.put(i)
            self.q.join()
            time.sleep(2)
        # if fast mode is selected then initialize threads to simultaneously scan target.
        elif "-f" in self.options:
            # create 50 threads
            for _ in range(50):
                t = threading.Thread(target=self.thread)
                t.daemon = True
                t.start()
            for i in self.ports:
                self.q.put(i)
            self.q.join()
        # if no speed mode is selected then run the default scan_port function with the
        # supplied port range.
        else:
            for i in self.ports:
                self.scan_port(i)

    def end(self):
        """the end function takes all of the open ports that were cached from the scan and displays
        them once the scan has completed."""

        if "-v" not in self.options:
            for port in open_ports:
                print(f"{port} is open")
        

if __name__ == "__main__":    
    # instantiates the argument an scanner classes.
    a = Arguments()
    s = Scanner(a.verify_target(), a.port_range(), a.verify_options())
    
    # clears screen
    os.system('clear')
    # presents all of the cli graphics and starts the scanner
    print(figlet_format("QuickPortScan"))
    print("Created by Hayden Aspiranti")
    print("-" * 28)
    print((' '.join(sys.argv)) + " | " + "Scanning Initiated at: " + str(datetime.now().replace(microsecond=0)))
    print("-" * 28)
    
    open_ports = []
    start_time = time.time()
    try:
        s.start()
    except KeyboardInterrupt:
        quit()
    end_time = time.time()
    s.end()
  
    print("-" * 50)
    print(f"Scanned {len(a.port_range())} port(s)")
    print(f"{len(open_ports)} port(s) open")
    print(convert_time(end_time, start_time))
    print("Scanning finished at: " + str(datetime.now().replace(microsecond=0)))
    print("-" * 50)