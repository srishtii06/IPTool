import threading
import queue
import requests
import ipaddress
import os
import sys
import subprocess
import platform
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import json
import time

# Get the path to the temporary directory
base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))

# Construct the path to the data folder
data_path = os.path.join(base_path, 'data')

outputData = {}
cancelFlag = threading.Event()
systemFlag = 0

def CheckIpType(ip):
    try:
        ipObj = ipaddress.ip_address(ip)
        CgnatNetwork = ipaddress.ip_network("100.64.0.0/10")
        if ipObj.is_private:
            return "Private IP"
        elif ipObj in CgnatNetwork:
            return "Public but reserved by ISP (CGNAT)"
        else:
            return "Public IP"
    except ValueError:
        return "Invalid IP address"
    
def CheckIpVersion(ip):
    try:
        ipObj = ipaddress.ip_address(ip)
        if ipObj.version == 4:
            return "IPv4"
        elif ipObj.version == 6:
            return "IPv6"
    except ValueError:
        return "Invalid IP address"
    
def CheckIpInFile(filePathProton, filePathNordvpn, filePathWindscribe, filePathExpress, filePath, ipAddress, resultQueue):
    if cancelFlag.is_set():
        resultQueue.put("Analysis cancelled.")
        return
    
    for filePathName in [*filePathProton, filePathNordvpn, filePathWindscribe, *filePathExpress, filePath]:
        if not os.path.isfile(filePathName):
            resultQueue.put(f"Error: The file at {filePathName} does not exist.")
            return
    
    try:
        with open(filePathNordvpn, 'r') as file:
            contentNordvpn = file.read().splitlines()
    except IOError as e:
        resultQueue.put(f"Error reading file {filePathNordvpn}: {e}")
        return

    try:
        with open(filePathWindscribe, 'r') as file:
            contentWindscribe = file.read().splitlines()
    except IOError as e:
        resultQueue.put(f"Error reading file {filePathWindscribe}: {e}")
        return

    try:
        with open(filePath, 'r') as file:
            content = file.read().splitlines()
    except IOError as e:
        resultQueue.put(f"Error reading file {filePath}: {e}")
        return
      
    for file in filePathProton:
        try:
            with open(file, 'r') as f:
                contentProton = f.read().splitlines()
            if ipAddress in contentProton:
                resultQueue.put("VPN/Proxy: True\nVPN Name: Proton VPN")
                return
        except IOError as e:
            continue

    if ipAddress in contentNordvpn:
        resultQueue.put("VPN/Proxy: True\nVPN Name: Nord VPN")
        return
   
    if ipAddress in contentWindscribe:
        resultQueue.put("VPN/Proxy: True\nVPN Name: Windscribe VPN")
        return
    
    expressMatch = False
    for file in filePathExpress:
        try:
            with open(file, 'r') as f:
                contentExpress = f.read().splitlines()
            for line in contentExpress:
                line = line.strip()
                if '/' in line:
                    if ipaddress.IPv4Address(ipAddress) in ipaddress.IPv4Network(line):
                        expressMatch = True
                else:
                    if ipAddress == line:
                        expressMatch = True
        except IOError as e:
            continue
        
    if expressMatch:
        resultQueue.put("VPN/Proxy: True\nVPN Name: Express VPN")
        return
      
    for rangePrefix in content:
        try:
            if ipaddress.IPv4Address(ipAddress) in ipaddress.IPv4Network(rangePrefix):
                resultQueue.put("VPN/Proxy:True\nVPN Name:null")
                return
        except ValueError:
            continue
        
    resultQueue.put("VPN/Proxy: False")

def LoadIpv6Ranges(filePath, resultQueue):
    if cancelFlag.is_set():
        resultQueue.put("Loading cancelled.")
        return
    
    try:
        with open(filePath, 'r') as file:
            lines = file.readlines()
        ipv6Ranges = [line.strip() for line in lines if line.strip()]
        resultQueue.put(ipv6Ranges)
    except IOError as e:
        resultQueue.put(f"Error reading file {filePath}: {e}")

def CheckIpv6InRanges(ipv6Address, ipv6Ranges, resultQueue):
    if cancelFlag.is_set():
        resultQueue.put("Check cancelled.")
        return
    
    try:
        for rangePrefix in ipv6Ranges:
            if ipaddress.IPv6Address(ipv6Address) in ipaddress.IPv6Network(rangePrefix):
                resultQueue.put(True)
                return
    except ValueError:
        resultQueue.put(f"Error: Invalid IPv6 range or address: {ipv6Address}")
        return
    
    resultQueue.put(False)

def GetIpDetails(ipAddress, resultQueue):
    if cancelFlag.is_set():
        resultQueue.put("Fetching IP details cancelled.")
        return
    
    try:
        response = requests.get(f'http://ip-api.com/json/{ipAddress}')
        response.raise_for_status()
        ipDetails = response.json()
        
        resultQueue.put(ipDetails)
    except requests.RequestException as e:
        resultQueue.put(f"Error fetching IP details: {e}")

def PrintIpDetails(ipDetails, outputBox):
    if ipDetails and ipDetails.get('status') == 'success':
        outputBox.insert(tk.END, f"Country: {ipDetails.get('country')}\n")
        outputBox.insert(tk.END, f"Region: {ipDetails.get('regionName')}\n")
        outputBox.insert(tk.END, f"City: {ipDetails.get('city')}\n")
        outputBox.insert(tk.END, f"ZIP: {ipDetails.get('zip')}\n")
        outputBox.insert(tk.END, f"Latitude: {ipDetails.get('lat')}\n")
        outputBox.insert(tk.END, f"Longitude: {ipDetails.get('lon')}\n")
        outputBox.insert(tk.END, f"ISP: {ipDetails.get('isp')}\n")
        outputBox.insert(tk.END, f"Organization: {ipDetails.get('org')}\n")
        outputBox.insert(tk.END, f"AS: {ipDetails.get('as')}\n")
    else:
        outputBox.insert(tk.END, "No details available or IP address is invalid.\n")

class Node:
    def __init__(self, hopNumber, ipAddress, hostName): #responseTime):
        self.hopNumber = hopNumber
        self.ipAddress = ipAddress
        self.hostName = hostName
        #self.responseTime = responseTime
        self.next = None

class SinglyLinkedList:
    def __init__(self):
        self.head = None
    
    def append(self, hopNumber, ipAddress, hostName): # responseTime)
        newNode = Node(hopNumber, ipAddress, hostName) #responseTime)
        if not self.head:
            self.head = newNode
        else:
            current = self.head
            while current.next:
                current = current.next
            current.next = newNode
    
    def PrintList(self):
        outputLines = []
        if not self.head:
            outputLines.append("Error: No traceroute data available.")
            return "\n".join(outputLines)
        
        current = self.head
        while current:
            outputLines.append(f"Hop {current.hopNumber}: {current.hostName} ({current.ipAddress})") #- Time: {current.responseTime}")
            current = current.next
        return "\n".join(outputLines)
    
    def toList(self):
        result = []
        current = self.head
        while current:
            result.append({
                'Hop Number': current.hopNumber,
                'Ip Address': current.ipAddress,
                'HostName': current.hostName,
                #'Response Time': current.responseTime
            })
            current = current.next
        return result
    
def PerformTraceroute(ipAddress, resultQueue):
    if cancelFlag.is_set():
        resultQueue.put("Traceroute cancelled.")
        return

    try:
        global systemFlag
        currentOs = platform.system().lower()
        if currentOs == 'windows':
            systemFlag = 1
            command = ['tracert', '-w', '1000',ipAddress]   # Timeout of 1 second per hop
            creationflags = subprocess.CREATE_NO_WINDOW
        else:
            systemFlag = 0
            command = ['traceroute', '-w', '1',ipAddress]   #1 second wait time
            creationflags = 0
        
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,creationflags=creationflags)
        
        while process.poll() is None:
            if cancelFlag.is_set():
                process.terminate()
                resultQueue.put("Traceroute cancelled.")
                return
            time.sleep(0.5)  # Sleep to prevent busy waiting
        
        try:
            stdout, stderr = process.communicate(timeout=60)  # Wait for 1 minute
        except subprocess.TimeoutExpired:
            process.terminate()
            resultQueue.put("Error: The traceroute operation timed out.")
            return 
        
        if cancelFlag.is_set():
            resultQueue.put("Traceroute cancelled.")
            return

        if process.returncode == 0:
            resultQueue.put(stdout)
        else:
            resultQueue.put(f"Error: {stderr}")
    except Exception as e:
        resultQueue.put(f"An error occurred: {str(e)}")
        
def ParseTracerouteOutputWindows(output):
    linkedList = SinglyLinkedList()
    lines = output.splitlines()

    timeoutCount = 0
    
    for line in lines:
        if cancelFlag.is_set():
            return 
        parts = line.split()
        
        if len(parts) <= 5 or not parts[0].isdigit():
            continue
        
        hopNumber = int(parts[0])
        #responseTimes = [parts[1], parts[3], parts[5]]
        ipAddress = ''
        hostName = ''

        if 'Request timed out' in line:
            timeoutCount += 1
            if timeoutCount >= 3:
                break
        else:
            timeoutCount = 0
        
        ipAddress = parts[-1].replace("[", "").replace("]", "")
        if len(parts[-2]) > 2:
            hostName = parts[-2]
        else:
            hostName = "Null"
        
        #responseTime = ', '.join(responseTimes)
        
        linkedList.append(hopNumber, ipAddress, hostName) #responseTime)
    return linkedList

def ParseTracerouteOutputLinux(output):
    linkedList = SinglyLinkedList()
    lines = output.splitlines()

    timeoutCount = 0
    
    for line in lines:
        if cancelFlag.is_set():
            return 
        parts = line.split()
        elementsToRemove = {'!H', '!N', '!P', '!F', '!S', '!X', '!A', '!'}
        parts = [item for item in parts if item not in elementsToRemove]
        
        if len(parts) < 5 or not parts[0].isdigit():
            continue
        
        hopNumber = int(parts[0])
        #responseTimes = [parts[3], parts[5], parts[7]]
        ipAddress = parts[2].replace("(", "").replace(")", "")
        hostName = parts[1]
        #responseTime = ', '.join(responseTimes)

        if '*' in line:
            timeoutCount += 1
            if timeoutCount >=3:
                break
        else:
            timeoutCount = 0
        
        linkedList.append(hopNumber, ipAddress, hostName) #responseTime)
    return linkedList    

def OnCheckIp():
    global cancelFlag
    cancelFlag.clear()  # Ensure that the cancel flag is reset
    checkButton.config(state=tk.DISABLED)
    cancelButton.config(state=tk.NORMAL)
    threading.Thread(target=PerformIpAnalysis).start()

def CopyResults():
    try:
        resultText = outputBox.get(1.0, tk.END)  # Get all text from the outputBox
        root.clipboard_clear()  
        excludeLines = [
        "Loading the Results for the IP Address",
        "Loading the Traceroute Results..",
        "Search Completed!",
        "Process has been cancelled."
        ]
        lines =resultText.splitlines()
        filteredLines = []
        skipLine = False
        for line in lines:
            if any(line.startswith(exclude) for exclude in excludeLines):
                skip_line = True
            elif line.strip() == "":  # Skip empty lines
                skip_line = False
            elif skip_line:
                continue
            else:
                filteredLines.append(line)
    
        filteredContent = "\n".join(filteredLines).strip()
        root.clipboard_append(filteredContent) 
        root.update()  
        messagebox.showinfo("Success", "Results copied to clipboard.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while copying to clipboard: {e}")

def OnCancel():
    global cancelFlag
    cancelFlag.set()  # Set the cancel flag to stop all ongoing operations
    outputBox.insert(tk.END, "\nProcess has been cancelled.\n") 
    checkButton.config(state=tk.NORMAL)
    cancelButton.config(state=tk.DISABLED)


def PerformIpAnalysis():
    global outputData
    ip = ipEntry.get().strip()
    outputBox.delete(1.0, tk.END)

    if not ip:
        outputBox.insert(tk.END, "Error: No IP address entered.\n")
        checkButton.config(state=tk.NORMAL)
        cancelButton.config(state=tk.DISABLED)
        return

    filePath = os.path.join(data_path, 'IPV4General.txt')
    filePathProton = [
        os.path.join(data_path, 'ProtonvpnExitIps.txt'),
        os.path.join(data_path, 'ProtonvpnEntryIps.txt')
    ]
    filePathNordvpn = os.path.join(data_path, 'NordVPNIPList.txt')
    filePathWindscribe = os.path.join(data_path, 'WindscribeVpn.txt')
    filePathExpress = [
        os.path.join(data_path, 'ExpressvpnSingleIps.txt'),
        os.path.join(data_path, 'ExpressvpnIpRanges.txt')
    ]
    filePathIpv6 = os.path.join(data_path, 'VpnIpv6.txt')
    
    try:
        ipVersion = CheckIpVersion(ip)
        if ipVersion == "Invalid IP address":
            outputBox.insert(tk.END, "Error: Invalid IP address.\n")
            checkButton.config(state=tk.NORMAL)
            cancelButton.config(state=tk.DISABLED)
            return

        outputData = {}
        outputData['Version'] = ipVersion

        outputBox.insert(tk.END, f"Loading the Results for the IP Address {ip} \n\n")

        def updateOutput(message):
            outputBox.insert(tk.END, message)
            outputBox.yview(tk.END)

        def setButtonsState(check_button_state, cancel_button_state):
            checkButton.config(state=check_button_state)
            cancelButton.config(state=cancel_button_state)

        def performIpAnalysisWorker():
            try:
                if ipVersion == "IPv4":
                    vpnCheckQueue = queue.Queue()
                    vpnCheckThread = threading.Thread(target=CheckIpInFile, args=(filePathProton, filePathNordvpn, filePathWindscribe, filePathExpress, filePath, ip, vpnCheckQueue))
                    vpnCheckThread.start()
                    vpnCheckThread.join()
                    if cancelFlag.is_set():
                        return
                    vpnCheckResult = vpnCheckQueue.get()
                    updateOutput(vpnCheckResult + "\n")
                    outputData['VPN/Proxy'] = vpnCheckResult
                elif ipVersion == "IPv6":
                    ipv6RangesQueue = queue.Queue()
                    ipv6RangesThread = threading.Thread(target=LoadIpv6Ranges, args=(filePathIpv6, ipv6RangesQueue))
                    ipv6RangesThread.start()
                    ipv6RangesThread.join()
                    if cancelFlag.is_set():
                        return
                    ipv6Ranges = ipv6RangesQueue.get()
                    isInRangeQueue = queue.Queue()
                    isInRangeThread = threading.Thread(target=CheckIpv6InRanges, args=(ip, ipv6Ranges, isInRangeQueue))
                    isInRangeThread.start()
                    isInRangeThread.join()
                    if cancelFlag.is_set():
                        return
                    isInRange = isInRangeQueue.get()
                    if isInRange:
                        updateOutput("VPN/Proxy:True\n")
                        outputData['VPN/Proxy'] = "True"
                    else:
                        updateOutput("VPN/Proxy:False\n")
                        outputData['VPN/Proxy'] = "False"

                if cancelFlag.is_set():
                    return        

                publicPrivate = CheckIpType(ip)
                updateOutput(f"Type : {publicPrivate}\n")
                outputData['Type'] = publicPrivate

                detailsQueue = queue.Queue()
                detailsThread = threading.Thread(target=GetIpDetails, args=(ip, detailsQueue))
                detailsThread.start()
                detailsThread.join()
                if cancelFlag.is_set():
                    return
                details = detailsQueue.get()
                PrintIpDetails(details, outputBox)
                outputData['IP Details'] = details

                updateOutput("\nLoading the Traceroute Results..\n")

                if cancelFlag.is_set():
                    return

                tracerouteQueue = queue.Queue()
                tracerouteThread = threading.Thread(target=PerformTraceroute, args=(ip, tracerouteQueue))
                tracerouteThread.start()
                tracerouteThread.join()
                if tracerouteThread.is_alive():
                    tracerouteQueue.put("Error: The traceroute operation timed out.")
                    tracerouteThread.join() # Ensure the thread is cleaned up
                if cancelFlag.is_set():
                    return
                tracerouteOutput = tracerouteQueue.get()

                if systemFlag == 1:
                    linkedList = ParseTracerouteOutputWindows(tracerouteOutput)
                else:
                    linkedList = ParseTracerouteOutputLinux(tracerouteOutput)

                updateOutput("\nTraceroute Results (Linked List Format):\n")
                linkedListOutput = linkedList.PrintList()
                updateOutput(linkedListOutput + "\n")  

                updateOutput("\nSearch Completed!\n")

                newLinkedList = linkedList.toList()
                outputData['Traceroute Linked List'] = newLinkedList

            finally:
                setButtonsState(tk.NORMAL, tk.DISABLED)

        # Start the worker thread
        threading.Thread(target=performIpAnalysisWorker).start()
    except Exception as e:
        updateOutput(f"An error occurred: {str(e)}")
        setButtonsState(tk.NORMAL, tk.DISABLED)


def DownloadOutput():
    global outputData
    if not outputData:
        messagebox.showerror("Error", "No output data to save.")
        return

    filePath = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
    if not filePath:
        return

    try:
        with open(filePath, 'w') as json_file:
            json.dump(outputData, json_file, indent=4)
        messagebox.showinfo("Success", f"File saved as {filePath}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while saving the file: {e}")

# GUI Setup
root = tk.Tk()
root.title("IP Address Analyser")
root.geometry("800x600")

title = tk.Label(root, text="IP Analyser Tool", font=("Futura", 12, 'bold'))
title.pack(pady=5)

inputFrame = tk.Frame(root)
inputFrame.pack(pady=10)

ipLabel = tk.Label(root, text="Enter IP address:")
ipLabel.pack(padx=10)

ipEntry = tk.Entry(root, width=50)
ipEntry.pack(padx=10)

checkButton = tk.Button(root, text="Analyse IP", command=OnCheckIp)
checkButton.pack(pady=5)

cancelButton = tk.Button(root, text="Cancel", command=OnCancel, state=tk.DISABLED)
cancelButton.pack(pady=5)

root.bind("<Return>", lambda event: checkButton.invoke())

outputBox = scrolledtext.ScrolledText(root, width=100, height=30, font=("Futura", 10))
outputBox.pack(pady=10)

downloadButton = tk.Button(root, text="Download Output", command=DownloadOutput)
downloadButton.pack(pady=5)

copyButton = tk.Button(root, text="Copy Results", command=CopyResults)
copyButton.pack(pady=5)

root.mainloop()