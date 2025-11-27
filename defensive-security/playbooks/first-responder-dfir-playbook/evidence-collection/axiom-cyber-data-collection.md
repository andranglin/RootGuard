# AXIOM Cyber Data Collection

### 1. Case Creation

Create a new case to organise and store all the evidence collected throughout the investigation.

<mark style="color:orange;">**Case Creation:**</mark>\
Launch the AXIOM Process and select _<mark style="color:green;">Create New Cas</mark><mark style="color:green;">**e**</mark>_

<mark style="color:orange;">**Add Case Information:**</mark>\
Case Number: Assign a case number for tracking purposes, <mark style="color:green;">INC</mark>_<mark style="color:green;">-1001</mark>_ \
Case type: Select the appropriate case type, for example _<mark style="color:green;">Intrusion/incident response</mark>_

<mark style="color:orange;">**Select Location For Case Files Storage**</mark>**:**\
Folder Name: Provide a meaningful name, such as <mark style="color:green;">\<hostname></mark> <mark style="color:green;"></mark>_<mark style="color:green;">- Intrusion Investigation</mark>_ \
File path: _<mark style="color:green;">A:\CASES</mark>_

<mark style="color:orange;">**Select Location For Acquired Evidence Storage:**</mark>\
Folder Name: Provide a meaningful name, such as <mark style="color:green;">\<hostname></mark> <mark style="color:green;"></mark>_<mark style="color:green;">- Intrusion Investigation</mark>_ \
File path: _<mark style="color:green;">A:\CASES</mark>_

<mark style="color:orange;">**Add Scan Information:**</mark>\
Scanned by: <mark style="color:green;">\<investigator name></mark>

NEXT: _<mark style="color:green;">Go to Evident Sources</mark>_

### <mark style="color:$primary;">2. Evidence Sources</mark>

#### <mark style="color:$primary;">Remote Computer</mark>

<mark style="color:$primary;">Create New Agent</mark>

<mark style="color:orange;">**General Agent Settings:**</mark>\
The agent will be saved to the default location: _<mark style="color:green;">C:\AXIOM-Agents</mark>_ \
Agent ID: _<mark style="color:green;">optional</mark>_ \
Operating System: _<mark style="color:green;">Windows</mark>_

<mark style="color:orange;">**Agent Masking Details:**</mark>\
File name: _<mark style="color:green;">AXIOM-Agent.exe</mark>_ \
&#x20;              SHOW MORE DETAILS (add as required or leave as is)

<mark style="color:orange;">**Survive Shutdown of Endpoint:**</mark>\
Based on the investigation scenario, Leave or select: _<mark style="color:green;">Keep the agent running on the endpoint after a  shutdown</mark>_

<mark style="color:orange;">**Connectivity Details:**</mark>\
Examiner workstation hostname or IP address: _<mark style="color:green;">\<IP address of examiner's workstation></mark>_\
Por&#x74;_: <mark style="color:green;">\<Portnumber></mark>_ (8080)\
Reconnect delay: _<mark style="color:green;">10</mark>_ <mark style="color:green;"></mark><mark style="color:green;">seconds</mark> \
Disconnected Keep alive: _<mark style="color:green;">1</mark>_ <mark style="color:green;"></mark><mark style="color:green;">day</mark> (up to you)

Next, _<mark style="color:green;">Create Agent</mark>_

#### <mark style="color:$primary;">Create Agent</mark>

<mark style="color:orange;">**Review Agent Details**</mark>\
<mark style="color:green;">**<**</mark><mark style="color:green;">Review details></mark>

<mark style="color:orange;">**Deploy Agent**</mark>\
Select: _<mark style="color:green;">Deploy Agent</mark>_\
Endpoint IP address: _<mark style="color:green;">Remote host IP address</mark>_ \
Username: _<mark style="color:green;">Investigator AD username</mark>_ \
Password: _<mark style="color:green;">AD password</mark>_ \
Agent location on endpoint: _<mark style="color:green;">C:\Windows\Temp</mark>_

Next: _<mark style="color:green;">Deploy Agent</mark>_\
\
&#xNAN;_<mark style="color:orange;">Deployment in Progress</mark>_\
Select: _<mark style="color:green;">Connect to Agent</mark>_ \
Select: _<mark style="color:green;">Connect to Endpoint</mark>_

<mark style="color:orange;">**Select Items to Download**</mark>\
&#xNAN;_<mark style="color:green;">Review and Select the Data From the Endpoint</mark>_ \
_<mark style="color:green;">Targeted Locations:</mark> Select all available options_ \
&#xNAN;_<mark style="color:green;">Files and Drives:</mark> Files and Folders_ \
_Select: <mark style="color:green;">Files and Folders as appropriate to investigations</mark>_

_<mark style="color:green;">Select Memory to Download</mark>_ \
Select: _<mark style="color:green;">Individual processes</mark>_ \
OR \
&#xNAN;_<mark style="color:green;">Full memory acquisition</mark>_

Important Note: <mark style="color:green;">Leave the tool to capture the data until finished; don't navigate away.</mark> \
Depending on the size and amount of files to be downloaded, it could take some time

When data capture is complete, select Next for the final section of EVIDENCE SOURCES: _<mark style="color:green;">Preparing Selected Items</mark>_ \
Note: AXIOM will archive and do its final checks. When complete, click: _<mark style="color:green;">Go to Evidence Sources</mark>_ and next click _<mark style="color:green;">Go to Processing Details</mark>_

### <mark style="color:$primary;">3. Processing Details</mark>

PROCESSING DETAILS allow additional IOCs or search keywords to be added to the search.

<mark style="color:$primary;">Data Processing Options</mark>\
<mark style="color:orange;">**Quick Scan**</mark><mark style="color:orange;">:</mark> A faster option focusing on key artefact types and providing quick insights into major evidence categories. \
<mark style="color:orange;">**Full Scan**</mark><mark style="color:orange;">:</mark> Performs a comprehensive scan of all collected data, including a deeper search for deleted files, file system artefacts, and more granular evidence. \
<mark style="color:orange;">**Custom Scan**</mark><mark style="color:orange;">:</mark> Customise the scan to focus on specific artefact types, such as system logs, user activity, or network traffic.

Add Keywords to Search\
Keyword Search Types:
