# Detecting DeviceNetworkEvents From Windows Processes and Domains by TLD

This query detects DeviceNetworkEvents from Windows processes and summarises them by Top-Level Domain (TLD):

{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where RemoteIPType == "Public" // Filter events with public IP addresses
| where InitiatingProcessFolderPath startswith @"C:\Windows\" // Filter events from processes in the C:\Windows folder
| extend RootDomain = extract(@"[^.]+\.[^.]+$", 0, extract(@"^(?:https?://)?([^/]+)", 1, RemoteUrl)) // Extract the root domain from the URL
| extend DomainTLD = tostring(split(RootDomain, ".")[-1]) // Extract the TLD from the root domain
| summarize count(), RootDomains = make_set(RootDomain), Processes = make_set(InitiatingProcessFolderPath), ProcessesCount = dcount(InitiatingProcessFolderPath) by DomainTLD // Summarize the events by TLD
| order by count_ desc // Order the results by the count of events in descending order
```
{% endcode %}

Below is a more extended version of the same query; test and customise as needed.

{% code overflow="wrap" %}
```kusto
DeviceNetworkEvents
| where RemoteIPType == "Public" // Filter events with public IP addresses
| where InitiatingProcessFolderPath startswith @"C:\Windows\" // Filter events from processes in the C:\Windows folder
| extend RootDomain = extract(@"[^.]+\.[^.]+$", 0, extract(@"^(?:https?://)?([^/]+)", 1, RemoteUrl)) // Extract the root domain from the URL
| extend DomainTLD = tostring(split(RootDomain, ".")[-1]) // Extract the TLD from the root domain
| extend ProcessName = extract(@"[^\\]+$", 0, InitiatingProcessFolderPath) // Extract the process name from the folder path
| extend EventHour = bin(TimeGenerated, 1h) // Group events into 1-hour bins
| summarize EventCount = count(), RootDomains = make_set(RootDomain), Processes = make_set(ProcessName), UniqueProcessesCount = dcount(ProcessName) by DomainTLD, EventHour // Summarize the events by TLD and hour
| extend AvgEventCountPerProcess = round(EventCount / UniqueProcessesCount, 2) // Calculate the average event count per process and round it to 2 decimal places
| project EventHour, DomainTLD, EventCount, RootDomains, Processes, UniqueProcessesCount, AvgEventCountPerProcess // Project relevant columns for the final output
| order by EventHour desc, EventCount desc // Order the results by event hour and count of events in descending order

```
{% endcode %}
