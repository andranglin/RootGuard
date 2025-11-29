# File Download and Browser Activity Investigation Guide

### asComplete DFIR Workflow & Cheatsheet

***

### 📚 Table of Contents

1. [Investigation Framework](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#investigation-framework)
2. [Browser History Analysis](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#browser-history-analysis)
3. [Download History Analysis](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#download-history-analysis)
4. [Internet Explorer/Edge File Access](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#internet-exploreredge-file-access)
5. [Email Attachments Investigation](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#email-attachments-investigation)
6. [Cross-Browser Analysis](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#cross-browser-analysis)
7. [Investigation Playbooks](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#investigation-playbooks)
8. [Tool Reference](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#tool-reference)
9. [Quick Reference Cards](https://claude.ai/chat/a68948bd-1cb3-4710-bb7f-5de81727a337#quick-reference-cards)

***

### 🎯 Investigation Framework

#### Artifact Priority Matrix

| Investigation Goal         | Primary Artifacts           | Secondary Artifacts          | Timeframe  |
| -------------------------- | --------------------------- | ---------------------------- | ---------- |
| **Malware Download**       | Browser Downloads           | Browser History, WebCache    | 15-30 min  |
| **Phishing Investigation** | Browser History             | Downloads, Email Attachments | 20-40 min  |
| **Data Exfiltration**      | Browser History (uploads)   | Downloads, Email             | 30-60 min  |
| **Suspicious File Access** | WebCache file:///           | Browser History              | 15-30 min  |
| **Drive-by Download**      | Browser History + Downloads | Cache files                  | 30-45 min  |
| **Email-based Compromise** | Email Attachments (OST/PST) | Browser Downloads            | 45-90 min  |
| **User Web Activity**      | Browser History (all)       | Downloads, Cache             | 30-60 min  |
| **Timeline Construction**  | All browser artifacts       | File system timestamps       | 60-120 min |

***

### 🔍 Quick Triage (First 15 Minutes)

#### Determine Investigation Scope

```bash
□ What's the incident type?
  - Malware infection
  - Phishing/credential theft
  - Data exfiltration
  - Inappropriate usage
  - Insider threat

□ Which browser(s) does user use?
  - Chrome/Edge (Chromium)
  - Firefox
  - Internet Explorer
  - Multiple browsers?

□ What's the suspected timeframe?
□ Any specific indicators? (URLs, file names, hashes)
□ Email client in use? (Outlook, Thunderbird, web-based)
```

#### Quick Win Queries

**Check for Recently Downloaded Executables:**

{% code overflow="wrap" %}
```powershell
# Chrome Downloads
$ChromeHistory = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\History"
if (Test-Path $ChromeHistory) {
    Write-Host "Chrome History found - collect for analysis"
}

# Edge Downloads
$EdgeHistory = "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\History"
if (Test-Path $EdgeHistory) {
    Write-Host "Edge History found - collect for analysis"
}

# Firefox Downloads
$FirefoxProfile = Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles\" -Filter "*.default*" -Directory | Select-Object -First 1
if ($FirefoxProfile) {
    $FirefoxDB = "$($FirefoxProfile.FullName)\places.sqlite"
    Write-Host "Firefox places.sqlite found - collect for analysis"
}

# Check Downloads folder for recent .exe, .zip, .ps1, .bat
Get-ChildItem "$env:USERPROFILE\Downloads" -Include *.exe,*.zip,*.ps1,*.bat,*.vbs,*.js,*.hta,*.msi -Recurse |
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} |
    Select-Object Name, Length, CreationTime, LastWriteTime, FullName
```
{% endcode %}

***

### 🌐 Browser History Analysis

#### Overview

**Purpose**: Reconstruct web browsing activity, identify malicious sites, track user behaviour

**Key Information Available:**

* URLs visited
* Visit timestamps
* Visit frequency (number of visits)
* Page titles
* Referrer information
* Typed URLs vs. clicked links
* Search queries

***

#### Chrome/Edge (Chromium) Browser History

**Database Location:**

{% code overflow="wrap" %}
```bash
Chrome:
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\History

Edge:
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\History

Common Profiles:
- Default (primary profile)
- Profile 1, Profile 2, etc. (additional profiles)
- Guest Profile
```
{% endcode %}

**Database Format**: SQLite

**Key Tables:**

| Table                      | Description              | Key Columns                                                                                                         |
| -------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| **urls**                   | All visited URLs         | id, url, title, visit\_count, typed\_count, last\_visit\_time                                                       |
| **visits**                 | Individual visit records | id, url (FK), visit\_time, from\_visit, transition                                                                  |
| **visit\_source**          | Source of visit          | id, source                                                                                                          |
| **downloads**              | Downloaded files         | id, current\_path, target\_path, start\_time, end\_time, received\_bytes, total\_bytes, state, danger\_type, opened |
| **downloads\_url\_chains** | Download referrer chain  | id, chain\_index, url                                                                                               |
| **keyword\_search\_terms** | Search queries           | keyword\_id, url\_id, term, normalized\_term                                                                        |

**Collection:**

{% code overflow="wrap" %}
```powershell
# Collect Chrome artifacts
$ChromeProfiles = Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Directory | 
    Where-Object {$_.Name -like "Profile*" -or $_.Name -eq "Default"}

foreach ($Profile in $ChromeProfiles) {
    $HistoryPath = "$($Profile.FullName)\History"
    $HistoryCopy = "C:\DFIR_Collection\Chrome\$($Profile.Name)_History"
    
    if (Test-Path $HistoryPath) {
        # File may be locked - use Volume Shadow Copy or close browser
        Copy-Item $HistoryPath -Destination $HistoryCopy -Force -ErrorAction SilentlyContinue
    }
}

# Collect Edge artifacts (same structure)
$EdgeProfiles = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Edge\User Data" -Directory |
    Where-Object {$_.Name -like "Profile*" -or $_.Name -eq "Default"}

foreach ($Profile in $EdgeProfiles) {
    $HistoryPath = "$($Profile.FullName)\History"
    Copy-Item $HistoryPath -Destination "C:\DFIR_Collection\Edge\$($Profile.Name)_History" -Force -ErrorAction SilentlyContinue
}
```
{% endcode %}

**Analysis - Using DB Browser for SQLite:**

{% code overflow="wrap" %}
```bash
1. Open History database
2. Browse Data → Select table:

Key Queries:

-- All visited URLs with timestamps
SELECT 
    urls.id,
    urls.url,
    urls.title,
    datetime(urls.last_visit_time/1000000-11644473600, 'unixepoch', 'localtime') as last_visit,
    urls.visit_count,
    urls.typed_count
FROM urls
ORDER BY urls.last_visit_time DESC;

-- URLs visited in specific timeframe
SELECT 
    urls.url,
    urls.title,
    datetime(visits.visit_time/1000000-11644473600, 'unixepoch', 'localtime') as visit_time
FROM urls
INNER JOIN visits ON urls.id = visits.url
WHERE visits.visit_time > (strftime('%s', 'now', '-7 days') + 11644473600) * 1000000
ORDER BY visits.visit_time DESC;

-- Most frequently visited sites
SELECT 
    url,
    title,
    visit_count,
    datetime(last_visit_time/1000000-11644473600, 'unixepoch', 'localtime') as last_visit
FROM urls
ORDER BY visit_count DESC
LIMIT 50;

-- URLs manually typed (intentional navigation)
SELECT 
    url,
    title,
    typed_count,
    visit_count,
    datetime(last_visit_time/1000000-11644473600, 'unixepoch', 'localtime') as last_visit
FROM urls
WHERE typed_count > 0
ORDER BY typed_count DESC;

-- Search queries
SELECT 
    keyword_search_terms.term,
    urls.url,
    datetime(urls.last_visit_time/1000000-11644473600, 'unixepoch', 'localtime') as search_time
FROM keyword_search_terms
INNER JOIN urls ON keyword_search_terms.url_id = urls.id
ORDER BY urls.last_visit_time DESC;
```
{% endcode %}

**Using BrowsingHistoryView (NirSoft):**

```bash
1. Run BrowsingHistoryView.exe
2. Advanced Options → Load history from:
   - Chrome: Check Chrome
   - Edge: Check Edge
   - Select profile folder
3. View all browsing history
4. Filter by:
   - Time range
   - URL keywords
   - Visit count
5. Export → CSV
```

**Using Hindsight (Python Tool):**

{% code overflow="wrap" %}
```bash
# Install
pip install pyhindsight

# Run against Chrome profile
hindsight.py -i "C:\Users\john\AppData\Local\Google\Chrome\User Data\Default" -o C:\Analysis\Chrome

# Output formats: SQLite, Excel, JSON
hindsight.py -i ChromeProfile -o output --format xlsx
```
{% endcode %}

***

#### Firefox Browser History

**Database Location:**

```bash
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default\places.sqlite

Example:
C:\Users\john\AppData\Roaming\Mozilla\Firefox\Profiles\abc123xyz.default\places.sqlite
```

**Database Format**: SQLite

**Key Tables:**

| Table                     | Description                      | Key Columns                                                         |
| ------------------------- | -------------------------------- | ------------------------------------------------------------------- |
| **moz\_places**           | URLs visited                     | id, url, title, visit\_count, last\_visit\_date, typed, description |
| **moz\_historyvisits**    | Individual visits                | id, place\_id (FK), visit\_date, from\_visit, visit\_type           |
| **moz\_bookmarks**        | Bookmarks                        | id, type, fk (place\_id), title, dateAdded, lastModified            |
| **moz\_annos**            | Annotations (downloads in FF26+) | id, place\_id, anno\_attribute\_id, content, dateAdded              |
| **moz\_anno\_attributes** | Annotation types                 | id, name                                                            |
| **moz\_inputhistory**     | Form inputs/autocomplete         | place\_id, input, use\_count                                        |

**Collection:**

{% code overflow="wrap" %}
```powershell
# Find Firefox profile
$FirefoxProfiles = Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory

foreach ($Profile in $FirefoxProfiles) {
    $PlacesDB = "$($Profile.FullName)\places.sqlite"
    
    if (Test-Path $PlacesDB) {
        Copy-Item $PlacesDB -Destination "C:\DFIR_Collection\Firefox\$($Profile.Name)_places.sqlite" -Force
    }
}
```
{% endcode %}

**Analysis - SQL Queries:**

{% code overflow="wrap" %}
```sql
-- All visited URLs
SELECT 
    moz_places.url,
    moz_places.title,
    datetime(moz_places.last_visit_date/1000000, 'unixepoch', 'localtime') as last_visit,
    moz_places.visit_count,
    moz_places.typed
FROM moz_places
WHERE moz_places.visit_count > 0
ORDER BY moz_places.last_visit_date DESC;

-- Detailed visit history
SELECT 
    moz_places.url,
    moz_places.title,
    datetime(moz_historyvisits.visit_date/1000000, 'unixepoch', 'localtime') as visit_time,
    moz_historyvisits.visit_type
FROM moz_historyvisits
INNER JOIN moz_places ON moz_historyvisits.place_id = moz_places.id
ORDER BY moz_historyvisits.visit_date DESC;

-- Downloads (Firefox 26+)
SELECT 
    moz_places.url,
    moz_annos.content,
    datetime(moz_annos.dateAdded/1000000, 'unixepoch', 'localtime') as download_date
FROM moz_annos
INNER JOIN moz_anno_attributes ON moz_annos.anno_attribute_id = moz_anno_attributes.id
INNER JOIN moz_places ON moz_annos.place_id = moz_places.id
WHERE moz_anno_attributes.name = 'downloads/destinationFileURI'
ORDER BY moz_annos.dateAdded DESC;

-- Typed URLs (intentional navigation)
SELECT 
    url,
    title,
    datetime(last_visit_date/1000000, 'unixepoch', 'localtime') as last_visit,
    visit_count,
    typed
FROM moz_places
WHERE typed = 1
ORDER BY last_visit_date DESC;
```
{% endcode %}

**Visit Types (Firefox):**

| Type | Description              |
| ---- | ------------------------ |
| 1    | Link followed            |
| 2    | Typed URL                |
| 3    | Bookmark                 |
| 4    | Embedded (iframe, image) |
| 5    | Permanent redirect       |
| 6    | Temporary redirect       |
| 7    | Download                 |
| 8    | Framed link              |

***

#### Investigation Workflows - Browser History

**1. Malicious Site Identification:**

{% code overflow="wrap" %}
```sql
-- Search for known malicious domains
SELECT url, title, visit_count, 
       datetime(last_visit_time/1000000-11644473600, 'unixepoch', 'localtime') as last_visit
FROM urls
WHERE url LIKE '%malicious-domain.com%'
   OR url LIKE '%phishing-site.net%'
ORDER BY last_visit_time DESC;

-- Suspicious TLDs
SELECT url, title, visit_count
FROM urls
WHERE url LIKE '%.tk%'     -- Free TLD
   OR url LIKE '%.ml%'
   OR url LIKE '%.ga%'
   OR url LIKE '%.cf%'
   OR url LIKE '%.xyz%'
ORDER BY last_visit_time DESC;

-- IP address URLs (suspicious)
SELECT url, title, visit_count
FROM urls
WHERE url REGEXP 'https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
ORDER BY last_visit_time DESC;
```
{% endcode %}

**2. Phishing Investigation:**

```sql
-- Look for credential harvesting sites
SELECT url, title, visit_count
FROM urls
WHERE url LIKE '%login%'
   OR url LIKE '%signin%'
   OR url LIKE '%verify%'
   OR url LIKE '%update%'
   OR url LIKE '%secure%'
   OR url LIKE '%account%'
ORDER BY last_visit_time DESC;

-- Suspicious domain typosquatting
SELECT url, title
FROM urls
WHERE url LIKE '%micros0ft%'
   OR url LIKE '%faceb00k%'
   OR url LIKE '%g00gle%'
   OR url LIKE '%paypa1%'
   OR url LIKE '%office365-secure%';
```

**3. Timeline Construction:**

{% code overflow="wrap" %}
```sql
-- Activity in specific timeframe (Chrome/Edge)
SELECT 
    urls.url,
    urls.title,
    datetime(visits.visit_time/1000000-11644473600, 'unixepoch', 'localtime') as visit_time,
    visits.transition
FROM visits
INNER JOIN urls ON visits.url = urls.id
WHERE visits.visit_time BETWEEN 
    (strftime('%s', '2025-11-29 09:00:00') + 11644473600) * 1000000
    AND
    (strftime('%s', '2025-11-29 17:00:00') + 11644473600) * 1000000
ORDER BY visits.visit_time ASC;
```
{% endcode %}

**4. Search Query Analysis:**

{% code overflow="wrap" %}
```sql
-- What was user searching for? (Chrome/Edge)
SELECT 
    term,
    url,
    datetime(urls.last_visit_time/1000000-11644473600, 'unixepoch', 'localtime') as search_time
FROM keyword_search_terms
INNER JOIN urls ON keyword_search_terms.url_id = urls.id
ORDER BY urls.last_visit_time DESC;
```
{% endcode %}

**Red Flags:**

```bash
🚩 Suspicious URLs:
   - Free file hosting (anonfiles, mega, mediafire for malware)
   - Pastebin, hastebin (C2 infrastructure)
   - URL shorteners (bit.ly, tinyurl - hiding destination)
   - IP addresses instead of domains
   - Typosquatted domains (micros0ft.com)
   
🚩 Suspicious searches:
   - "how to exfiltrate data"
   - "bypass antivirus"
   - "delete logs"
   - Company confidential information
   - Competitor research
   
🚩 Unusual patterns:
   - After-hours browsing to work resources
   - High frequency to single domain
   - Sequential visits to multiple file sharing sites
   - Access to dark web (.onion)
```

***

### 📥 Download History Analysis

#### Overview

**Purpose**: Track all files downloaded via browser, including malware, documents, tools

**Key Information:**

* Downloaded file name
* Original file name (before rename)
* Download URL (source)
* Referrer URL (how user got to download)
* Download start time
* Download end time
* File size (total and received)
* Download state (complete, interrupted, canceled)
* Danger type (malware warning)
* File system location
* Opened status (was file executed?)

***

#### Chrome/Edge Download History

**Location**: Same History database as browsing history

**Key Tables:**

**downloads table:**

{% code overflow="wrap" %}
```sql
CREATE TABLE downloads (
    id INTEGER PRIMARY KEY,
    guid TEXT NOT NULL,
    current_path TEXT NOT NULL,           -- Where file was saved
    target_path TEXT NOT NULL,            -- Intended save location
    start_time INTEGER NOT NULL,          -- Download start
    received_bytes INTEGER NOT NULL,       -- Bytes downloaded
    total_bytes INTEGER NOT NULL,         -- Total file size
    state INTEGER NOT NULL,               -- 0=in progress, 1=complete, 2=cancelled, 3=interrupted, 4=dangerous
    danger_type INTEGER NOT NULL,         -- 0=safe, 1=dangerous, 2=dangerous_url, etc.
    interrupt_reason INTEGER NOT NULL,
    hash BLOB,
    end_time INTEGER NOT NULL,            -- Download completion
    opened INTEGER NOT NULL,              -- 0=not opened, 1=opened
    last_access_time INTEGER NOT NULL,
    transient INTEGER NOT NULL,
    referrer TEXT NOT NULL,
    site_url TEXT NOT NULL,
    tab_url TEXT NOT NULL,
    tab_referrer_url TEXT NOT NULL,
    http_method TEXT,
    by_ext_id TEXT,
    by_ext_name TEXT,
    etag TEXT,
    last_modified TEXT,
    mime_type TEXT,
    original_mime_type TEXT
);
```
{% endcode %}

**downloads\_url\_chains table:**

```sql
-- Tracks redirect chain from initial click to final download
CREATE TABLE downloads_url_chains (
    id INTEGER NOT NULL,
    chain_index INTEGER NOT NULL,
    url LONGVARCHAR NOT NULL,
    PRIMARY KEY (id, chain_index)
);
```

**Analysis - SQL Queries:**

{% code overflow="wrap" %}
```sql
-- All downloads with details
SELECT 
    downloads.id,
    downloads.target_path,
    downloads_url_chains.url as download_url,
    datetime(downloads.start_time/1000000-11644473600, 'unixepoch', 'localtime') as start_time,
    datetime(downloads.end_time/1000000-11644473600, 'unixepoch', 'localtime') as end_time,
    downloads.received_bytes,
    downloads.total_bytes,
    CASE downloads.state
        WHEN 0 THEN 'In Progress'
        WHEN 1 THEN 'Complete'
        WHEN 2 THEN 'Cancelled'
        WHEN 3 THEN 'Interrupted'
        WHEN 4 THEN 'Dangerous'
    END as state,
    CASE downloads.danger_type
        WHEN 0 THEN 'Not Dangerous'
        WHEN 1 THEN 'Dangerous File'
        WHEN 2 THEN 'Dangerous URL'
        WHEN 3 THEN 'Dangerous Content'
        WHEN 4 THEN 'Content May Be Malicious'
        WHEN 5 THEN 'Uncommon Content'
        WHEN 6 THEN 'Dangerous But User Validated'
        WHEN 7 THEN 'Dangerous Host'
        WHEN 8 THEN 'Potentially Unwanted'
    END as danger_type,
    CASE downloads.opened
        WHEN 0 THEN 'Not Opened'
        WHEN 1 THEN 'Opened'
    END as opened,
    downloads.referrer,
    downloads.mime_type
FROM downloads
LEFT JOIN downloads_url_chains ON downloads.id = downloads_url_chains.id
WHERE downloads_url_chains.chain_index = 0 OR downloads_url_chains.chain_index IS NULL
ORDER BY downloads.start_time DESC;

-- Downloaded executables
SELECT 
    target_path,
    downloads_url_chains.url,
    datetime(start_time/1000000-11644473600, 'unixepoch', 'localtime') as download_time,
    opened,
    danger_type
FROM downloads
LEFT JOIN downloads_url_chains ON downloads.id = downloads_url_chains.id
WHERE target_path LIKE '%.exe'
   OR target_path LIKE '%.msi'
   OR target_path LIKE '%.scr'
   OR target_path LIKE '%.bat'
   OR target_path LIKE '%.ps1'
   OR target_path LIKE '%.vbs'
   OR target_path LIKE '%.js'
   OR target_path LIKE '%.hta'
ORDER BY start_time DESC;

-- Downloads marked as dangerous
SELECT 
    target_path,
    downloads_url_chains.url,
    datetime(start_time/1000000-11644473600, 'unixepoch', 'localtime') as download_time,
    danger_type,
    opened
FROM downloads
LEFT JOIN downloads_url_chains ON downloads.id = downloads_url_chains.id
WHERE danger_type > 0
ORDER BY start_time DESC;

-- Downloads that were opened (potential execution)
SELECT 
    target_path,
    downloads_url_chains.url,
    datetime(start_time/1000000-11644473600, 'unixepoch', 'localtime') as download_time,
    datetime(opened, 'unixepoch', 'localtime') as opened_time
FROM downloads
LEFT JOIN downloads_url_chains ON downloads.id = downloads_url_chains.id
WHERE opened = 1
ORDER BY start_time DESC;

-- Full download chain (redirects)
SELECT 
    downloads.id,
    downloads.target_path,
    downloads_url_chains.chain_index,
    downloads_url_chains.url,
    datetime(downloads.start_time/1000000-11644473600, 'unixepoch', 'localtime') as download_time
FROM downloads
INNER JOIN downloads_url_chains ON downloads.id = downloads_url_chains.id
ORDER BY downloads.start_time DESC, downloads_url_chains.chain_index ASC;
```
{% endcode %}

***

#### Firefox Download History

**Location (versions):**

**Firefox 3-25:**

{% code overflow="wrap" %}
```bash
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default\downloads.sqlite
```
{% endcode %}

**Firefox 26+:**

{% code overflow="wrap" %}
```bash
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default\places.sqlite

Table: moz_annos (annotations)
Downloads stored as annotations with attribute: "downloads/destinationFileURI"
```
{% endcode %}

**Analysis - Firefox 26+ (places.sqlite):**

{% code overflow="wrap" %}
```sql
-- Extract downloads from annotations
SELECT 
    moz_places.url as download_url,
    moz_places.title,
    moz_annos.content as file_path,
    datetime(moz_annos.dateAdded/1000000, 'unixepoch', 'localtime') as download_date,
    datetime(moz_annos.lastModified/1000000, 'unixepoch', 'localtime') as last_modified
FROM moz_annos
INNER JOIN moz_anno_attributes ON moz_annos.anno_attribute_id = moz_anno_attributes.id
INNER JOIN moz_places ON moz_annos.place_id = moz_places.id
WHERE moz_anno_attributes.name = 'downloads/destinationFileURI'
ORDER BY moz_annos.dateAdded DESC;

-- Download metadata annotations
SELECT 
    moz_anno_attributes.name as annotation_type,
    moz_places.url,
    moz_annos.content,
    datetime(moz_annos.dateAdded/1000000, 'unixepoch', 'localtime') as date_added
FROM moz_annos
INNER JOIN moz_anno_attributes ON moz_annos.anno_attribute_id = moz_anno_attributes.id
INNER JOIN moz_places ON moz_annos.place_id = moz_places.id
WHERE moz_anno_attributes.name LIKE 'downloads/%'
ORDER BY moz_annos.dateAdded DESC;
```
{% endcode %}

***

#### Investigation Workflows - Downloads

**1. Malware Download Investigation:**

{% code overflow="wrap" %}
```sql
-- Step 1: Find suspicious downloads
SELECT 
    target_path,
    downloads_url_chains.url as source,
    datetime(start_time/1000000-11644473600, 'unixepoch', 'localtime') as download_time,
    opened
FROM downloads
LEFT JOIN downloads_url_chains ON downloads.id = downloads_url_chains.id
WHERE (target_path LIKE '%.exe' OR target_path LIKE '%.dll' OR target_path LIKE '%.scr')
  AND opened = 1
ORDER BY start_time DESC;

-- Step 2: Get full redirect chain
SELECT 
    chain_index,
    url
FROM downloads_url_chains
WHERE id = [download_id_from_step1]
ORDER BY chain_index;

-- Step 3: Check if file still exists
```
{% endcode %}

```powershell
# PowerShell: Check file existence and hash
$DownloadPath = "C:\Users\john\Downloads\installer.exe"

if (Test-Path $DownloadPath) {
    $Hash = Get-FileHash $DownloadPath -Algorithm SHA256
    Write-Host "File exists - SHA256: $($Hash.Hash)"
    
    # Check VirusTotal
    # Get file metadata
    Get-Item $DownloadPath | Select-Object Name, Length, CreationTime, LastWriteTime
} else {
    Write-Host "File deleted or moved - check Recycle Bin, Prefetch, Amcache"
}
```

**2. Phishing Document Downloads:**

{% code overflow="wrap" %}
```sql
-- Documents from suspicious sources
SELECT 
    target_path,
    downloads_url_chains.url,
    datetime(start_time/1000000-11644473600, 'unixepoch', 'localtime') as download_time,
    opened,
    referrer
FROM downloads
LEFT JOIN downloads_url_chains ON downloads.id = downloads_url_chains.id
WHERE (target_path LIKE '%.docx' OR target_path LIKE '%.xlsx' OR target_path LIKE '%.pdf')
  AND (downloads_url_chains.url NOT LIKE '%sharepoint%' 
       AND downloads_url_chains.url NOT LIKE '%onedrive%'
       AND downloads_url_chains.url NOT LIKE '%dropbox%')
ORDER BY start_time DESC;

-- Correlate with Office Trust Records
-- If document opened + macros enabled = potential compromise
```
{% endcode %}

**3. Data Exfiltration Upload Detection:**

{% code overflow="wrap" %}
```sql
-- Look for large uploads (POST requests in history)
-- This requires analyzing HTTP method from visits table
-- Or checking browser cache for POST data

-- Downloads from cloud storage (may indicate data staging)
SELECT 
    target_path,
    downloads_url_chains.url,
    received_bytes,
    datetime(start_time/1000000-11644473600, 'unixepoch', 'localtime') as download_time
FROM downloads
LEFT JOIN downloads_url_chains ON downloads.id = downloads_url_chains.id
WHERE downloads_url_chains.url LIKE '%dropbox%'
   OR downloads_url_chains.url LIKE '%mega.nz%'
   OR downloads_url_chains.url LIKE '%mediafire%'
   OR downloads_url_chains.url LIKE '%drive.google%'
ORDER BY start_time DESC;
```
{% endcode %}

**4. Timeline Correlation:**

{% code overflow="wrap" %}
```sql
-- Download + Execution Timeline
-- 1. Get download time
-- 2. Check Prefetch for execution time
-- 3. Check Event 4688 for process creation
-- 4. Build complete attack timeline

-- Example: Downloads within suspected compromise window
SELECT 
    target_path,
    downloads_url_chains.url,
    datetime(start_time/1000000-11644473600, 'unixepoch', 'localtime') as download_time,
    datetime(end_time/1000000-11644473600, 'unixepoch', 'localtime') as complete_time,
    opened
FROM downloads
LEFT JOIN downloads_url_chains ON downloads.id = downloads_url_chains.id
WHERE start_time BETWEEN 
    (strftime('%s', '2025-11-29 09:00:00') + 11644473600) * 1000000
    AND
    (strftime('%s', '2025-11-29 17:00:00') + 11644473600) * 1000000
ORDER BY start_time ASC;
```
{% endcode %}

**Red Flags:**

```bash
🚩🚩🚩 CRITICAL - Downloaded and Opened:
   - .exe, .scr, .bat, .ps1, .vbs from internet
   - Documents with macros from email/untrusted sources
   - Archives (.zip, .rar) from unknown sites
   - Files marked as dangerous but user proceeded
   
🚩 Suspicious download sources:
   - Free file hosting (anonfiles, mega)
   - Pastebin, Github Gist (C2 payloads)
   - Compromised websites
   - Shortened URLs
   - Direct IP downloads
   
🚩 Unusual file types:
   - .hta (HTML Application)
   - .iso, .img (disk images)
   - .lnk from internet
   - Executable disguised as document (invoice.pdf.exe)
   
🚩 Download patterns:
   - Multiple tool downloads (reconnaissance)
   - Downloads followed immediately by execution
   - Downloads during off-hours
   - Large downloads to external drives
```

***

### 🌐 Internet Explorer/Edge File Access

#### WebCache Database

**Overview:**

* **Purpose**: IE/Edge cache includes file:/// protocol access
* **Forensic Value**: Tracks local and network file access even if not opened in browser
* **Persists**: Even on Windows 11 without IE installed
* **Location**: WebCacheV01.dat (ESE database)

**Location:**

```bash
%USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat

Multiple supporting files:
WebCacheV01.dat
WebCacheV01.jfm
WebCacheV*.dat
```

**What's Tracked:**

```bash
file:///C:/Users/john/Documents/report.docx
file:///C:/Temp/malware.exe
file:///\\SERVER\Share\confidential.xlsx
file:///E:/USB_Drive/data.zip

Note: These entries created even when:
- File double-clicked in Explorer
- File opened from network share
- File opened from email attachment
- NOT actually opened in browser
```

**Collection:**

{% code overflow="wrap" %}
```powershell
# WebCache is usually locked - requires special handling

# Method 1: Volume Shadow Copy
$VSS = (Get-WmiObject -List Win32_ShadowCopy).Create("C:\", "ClientAccessible")
$Shadow = Get-WmiObject Win32_ShadowCopy | Where-Object {$_.ID -eq $VSS.ShadowID}
$ShadowPath = $Shadow.DevicePath + "\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\WebCache\"
Copy-Item "$ShadowPath\*" -Destination "C:\DFIR_Collection\WebCache\" -Recurse
$Shadow.Delete()

# Method 2: RawCopy (bypass locks)
RawCopy.exe /FileNamePath:"C:\Users\john\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat" /OutputPath:"C:\Analysis"

# Method 3: KAPE
.\kape.exe --target WebCacheV1 --tdest C:\Collection
```
{% endcode %}

**Analysis:**

**Using ESEDatabaseView (NirSoft):**

```bash
1. Run ESEDatabaseView
2. File → Select Database → WebCacheV01.dat
3. Browse tables (Container_0 through Container_N)
4. Look for columns:
   - Url (contains file:/// entries)
   - AccessedTime
   - ModifiedTime
   - ResponseHeaders
   - RequestHeaders
5. Search for "file:///"
6. Export to CSV
```

**Using BrowsingHistoryView (NirSoft):**

```bash
1. Run BrowsingHistoryView
2. Advanced Options → Load from specific profiles
3. Select user profile folder
4. Filter → URL contains "file:///"
5. Export results
```

**Investigation Workflows:**

**1. Local File Access:**

```bash
Search WebCache for:
file:///C:/Users/*/Documents/
file:///C:/Users/*/Downloads/
file:///C:/Temp/
file:///C:/Windows/Temp/

Focus on:
- .exe files accessed
- .docx, .xlsx with macros
- .ps1, .bat scripts
- Files in suspicious locations
```

**2. Network Share Access:**

```bash
Search for:
file:///\\SERVER\
file:///\\WORKSTATION\C$\
file:///\\*\ADMIN$\

Indicates:
- Lateral movement
- Remote file access
- Network reconnaissance
- Data exfiltration
```

**3. USB Drive Access:**

```bash
Search for:
file:///E:/
file:///F:/
file:///G:/

Cross-reference with:
- LNK files (volume serial numbers)
- Event logs (USB insertion)
- Timeline of activity
```

**4. Deleted File Evidence:**

```bash
file:/// entries persist after file deletion!

Use case:
- File accessed but now deleted
- WebCache preserves path
- Cross-reference with:
  - Recycle Bin
  - LNK files
  - MFT records
  - Volume Shadow Copies
```

***

### 📧 Email Attachments Investigation

#### Overview

**Key Statistic**: 80% of email data stored as attachments

**Forensic Value:**

* Phishing investigation
* Malware delivery
* Data exfiltration
* Intellectual property theft
* Communication analysis

***

#### Microsoft Outlook

**File Formats:**

| Format  | Description            | Use Case                   |
| ------- | ---------------------- | -------------------------- |
| **PST** | Personal Storage Table | User's local email archive |
| **OST** | Offline Storage Table  | Cached Exchange mailbox    |

**Locations:**

```bash
Primary:
%USERPROFILE%\Documents\Outlook Files\
%USERPROFILE%\AppData\Local\Microsoft\Outlook\

Alternative:
%USERPROFILE%\AppData\Roaming\Microsoft\Outlook\

Temporary Attachments (OLK):
%USERPROFILE%\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\<random>\

Outlook 2016+:
%USERPROFILE%\AppData\Local\Microsoft\Outlook\RoamCache\
```

**Collection:**

{% code overflow="wrap" %}
```powershell
# Collect Outlook data files
$OutlookLocations = @(
    "$env:USERPROFILE\Documents\Outlook Files",
    "$env:USERPROFILE\AppData\Local\Microsoft\Outlook",
    "$env:USERPROFILE\AppData\Roaming\Microsoft\Outlook",
    "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\Content.Outlook"
)

foreach ($Location in $OutlookLocations) {
    if (Test-Path $Location) {
        # Find PST and OST files
        Get-ChildItem $Location -Include *.pst,*.ost -Recurse |
            Copy-Item -Destination "C:\DFIR_Collection\Outlook\" -Force
    }
}

# Collect OLK temporary attachments
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\Content.Outlook" -Recurse |
    Copy-Item -Destination "C:\DFIR_Collection\Outlook\TempAttachments\" -Force -Recurse
```
{% endcode %}

**Analysis:**

**Using Outlook (If Available):**

```bash
1. Open Outlook
2. File → Open & Export → Open Outlook Data File
3. Browse to PST/OST file
4. Navigate folders
5. Search for:
   - Attachments
   - Specific senders
   - Keywords
   - Date ranges
6. Export relevant emails
```

**Using SysTools Outlook PST Viewer (Free):**

```bash
1. Download and install
2. Load PST file
3. Browse folders
4. View emails and attachments
5. Export attachments
6. Export emails to MSG, EML formats
```

**Using libpff (Python):**

```bash
# Install
pip install pypff

# Python script to extract attachments
import pypff

pst = pypff.file()
pst.open("C:\\Evidence\\outlook.pst")

root = pst.get_root_folder()

def extract_attachments(folder, output_path):
    for message in folder.sub_messages:
        for attachment in message.attachments:
            filename = attachment.get_name()
            data = attachment.read_buffer(attachment.get_size())
            
            with open(f"{output_path}\\{filename}", "wb") as f:
                f.write(data)
                
    for subfolder in folder.sub_folders:
        extract_attachments(subfolder, output_path)

extract_attachments(root, "C:\\Analysis\\Attachments")
```

**Using KAPE with Outlook Module:**

{% code overflow="wrap" %}
```powershell
.\kape.exe --target Outlook --tdest C:\Collection --module OutlookAttachments --mdest C:\Analysis
```
{% endcode %}

***

#### Investigation Workflows - Email Attachments

**1. Phishing Investigation:**

```bash
Goal: Identify phishing email with malicious attachment

Steps:
1. Identify suspected phishing timeframe
2. Load PST/OST in viewer
3. Search for:
   - External senders
   - Suspicious subject lines (invoice, urgent, verify)
   - Attachments: .docx, .xlsx, .zip, .exe
4. Extract suspicious attachments
5. Check attachment hashes (VirusTotal)
6. Correlate with:
   - Browser downloads (if link clicked)
   - Office Trust Records (if doc opened)
   - Prefetch (if file executed)
```

**2. Macro-Enabled Document Tracking:**

```bash
Search criteria:
- Attachments: *.docm, *.xlsm, *.pptm (macro-enabled)
- From: External domains
- Date: Incident timeframe

Correlation:
1. Email received time
2. Attachment saved location
3. Office Trust Record (macro enabled)
4. Process execution (Event 4688)
5. Network connections (C2 callback)
```

**3. Data Exfiltration:**

```bash
Search for:
- Large attachments sent by user
- Multiple attachments to external addresses
- Personal email domains (gmail, yahoo) from work
- Archive files (.zip, .7z, .rar)

Red flags:
- Emails to personal accounts
- Multiple small attachments (avoiding size limits)
- Encrypted archives
- Generic subject lines
```

**4. Timeline Construction:**

```bash
Email artifacts timeline:
1. Email received (message timestamp)
2. Attachment saved to disk (temp folder)
3. File opened (LNK created)
4. Macros enabled (Trust Records)
5. Process launched (Prefetch, Event 4688)
6. Persistence established (Run keys, services)
```

***

#### OLK Temporary Attachments

**Overview:**

* When user opens attachment, copied to temp location
* Remains until Outlook closed or attachment deleted
* Can recover recently opened attachments

**Location:**

```bash
%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook\<Random 8-char folder>\
```

**Collection & Analysis:**

{% code overflow="wrap" %}
```powershell
# Find all OLK folders
$OLKFolders = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\Content.Outlook" -Directory

foreach ($Folder in $OLKFolders) {
    $Files = Get-ChildItem $Folder.FullName -File
    
    foreach ($File in $Files) {
        [PSCustomObject]@{
            FileName = $File.Name
            Size = $File.Length
            Created = $File.CreationTime
            Modified = $File.LastWriteTime
            Accessed = $File.LastAccessTime
            Location = $File.FullName
        }
    }
} | Export-Csv C:\Analysis\OLK_Attachments.csv -NoTypeInformation
```
{% endcode %}

**Investigation Use:**

```bash
OLK files indicate:
✓ Attachment was opened from email
✓ Approximate open time (file timestamps)
✓ File type and size
✓ Persistence after email deletion

Cross-reference with:
- Office MRU (if Office doc)
- Prefetch (if executable)
- Event logs (process creation)
```

***

### 🔄 Cross-Browser Analysis

#### Multi-Browser Investigation

**Scenario**: User may use multiple browsers (work = Edge, personal = Chrome)

**Comprehensive Collection:**

{% code overflow="wrap" %}
```powershell
# Create collection structure
$CollectionRoot = "C:\DFIR_Collection\Browsers"
New-Item -Path $CollectionRoot -ItemType Directory -Force

# Chrome
$ChromeProfiles = Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Directory -ErrorAction SilentlyContinue
foreach ($Profile in $ChromeProfiles | Where-Object {$_.Name -like "*Profile*" -or $_.Name -eq "Default"}) {
    $Dest = "$CollectionRoot\Chrome\$($Profile.Name)"
    New-Item -Path $Dest -ItemType Directory -Force
    
    Copy-Item "$($Profile.FullName)\History" -Destination $Dest -Force -ErrorAction SilentlyContinue
    Copy-Item "$($Profile.FullName)\Cookies" -Destination $Dest -Force -ErrorAction SilentlyContinue
    Copy-Item "$($Profile.FullName)\Login Data" -Destination $Dest -Force -ErrorAction SilentlyContinue
}

# Edge
$EdgeProfiles = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Edge\User Data" -Directory -ErrorAction SilentlyContinue
foreach ($Profile in $EdgeProfiles | Where-Object {$_.Name -like "*Profile*" -or $_.Name -eq "Default"}) {
    $Dest = "$CollectionRoot\Edge\$($Profile.Name)"
    New-Item -Path $Dest -ItemType Directory -Force
    
    Copy-Item "$($Profile.FullName)\History" -Destination $Dest -Force -ErrorAction SilentlyContinue
    Copy-Item "$($Profile.FullName)\Cookies" -Destination $Dest -Force -ErrorAction SilentlyContinue
}

# Firefox
$FirefoxProfiles = Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue
foreach ($Profile in $FirefoxProfiles) {
    $Dest = "$CollectionRoot\Firefox\$($Profile.Name)"
    New-Item -Path $Dest -ItemType Directory -Force
    
    Copy-Item "$($Profile.FullName)\places.sqlite" -Destination $Dest -Force -ErrorAction SilentlyContinue
    Copy-Item "$($Profile.FullName)\cookies.sqlite" -Destination $Dest -Force -ErrorAction SilentlyContinue
}

# Internet Explorer / WebCache
Copy-Item "$env:LOCALAPPDATA\Microsoft\Windows\WebCache\WebCacheV01.dat" -Destination "$CollectionRoot\IE\" -Force -ErrorAction SilentlyContinue
```
{% endcode %}

#### Unified Timeline Creation

**Goal**: Combine all browser activity into single timeline

**Using BrowsingHistoryView:**

```bash
1. Run BrowsingHistoryView
2. Advanced Options:
   - Check all browsers (Chrome, Edge, Firefox, IE)
   - Load from all profiles
3. View combined history
4. Sort by Visit Time
5. Export to CSV
```

**Manual Correlation:**

{% code overflow="wrap" %}
```powershell
# Parse all browsers and combine
$AllActivity = @()

# Chrome parsing (simplified)
$ChromeHistory = Import-Csv "C:\Analysis\Chrome_History_Parsed.csv"
$ChromeHistory | ForEach-Object {
    $AllActivity += [PSCustomObject]@{
        Browser = "Chrome"
        Timestamp = $_.VisitTime
        Activity = "Browse"
        URL = $_.URL
        Title = $_.Title
    }
}

# Edge parsing
$EdgeHistory = Import-Csv "C:\Analysis\Edge_History_Parsed.csv"
$EdgeHistory | ForEach-Object {
    $AllActivity += [PSCustomObject]@{
        Browser = "Edge"
        Timestamp = $_.VisitTime
        Activity = "Browse"
        URL = $_.URL
        Title = $_.Title
    }
}

# Firefox parsing
$FirefoxHistory = Import-Csv "C:\Analysis\Firefox_History_Parsed.csv"
$FirefoxHistory | ForEach-Object {
    $AllActivity += [PSCustomObject]@{
        Browser = "Firefox"
        Timestamp = $_.VisitTime
        Activity = "Browse"
        URL = $_.URL
        Title = $_.Title
    }
}

# Combine and sort
$AllActivity | Sort-Object Timestamp | Export-Csv C:\Analysis\Unified_Browser_Timeline.csv -NoTypeInformation
```
{% endcode %}

***

### 📚 Investigation Playbooks

#### Playbook 1: Malware Download Investigation

**Objective**: Investigate suspected malware download and execution

**Phase 1: Initial Indicators (15 min)**

```bash
□ Identify alert/indicator (AV alert, suspicious process, C2 beacon)
□ Determine approximate timeframe
□ Identify affected user
□ Check running processes
□ Check network connections
```

**Phase 2: Download Detection (30 min)**

```bash
□ Check browser download history (all browsers)
  - Chrome: downloads table
  - Edge: downloads table
  - Firefox: moz_annos table
  
□ Search for downloaded executables:
  - .exe, .dll, .scr
  - .ps1, .bat, .vbs
  - .zip, .rar (may contain malware)
  - .hta, .js, .wsf
  
□ Note for each download:
  - Source URL
  - Download time
  - File save location
  - Whether file was opened
```

**Phase 3: Source Analysis (30 min)**

```bash
□ Check browser history for:
  - How user reached download URL
  - Referrer sites
  - Search queries leading to download
  - Email link click (if from webmail)
  
□ Get full URL chain:
  - downloads_url_chains table
  - Track redirects from initial click
  
□ Categorize source:
  - Phishing email link
  - Malicious advertisement
  - Compromised website
  - Direct navigation to malware site
  - File sharing site
```

**Phase 4: File Analysis (45 min)**

```bash
□ Locate downloaded file:
  - Check Downloads folder
  - Check path in download history
  - If missing → check Recycle Bin
  
□ If file exists:
  - Calculate hash (SHA256)
  - Check VirusTotal
  - Check internal malware database
  - Note file size, timestamps
  - Submit for sandbox analysis if unknown
  
□ If file deleted:
  - Check Prefetch (proves execution)
  - Check Amcache (get SHA1 hash)
  - Check ShimCache (file presence)
  - Check Recycle Bin
  - Check file carving
```

**Phase 5: Execution Evidence (45 min)**

```bash
□ Check Prefetch:
  - Look for downloaded file name
  - Get last 8 execution times
  - Get run count
  
□ Check Event Logs:
  - Event 4688 (process creation)
  - Time window: 0-5 minutes after download
  - Look for parent process (browser or explorer.exe)
  
□ Check BAM/DAM:
  - Last execution timestamp
  - User account used
  
□ Check UserAssist (if GUI app):
  - Execution count
  - Last run time
```

**Phase 6: Post-Execution Analysis (60 min)**

```bash
□ Check for child processes:
  - PowerShell, cmd.exe
  - Network tools (wget, curl)
  - System tools (reg.exe, sc.exe)
  
□ Check for persistence:
  - Registry Run keys
  - Services (Event 7045, 4697)
  - Scheduled tasks (Event 4698)
  - WMI event consumers
  
□ Check network activity:
  - SRUM (bytes sent/received)
  - Firewall logs
  - Proxy logs
  
□ Check for lateral movement:
  - Network logons (Type 3)
  - RDP sessions (Type 10)
  - Share access (Event 5140)
```

**Phase 7: Timeline & Reporting (30 min)**

```bash
□ Build complete timeline:
  1. User browsing → malicious site
  2. File download initiated
  3. File download completed
  4. File executed
  5. Malicious process actions
  6. Persistence established
  7. Network connections (C2)
  8. Lateral movement (if applicable)
  
□ Document IOCs:
  - URLs
  - File hashes
  - File names
  - IP addresses
  - Domain names
  - Registry keys
  - Service names
  
□ Assess impact:
  - Scope of compromise
  - Data accessed
  - Systems affected
  - Credentials compromised
```

***

#### Playbook 2: Phishing Investigation

**Objective**: Investigate phishing email leading to credential theft or malware

**Phase 1: Email Identification (20 min)**

```bash
□ Locate phishing email:
  - Search Outlook PST/OST
  - Subject line keywords
  - Sender domain
  - Date/time window
  
□ Document email details:
  - Sender email address
  - Sender display name
  - Subject line
  - Received time
  - Attachments
  - Links in email body
  
□ Extract email:
  - Save as .msg or .eml
  - Export headers
  - Screenshot email
```

**Phase 2: Link Analysis (30 min)**

```bash
If email contains links:

□ Extract all URLs from email
□ Check URL reputation
□ Identify landing page:
  - Credential harvesting
  - Malware download
  - Redirect chain
  
□ Check browser history:
  - Did user click link?
  - What time?
  - What site loaded?
  - Full navigation path
  
□ Check downloaded files:
  - If link led to download
  - File type
  - Source URL
  - Download completion
```

**Phase 3: Attachment Analysis (45 min)**

```bash
If email contains attachments:

□ Extract attachment from email
□ Document metadata:
  - Filename
  - File size
  - File hash
  - Creation date (in email)
  
□ Check file type:
  - Document (.docx, .xlsx, .pdf)
  - Archive (.zip, .rar)
  - Executable (.exe, .scr)
  
□ For documents:
  - Check for macros
  - Check Office Trust Records
  - Extract macro code if present
  - Check for exploits (CVEs)
  
□ For archives:
  - List contents
  - Extract files
  - Check each file
  
□ For executables:
  - Hash lookup (VirusTotal)
  - Sandbox analysis
  - Static analysis
```

**Phase 4: User Actions (45 min)**

```bash
□ Did user open attachment?
  - Check OLK temp folders
  - Check Recent Files (RecentDocs)
  - Check Office MRU
  - Check LNK files
  
□ If document opened:
  - Check Office Trust Records
  - Were macros enabled? (FF FF FF 7F)
  - Check Office OAlerts
  - Check Reading Locations (time spent)
  
□ If executable run:
  - Check Prefetch
  - Check process execution (Event 4688)
  - Check parent process
  - Execution time vs. email time
```

**Phase 5: Credential Harvesting Check (30 min)**

```bash
If phishing site mimics login:

□ Check browser history for:
  - Fake login pages
  - Domains similar to legitimate (typosquatting)
  - URLs with "login", "signin", "verify"
  
□ Check browser saved passwords:
  - Were credentials saved?
  - Check Login Data database
  
□ Check for account compromise:
  - Unusual logons (Event 4624)
  - Failed logons (Event 4625)
  - Logons from unusual IPs
  - Account lockouts
  
□ Check for account usage:
  - Email sent from account
  - File access
  - Data exfiltration
  - Lateral movement
```

**Phase 6: Impact Assessment (45 min)**

```bash
□ Determine compromise level:
  - Email preview only (low risk)
  - Clicked link but didnt proceed (low-medium)
  - Downloaded file but didnt open (medium)
  - Opened document (medium-high)
  - Enabled macros (high)
  - Executed malware (critical)
  - Entered credentials (critical)
  
□ Check for spread:
  - Did user forward email?
  - Check sent items
  - Other users affected?
  
□ Check for malicious activity:
  - Persistence mechanisms
  - Data access
  - Exfiltration
  - Lateral movement
```

***

#### Playbook 3: Data Exfiltration via Web

**Objective**: Detect data theft via web uploads

**Phase 1: Baseline Activity (30 min)**

```bash
□ Identify users normal web usage:
  - Common sites visited
  - Typical upload activities
  - Business-related cloud services
  
□ Identify sensitive data:
  - Location of confidential files
  - File types of concern
  - Normal data flow patterns
```

**Phase 2: File Access Detection (45 min)**

```bash
□ Check recent file access:
  - RecentDocs registry
  - Office MRU
  - LNK files
  - Jump Lists
  
□ Focus on sensitive files:
  - Financial documents
  - Customer data
  - Intellectual property
  - HR files
  - Credentials
  
□ Build timeline:
  - When files were accessed
  - Which applications used
  - How long files were open
```

**Phase 3: Browser Activity Analysis (60 min)**

```bash
□ Check browser history for:
  - Cloud storage sites (not approved)
    • Personal Google Drive
    • Dropbox
    • MEGA
    • WeTransfer
    • File sharing sites
  
  - Email services:
    • Personal Gmail, Yahoo
    • Temporary email services
  
  - Paste sites:
    • Pastebin
    • GitHub Gists
    • Hastebin
  
□ Check downloads:
  - Were files downloaded FROM cloud?
  - Potential data staging
  
□ Check for file:/// access:
  - WebCache database
  - Local files accessed via browser
```

**Phase 4: Upload Detection (60 min)**

```bash
Note: Upload detection is challenging - no explicit "uploads" table

□ Browser history analysis:
  - POST requests (requires cache analysis)
  - Repeated visits to upload pages
  - "upload", "send", "share" in URLs
  
□ SRUM analysis:
  - Check network activity
  - Bytes sent (high uploads)
  - Applications with high sent/received ratio
  
□ Check browser cache:
  - Upload confirmation pages
  - "File uploaded successfully" text
  - Upload tokens/IDs
  
□ Check cookies:
  - Cloud service sessions
  - Upload session data
```

**Phase 5: Correlation (45 min)**

```bash
□ Build timeline:
  1. File accessed (RecentDocs, MRU)
  2. Browser navigated to upload site
  3. Time spent on site
  4. Network activity spike (SRUM)
  5. File potentially deleted (cleanup)
  
□ Cross-reference:
  - File timestamps with browser activity
  - Browser activity with network logs
  - File size with bytes uploaded
  
□ Check for evidence destruction:
  - Files deleted after upload
  - Browser history cleared
  - Cache cleared
```

**Phase 6: External Evidence (varies)**

```bash
□ Check network logs:
  - Proxy logs (if available)
  - Firewall logs
  - IDS/IPS alerts
  - Cloud service logs
  
□ Check cloud services:
  - Corporate G Suite audit logs
  - Office 365 audit logs
  - Third-party DLP logs
  
□ Check email:
  - Files sent as attachments
  - Email to personal accounts
  - Large emails sent
```

***

### 🛠️ Tool Reference

#### Browser Analysis Tools

**BrowsingHistoryView** - NirSoft (Windows)

```bash
Download: https://www.nirsoft.net/utils/browsing_history_view.html

Features:
- Multi-browser support
- All profiles
- Unified timeline
- Filter and search
- Export CSV/HTML/XML

Usage:
1. Run executable
2. Advanced Options → Select browsers/profiles
3. View unified history
4. Export results
```

**DB Browser for SQLite** (Cross-platform)

```bash
Download: https://sqlitebrowser.org/

Usage:
1. Open History or places.sqlite
2. Browse Data → Select table
3. Execute SQL queries
4. Export results
```

**Hindsight** - Python Tool

```bash
Installation:
pip install pyhindsight

Usage:
hindsight.py -i "Chrome/User Data/Default" -o output_folder --format xlsx

Features:
- Chrome/Chromium parsing
- Multiple output formats
- Bookmark analysis
- Extension analysis
```

**Dumpzilla** - Firefox Analysis

```bash
Download: https://github.com/Busindre/dumpzilla

Usage:
python dumpzilla.py /path/to/firefox/profile

Features:
- Firefox-specific
- Downloads
- History
- Cookies
- Passwords (if not encrypted)
```

***

#### Email Analysis Tools

**OutlookView Tools** - NirSoft

```bash
- OutlookAttachView: View attachments in PST/OST
- OutlookAddressBookView: Extract contacts
- OutlookStatView: Statistics

Download: https://www.nirsoft.net/outlook_tools.html
```

**Kernel PST Viewer** - Free

```bash
Features:
- View PST/OST files
- No Outlook required
- Export attachments
- Search emails
```

**libpff** - Python Library

```bash
Installation:
pip install pypff

Usage: Parse PST/OST programmatically
- Extract emails
- Extract attachments
- Search by criteria
```

***

#### Collection Tools

**KAPE** - Kroll Artifact Parser and Extractor

```bash
Targets:
.\kape.exe --target ChromeHistory --tdest C:\Collection
.\kape.exe --target FirefoxHistory --tdest C:\Collection
.\kape.exe --target WebBrowsers --tdest C:\Collection
.\kape.exe --target Outlook --tdest C:\Collection

Modules:
.\kape.exe --module BrowsingHistory --msource C:\Collection --mdest C:\Analysis
```

**FTK Imager**

```bash
Usage:
- Mount forensic images
- Extract locked files (WebCache)
- Create forensic copies
```

***

### 📊 Quick Reference Cards

#### Browser Database Comparison

| Browser            | Database        | Format | History Table                   | Downloads Table                   | Location                                              |
| ------------------ | --------------- | ------ | ------------------------------- | --------------------------------- | ----------------------------------------------------- |
| **Chrome**         | History         | SQLite | urls, visits                    | downloads, downloads\_url\_chains | %LOCALAPPDATA%\Google\Chrome\User Data\<Profile>\\    |
| **Edge**           | History         | SQLite | urls, visits                    | downloads, downloads\_url\_chains | %LOCALAPPDATA%\Microsoft\Edge\User Data\<Profile>\\   |
| **Firefox**        | places.sqlite   | SQLite | moz\_places, moz\_historyvisits | moz\_annos                        | %APPDATA%\Mozilla\Firefox\Profiles\<random>.default\\ |
| **IE/Edge Legacy** | WebCacheV01.dat | ESE    | Container\_#                    | Container\_#                      | %LOCALAPPDATA%\Microsoft\Windows\WebCache\\           |

#### Time Conversion Reference

**Chrome/Edge Timestamps:**

```bash
Format: WebKit/Chrome timestamp (microseconds since 1601-01-01)

SQL Conversion:
datetime(timestamp/1000000-11644473600, 'unixepoch', 'localtime')

PowerShell Conversion:
[DateTime]::FromFileTimeUtc($ChromeTimestamp * 10)
```

**Firefox Timestamps:**

```bash
Format: Unix timestamp (microseconds since 1970-01-01)

SQL Conversion:
datetime(timestamp/1000000, 'unixepoch', 'localtime')

PowerShell Conversion:
$UnixEpoch = Get-Date "1970-01-01 00:00:00"
$UnixEpoch.AddSeconds($FirefoxTimestamp / 1000000)
```

#### Investigation Time Estimates

| Task                                   | Estimated Time |
| -------------------------------------- | -------------- |
| Quick download history check           | 10-15 min      |
| Comprehensive browser history analysis | 30-60 min      |
| Multi-browser correlation              | 45-90 min      |
| Malware download investigation         | 2-3 hours      |
| Phishing investigation                 | 2-4 hours      |
| Email attachment analysis              | 1-2 hours      |
| Data exfiltration investigation        | 3-6 hours      |
| Complete web activity timeline         | 4-8 hours      |

***

### 🎓 Pro Tips

#### Cross-Artifact Correlation Strategy

```bash
Complete Investigation Flow:

1. Browser Download → File downloaded
         ↓
2. Downloads Folder → File saved to disk
         ↓
3. LNK File Created → File accessed
         ↓
4. RecentDocs → File opened
         ↓
5. Office MRU → If document, tracked here
         ↓
6. Trust Records → If macros enabled
         ↓
7. Prefetch → If executable, execution proof
         ↓
8. Event 4688 → Process creation
         ↓
9. Network Activity → C2 beacon (SRUM)
         ↓
10. Persistence → Run keys, services, tasks
```

#### Red Flag Summary

```bash
🚩🚩🚩 IMMEDIATE INVESTIGATION:

Browser Downloads:
- .exe, .dll, .scr downloaded and opened
- Files from free hosting sites
- Downloads marked "dangerous" but proceeded
- Executable disguised as document

Browser History:
- IP address URLs
- Typosquatted domains (micros0ft.com)
- Suspicious TLDs (.tk, .ml, .xyz)
- Credential harvesting pages

Email:
- External attachments with macros
- Attachments from unknown senders
- Invoice/payment themed emails
- Multiple recipients (campaign)

WebCache file:///:
- .exe files accessed locally
- Network share access (\\C$)
- USB drive file access (E:/)
- Files from Temp directories
```

#### Common Pitfalls

```bash
❌ Only checking one browser (user may use multiple)
❌ Forgetting about WebCache file:/// access
❌ Not checking all Chrome/Edge profiles
❌ Ignoring OLK temporary attachment folders
❌ Not correlating download time with execution
❌ Missing downloads_url_chains (redirect analysis)
❌ Not checking if downloaded file still exists
❌ Forgetting to check Recycle Bin for deleted downloads
❌ Not analyzing referrer URLs (how user got to download)
❌ Ignoring search queries leading to malicious sites
```

#### Timeline Reconstruction Tips

```bash
✅ Combine multiple sources:
   1. Browser history (navigation)
   2. Download history (file acquisition)
   3. File system (file timestamps)
   4. Prefetch (execution times)
   5. Event logs (process creation)
   6. SRUM (network activity)
   
✅ Look for gaps:
   - History cleared?
   - Downloads deleted?
   - Private browsing mode?
   
✅ Corroborate evidence:
   - Browser says file downloaded
   - File system shows file exists
   - Prefetch proves execution
   - Event log confirms process
```

***

_Use this guide for comprehensive web-based investigation. Remember: Browser artifacts + file system artifacts + execution artifacts = complete picture!_
