# Browser Forensics – DFIR Workflow & Cheatsheet

## Quick Reference: Investigation Priority Matrix

| Priority   | Artifact            | Key Questions Answered              | Volatility |
| ---------- | ------------------- | ----------------------------------- | ---------- |
| **HIGH**   | History & Downloads | What sites? When? What files?       | Medium     |
| **HIGH**   | Session Restore     | Active tabs at incident time?       | High       |
| **HIGH**   | Cache               | What content viewed? Screenshots?   | Medium     |
| **MEDIUM** | Cookies             | Session data? Authentication?       | Low        |
| **MEDIUM** | Auto-Complete Data  | What was searched/typed?            | Low        |
| **MEDIUM** | Stored Credentials  | What accounts accessed?             | Low        |
| **LOW**    | Bookmarks           | Sites of interest (may never visit) | Very Low   |
| **LOW**    | Extensions          | Capabilities added? Malicious?      | Very Low   |

***

## Investigation Workflow

### Phase 1: Initial Triage (High Priority)

**Goal:** Establish timeline and user activity scope

**1.1 Browser History & Download History**

**What it tells you:** Websites visited, frequency, downloaded files, timeline

#### **Firefox Locations:**

{% code overflow="wrap" %}
```bash
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default\places.sqlite
```
{% endcode %}

#### **Chrome/Edge Locations:**

```bash
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\History
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\History
```

**Key Investigation Points:**

* ✓ Check ALL profiles (Default, Profile1, Profile2, etc.)
* ✓ Visit frequency indicates user interest/habit
* ✓ Download metadata: filename, size, source URL, referring page
* ✓ Check both `downloads` and `download_url_chains` tables (Chromium)
* ✓ Cross-reference with filesystem timestamps

**SQLite Tables to Query:**

* `urls` - Browsing history
* `visits` - Individual visit records with timestamps
* `downloads` - Download metadata
* `download_url_chains` - Redirect chains

***

#### **1.2 Session Restore Files**

**What it tells you:** Active browser state at crash/incident time

**Firefox Locations:**

{% code overflow="wrap" %}
```bash
# Newer versions (JSONLZ4 format)
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default\sessionstore.jsonlz4
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default\sessionstore-backups\

# Older versions
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default\sessionstore.js
```
{% endcode %}

#### **Chrome/Edge Locations:**

```bash
# Newer versions
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Sessions\
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Sessions\
Files: Session_<timestamp>, Tabs_<timestamp>

# Older versions
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\
Files: Current Session, Current Tabs, Last Session, Last Tabs
```

**Key Investigation Points:**

* ✓ **HIGHLY VOLATILE** - Capture early in investigation
* ✓ Shows tabs open at time of incident/crash
* ✓ Includes referring URLs (how user got there)
* ✓ May contain form data, JavaScript state
* ✓ Browser window configuration (size, pinned tabs)
* ✓ Tab transition types reveal navigation method

***

### Phase 2: Content Analysis (Medium Priority)

**Goal:** Understand what content user actually viewed

**2.1 Cache Files**

**What it tells you:** Actual webpage content, images, media viewed

#### **Firefox Locations:**

```bash
# Firefox 32+
%USERPROFILE%\AppData\Local\Mozilla\Firefox\Profiles\<random>.default\cache2

# Firefox 31 and earlier
%USERPROFILE%\AppData\Local\Mozilla\Firefox\Profiles\<random>.default\Cache
```

#### **Chrome/Edge Locations:**

```bash
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Cache\
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Cache\
Files: data_# and f_######
```

**Key Investigation Points:**

* ✓ Provides "snapshot in time" of viewed content
* ✓ Recover actual images, videos, documents
* ✓ Timestamps: first cached AND last viewed
* ✓ Can reconstruct pages even if history cleared
* ✓ Tied to specific local user account
* ✓ Use specialized tools (NirSoft ChromeCacheView, MZCacheView)

***

#### **2.2 Media History (Chromium Only)**

**What it tells you:** Audio/video played on websites

#### **Chrome/Edge Locations:**

```bash
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Media History
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Media History
```

**Key Investigation Points:**

* ✓ Three primary tables: `playback`, `playbackSession`, `origin`
* ✓ URLs of media played
* ✓ Watch time duration
* ✓ Last video position (where user stopped)
* ✓ Last play time
* ⚠️ Unclear persistence when other history cleared

***

### Phase 3: User Behaviour & Intent (Medium Priority)

**Goal:** Understand user searches, inputs, and interests

#### **3.1 Auto-Complete Data**

**What it tells you:** User searches, form inputs, typed URLs

#### **Firefox Locations:**

{% code overflow="wrap" %}
```bash
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default\places.sqlite
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default\formhistory.sqlite
```
{% endcode %}

#### **Chrome/Edge Locations - By Data Type:**

**Search Terms:**

```bash
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\History
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\History
Table: keyword_search_terms
```

**Web Form Data:**

```bash
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Web Data
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Web Data
```

**Omnibox (URL Bar) Entries:**

```bash
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Shortcuts
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Shortcuts
```

**Keystroke-Level Recording:**

{% code overflow="wrap" %}
```bash
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Network Action Predictor
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Network Action Predictor
⚠️ Records typing letter-by-letter
```
{% endcode %}

**Login Credentials:**

```bash
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Login Data
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Login Data
```

**Key Investigation Points:**

* ✓ Shows user knowledge and intent
* ✓ Connects typed data to user account
* ✓ Search terms reveal investigation targets
* ✓ Network Action Predictor = keystroke logger
* ✓ Form data may include PII, credentials

***

#### **3.2 Cookies**

**What it tells you:** Session data, authentication tokens, tracking

**Firefox Locations:**

```bash
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default\cookies.sqlite
```

#### **Chrome/Edge Locations:**

```bash
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Network\Cookies
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Network\Cookies
```

**Key Investigation Points:**

* ✓ Confirms website visits
* ✓ Session authentication tokens
* ✓ User preferences and settings
* ✓ Tracking/advertising IDs
* ✓ Creation and expiration times
* ✓ May persist after history clearing

***

### Phase 4: Configuration & Credentials (Low-Medium Priority)

**Goal:** Understand browser setup and account access

#### **4.1 Stored Credentials**

**What it tells you:** Saved usernames/passwords for websites

**Firefox Locations:**

```bash
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default\logins.json
```

**Chrome/Edge Locations:**

```bash
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Login Data
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Login Data
```

**Key Investigation Points:**

* ✓ **Encrypted via Windows DPAPI**
* ✓ Firefox: JSON format with hostname, URL, creation time, last used
* ✓ Chrome/Edge: SQLite with origin URL, username, date created/used
* ⚠️ **Win 10/11 Microsoft accounts:** DPAPI uses 44-char random password
* ✓ Metadata available even if passwords encrypted
* ✓ **Best retrieved on live system with user logged in**
* ✓ Shows accounts user accessed

***

#### **4.2 Browser Preferences**

**What it tells you:** Privacy settings, sync status, user engagement

**Firefox Locations:**

```bash
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default\prefs.js
```

**Chrome/Edge Locations:**

```bash
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Preferences
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Preferences
```

**Key Investigation Points:**

* ✓ Firefox: Sync status, last sync time, artifacts synced
* ✓ Chrome/Edge: JSON format
  * `per_host_zoom_levels` - Sites frequently visited
  * `media-engagement` - Media interaction scores
  * `site_engagement` - Overall site interaction
* ✓ Edge: `account_info`, `clear_data_on_exit`, sync settings
* ✓ Privacy settings (anti-tracking, cookie policies)
* ✓ **Sync can move artifacts across devices** - check timestamps carefully

***

### Phase 5: Supporting Artifacts (Low Priority)

#### **5.1 Bookmarks**

**What it tells you:** Sites of interest (not necessarily visited)

**Firefox Locations:**

{% code overflow="wrap" %}
```bash
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default\places.sqlite
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default\bookmarkbackups\bookmarks-<date>.jsonlz4
```
{% endcode %}

**Chrome/Edge Locations:**

```bash
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Bookmarks
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Bookmarks
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Bookmarks.bak
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Bookmarks.msbak
```

**Key Investigation Points:**

* ✓ JSON format (Firefox backups, all Chromium)
* ✓ Shows intent/interest, not necessarily activity
* ⚠️ **Not all bookmarks are user-generated** (defaults exist)
* ⚠️ **Can bookmark without visiting**
* ✓ Firefox: Multiple backup copies in bookmarkbackups folder
* ✓ Check .bak files for deleted bookmarks

***

#### **5.2 Extensions & Add-ons**

**What it tells you:** Added capabilities, potential malware vector

**Firefox Locations:**

{% code overflow="wrap" %}
```bash
# Firefox 26+
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default\addons.json
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default\extensions.json

# Firefox 4-25
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default\extensions.sqlite
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random>.default\addons.sqlite
```
{% endcode %}

**Chrome/Edge Locations:**

{% code overflow="wrap" %}
```bash
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Extensions\<GUID>\<version>\
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Extensions\<GUID>\<version>\
```
{% endcode %}

**Key Investigation Points:**

* ✓ Firefox: Name, source, install time, last update, status
* ✓ Chrome/Edge: Each extension in GUID-named folder
  * Folder creation time = installation time
  * `manifest.json` = name, URL, permissions, version
* ✓ Check Preferences file for additional extension data
* ⚠️ **Extensions can sync across devices** (affects timestamp interpretation)
* ✓ Look for suspicious permissions (screen capture, keylogging, etc.)
* ✓ Cross-reference with known malicious extensions

***

### Critical Investigation Tips

#### Multi-Profile Awareness

```bash
⚠️ ALWAYS check for multiple browser profiles:
- Default
- Profile 1, Profile 2, Profile 3...
- Guest profiles
- Work profiles (Edge)
```

#### Timestamp Interpretation

```bash
✓ Cache: First cached vs. Last accessed
✓ Downloads: Start time vs. End time
✓ Cookies: Created vs. Expires vs. Last accessed
✓ History: Visit time (can have multiple per URL)
⚠️ Sync can alter timestamps - check sync settings
```

#### Data Persistence Hierarchy

```bash
Most Persistent:
1. Cookies (often survive clearing)
2. Bookmarks
3. Stored Credentials
4. Extensions
5. Preferences

Least Persistent:
6. Auto-complete data
7. History
8. Cache
9. Session Restore (most volatile)
```

#### Anti-Forensics Detection

```bash
Check for:
- Browser cleaning tools in history (CCleaner, BleachBit)
- Privacy-focused browsers (Tor, Brave private mode)
- Extensions for history clearing
- Preferences: clear_data_on_exit = true
- Gaps in history timelines
- Mismatched artifact timestamps
```

#### Live System vs. Dead Disk

```bash
LIVE SYSTEM ADVANTAGES:
✓ Decrypt stored credentials (DPAPI with user logged in)
✓ Capture active sessions
✓ View current cache state
✓ Access locked SQLite databases

DEAD DISK ADVANTAGES:
✓ No data contamination
✓ Deleted artifact recovery
✓ Volume shadow copies
✓ Unallocated space carving
```

***

### Essential DFIR Tools

#### SQLite Browsers

* **DB Browser for SQLite** - View/query .sqlite files
* **SQLite Forensic Explorer** - Deleted record recovery

#### Browser-Specific Tools

* **Hindsight** - Chrome/Chromium timeline analysis
* **NirSoft BrowsingHistoryView** - Multi-browser history
* **NirSoft ChromeCacheView** - Cache file extraction
* **NirSoft MZCacheView** - Firefox cache extraction
* **Firefox Forensics Toolkit**

#### Comprehensive Suites

* **Magnet AXIOM** - Full browser artifact processing
* **X-Ways Forensics** - Browser artifact templates
* **Autopsy** - Open-source browser modules
* **KAPE** - Browser artifact collection targets

#### Manual Analysis

{% code overflow="wrap" %}
```bash
# Query SQLite from command line
sqlite3 History "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100;"

# Convert Chrome timestamps (microseconds since 1601-01-01)
# Use online converters or custom scripts

# Decompress Firefox JSONLZ4
# Use mozlz4 Python library or LZ4 tools
```
{% endcode %}

***

### Quick Command Reference

#### Identify Browser Profiles

```powershell
# Chrome
dir "C:\Users\*\AppData\Local\Google\Chrome\User Data" -Directory

# Edge  
dir "C:\Users\*\AppData\Local\Microsoft\Edge\User Data" -Directory

# Firefox
dir "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles" -Directory
```

#### Collect All Browser Artifacts (PowerShell)

{% code overflow="wrap" %}
```powershell
$destination = "C:\Cases\BrowserForensics"
$user = $env:USERNAME

# Chrome
Copy-Item "$env:LOCALAPPDATA\Google\Chrome\User Data" -Destination "$destination\Chrome" -Recurse

# Edge
Copy-Item "$env:LOCALAPPDATA\Microsoft\Edge\User Data" -Destination "$destination\Edge" -Recurse

# Firefox
Copy-Item "$env:APPDATA\Mozilla\Firefox\Profiles" -Destination "$destination\Firefox" -Recurse
```
{% endcode %}

#### Hash Browser Databases (Before Analysis)

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Cases\BrowserForensics" -Recurse -Include *.sqlite,*.db,*.json | 
    Get-FileHash -Algorithm SHA256 | 
    Export-Csv -Path "C:\Cases\BrowserHashes.csv"
```
{% endcode %}

***

### Investigation Checklist

#### Initial Response

* \[ ] Identify all user accounts on system
* \[ ] Identify all browsers installed
* \[ ] Document current date/time and timezone
* \[ ] Check if users currently logged in (live system)
* \[ ] Capture volatile session restore files FIRST

#### Data Collection

* \[ ] Collect all browser profiles (not just Default)
* \[ ] Hash all databases before opening
* \[ ] Document sync settings and last sync times
* \[ ] Check for browser backup/cleaning tools
* \[ ] Capture browser process memory (if live)

#### Analysis

* \[ ] Establish baseline timeline from history
* \[ ] Correlate downloads with filesystem artifacts
* \[ ] Cross-reference cookies with history
* \[ ] Check auto-complete for searches related to incident
* \[ ] Review extensions for malicious/suspicious capabilities
* \[ ] Analyse session restore for incident timeframe
* \[ ] Examine cache for evidence of viewed content

#### Reporting

* \[ ] Timeline of relevant browsing activity
* \[ ] Downloads tied to incident
* \[ ] Search terms indicating intent
* \[ ] Websites accessed related to case
* \[ ] Evidence of anti-forensics
* \[ ] Account credentials discovered
* \[ ] Screenshots/content from cache

***

### File Path Environment Variables

```bash
%USERPROFILE% = C:\Users\<username>
%LOCALAPPDATA% = C:\Users\<username>\AppData\Local
%APPDATA% = C:\Users\<username>\AppData\Roaming
```

***

### Notes & Gotchas

1. **Chrome Timestamp Format:** Microseconds since January 1, 1601 (Windows FILETIME)
2. **Firefox JSONLZ4:** Requires special decompression (mozlz4 library)
3. **DPAPI Encryption:** Tied to user account; decrypt on live system while logged in
4. **Profile Sync:** Can move artifacts between devices - verify device origin
5. **Private/Incognito:** Leaves NO browser artifacts (check RAM, pagefile, network logs)
6. **Extensions Storage:** Some extensions have their own databases with user data
7. **Service Workers:** May cache data outside standard cache locations
8. **Browser Version Matters:** Artifact locations change between major versions
9. **Chromium Variants:** Brave, Opera, Vivaldi use similar structures to Chrome
10. **Mobile Browsers:** Different artifact locations (not covered here)

***
