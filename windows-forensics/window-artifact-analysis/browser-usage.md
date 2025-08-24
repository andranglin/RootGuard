# Browser Usage

### History and Download History

**Description:** History and Download History records websites visited by date and time.&#x20;

**Location:**

Firefox

{% code overflow="wrap" %}
```cs
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<random text>.default\places.sqlite
```
{% endcode %}

Chrome/Edge

```cs
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\History
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\History
```

**Interpretation:**

* Web browser artifacts are stored for each local user account
* Most browsers also record the number of times visited (frequency)
* Look for multiple profiles in Chromium browsers, including “Default”, and “Profile1”, etc.

### Media History

**Description:** Media History tracks media usage (audio and video played) on visited websites (Chromium browsers).&#x20;

**Location:**

Chrome/Edge

```cs
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Media History
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Media History
```

**Interpretation:**

* Three primary tables: playback session, origin, playback
* Includes URLs, last play time, watch time duration, and last video position
* Not clear when other history data is cleared

### Auto-Complete Data

**Description:** Many databases store data that a user has typed into the browser.&#x20;

**Location:**

Firefox

{% code overflow="wrap" %}
```cs
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<randomtext>.default\places.sqlite
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<randomtext>.default\formhistory.sqlite
```
{% endcode %}

Chrome/Edge

```cs
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\History
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\History

- keyword_search_terms – items typed into various search engines
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Web Data
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\ Web Data
```

* Items typed into web forms

```cs
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Shortcuts
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\ Shortcuts
```

* Items typed in the Chrome URL address bar (Omnibox)

{% code overflow="wrap" %}
```cs
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Network Action Predictor
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\ Network Action Predictor 
```
{% endcode %}

* Records what was typed, letter by letter

```cs
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Login Data
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\ Login Data
```

**Interpretation:**

* Stores inputted user credentials&#x20;
* Includes typed-in data, as well as data types
* Connects typed data and knowledge to a user account

### Browser Preferences

**Description:** Configuration data associated with the browser application, including privacy settings and synchronization preferences.&#x20;

**Location:**

Firefox

```cs
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<randomtext>.default\prefs.js
```

Chrome/Edge

```cs
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Preferences
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Preferences
```

**Interpretation:**

* Firefox prefs.js shows the sync status, last sync time, and artifacts selected to sync
* Chrome uses JSON format
* per\_host\_zoom\_levels, media-engagement, and site\_engagement can help to show user interaction
* Contains synchronization status, last sync time and artifacts selected to syn
* Edge preferences include account\_info, clear\_data\_on\_exit, and sync settings

### Cache

**Description:** The cache is where web page components can be stored locally to speed up subsequent visits.&#x20;

**Location:**

Firefox Firefox 31-

```cs
%USERPROFILE%\AppData\Local\Mozilla\Firefox\Profiles\<randomtext>.default\Cache
```

Firefox 32+

```cs
%USERPROFILE%\AppData\Local\Mozilla\Firefox\Profiles\<randomtext>.default\cache2
```

Chrome/Edge

{% code overflow="wrap" %}
```cs
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Cache\ - data_# and f_######
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Cache\ - data_# and f_######
```
{% endcode %}

**Interpretation:**

* It gives the investigator a “snapshot in time” of what a user was looking at online.
* Identifies websites which were visited
* Provides the actual files the user viewed on a given website
* Similar to all browser artifacts, cached files are tied to a specific local user account
* Timestamps show when the site was first saved and last viewed

### Bookmarks

**Description:** Bookmarks include default items and those the user chose to save for future reference.&#x20;

**Location:**

Firefox 3+

{% code overflow="wrap" %}
```cs
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<randomtext>.default\places.sqlite
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<randomtext>.default\bookmarkbackups\bookmarks-<date>.jsonlz4
```
{% endcode %}

Chrome/Edge

```cs
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Bookmarks
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Bookmarks
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Bookmarks.bak
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Bookmarks.msbak
```

**Interpretation:**

* Provides the website of interest and the specific URL that was saved
* Firefox bookmark backup folder can contain multiple backup copies of bookmarks in JSON format.&#x20;
* Chromium Bookmark files are in JSON format.&#x20;

**Note:** not all bookmarks are user-generated; it is possible to bookmark a site and never visit it

### Stored Credentials

**Description:** Browser-based credential storage typically uses Windows DPAPI encryption. If the login account is a Microsoft Cloud account in Windows 10 or 11, DPAPI uses a 44-character randomly generated password in lieu of the account password.&#x20;

**Location:**

Firefox

```cs
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\logins.json
```

Chrome/Edge

```cs
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Login Data
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Login Data
```

**Interpretation:**

* Firefox stores the hostname and URL, creation time, last used time, times used, and time of last password change in JSON format.
* Chromium-based browsers use an SQLite database, including the origin URL, action URL, username, date created, and date last used.
* Credential metadata can be available even if actual credentials are encrypted. Actual credentials are easiest to retrieve on a live system with the user account logged in.

### Browser Downloads

**Description:** Modern browsers include built-in download manager applications capable of keeping a history of every file downloaded by the user. This browser artifact can provide excellent information about websites visited and corresponding items downloaded.&#x20;

**Location:**

Firefox 3-25

{% code overflow="wrap" %}
```cs
%USERPROFILE%\AppData\Roaming\Mozilla\ Firefox\Profiles\<random text>.default\downloads.sqlite
```
{% endcode %}

Firefox 26+

{% code overflow="wrap" %}
```cs
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<randomtext>.default\places.sqlite- moz_annos table
```
{% endcode %}

Chrome/Edge

```cs
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\History
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\History
```

* Downloads and download\_url\_chains tables **Interpretation** Download metadata includes:
* Filename, size, and type
* Source website and referring page
* Download start and end times
* The file system saves the location
* State information, including success and failure

### Extensions

**Description:** Browser functionality can be extended through extensions or browser plugins.&#x20;

**Location:**

Firefox 4-25

{% code overflow="wrap" %}
```cs
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<randomtext>.default\extensions.sqlite
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<randomtext>.default\addons.sqlite
```
{% endcode %}

Firefox 26+

{% code overflow="wrap" %}
```cs
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<randomtext>.default\addons.json
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<randomtext>.default\extensions.json
```
{% endcode %}

Chrome/Edge

{% code overflow="wrap" %}
```cs
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Extensions\<GUID>\<version>
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Extensions\<GUID>\<version>
```
{% endcode %}

**Interpretation:**

* The newer Firefox JSON format stores more information than in older versions
* Extension name, installation source, installation time, last update, and plugin status
* Chrome/Edge extensions each have their folder on the local system, named with a GUID, containing the code and metadata.
* The creation time of the folder indicates the installation time for the extension. Beware that extensions can be synced across devices affecting the interpretation of this timestamp.
* A manifest.json file provides plugin details, including name, URL, permissions, and version.
* The preferences file can also include additional extension data

### Session Restore

**Description:** Automatic crash recovery features are built into the browser.&#x20;

**Location:**

Firefox (older versions)

{% code overflow="wrap" %}
```cs
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<randomtext>.default\sessionstore.js
```
{% endcode %}

Firefox (newer versions)

{% code overflow="wrap" %}
```cs
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<randomtext>.default\sessionstore.jsonlz4
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<randomtext>.default\sessionstore-backups\
```
{% endcode %}

Chrome/Edge (older versions)

```cs
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\
```

* Restore files = Current Session, Current Tabs, Last Session, Last Tabs Chrome/Edge (newer versions)

```cs
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Sessions
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Sessions
```

```cs
- Restore files = Session_<timestamp>, Tabs_<timestamp>
```

**Interpretation:**

* Historical websites viewed in each tab
* Referring websites
* Time session started or ended
* HTML, JavaScript, XML, and form data from the page
* Other artifacts, such as transition type, browser window size and pinned tabs

### Cookies

**Description:** Cookies provide insight into what websites have been visited and what activities might have occurred there.&#x20;

**Location:**

Firefox

{% code overflow="wrap" %}
```cs
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\<randomtext>.default\cookies.sqlite
```
{% endcode %}

Chrome/Edge

```cs
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\<Profile>\Network\Cookies
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\<Profile>\Network\Cookies
```
