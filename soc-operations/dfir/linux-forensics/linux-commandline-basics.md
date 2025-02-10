---
layout:
  title:
    visible: true
  description:
    visible: false
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Linux Commandline Basics

**Knowing the Linux command line** is essential for leveraging the full potential of Linux systems, particularly in technical fields such as cybersecurity, software development, and system administration. The command line offers unmatched control and flexibility, allowing users to perform tasks more efficiently than through graphical interfaces. With the command line, users can quickly manage files, configure systems, automate repetitive tasks using shell scripts, and troubleshoot issues. Its power and precision make it indispensable for professionals managing servers, networks, and cloud environments where remote and headless systems are common.

The benefits of mastering the Linux command line extend beyond efficiency. It enhances problem-solving skills by providing access to powerful tools like `grep`, `awk`, `sed`, and `find` for data processing and analysis. Additionally, understanding command-line basics is critical for security professionals who need to investigate logs, monitor system activity, and respond to threats in realtime. Familiarity with the command line also fosters a deeper understanding of how Linux operates, enabling users to optimise system performance, enhance security, and customise environments to fit specific needs. In a world increasingly reliant on open-source technologies, command-line proficiency is a vital skill that opens doors to innovation and career advancement.

The following is a set of commands that are useful to know as a security professional, as they can be used to triage and help determine the state of a host or environment. The commands are designed to quickly grab the relevant information that will allow the investigator to determine whether the activity warrants deeper analysis or escalation.

**Note**: Depending on the distro of the system being investigated, in certain situations, the commands present may not return the desired information; at that point, you will have to customise the queries to the distro being investigated.

<pre class="language-bash" data-title="Print Working Directory (PWD)" data-overflow="wrap"><code class="lang-bash"><strong>Command: pwd
</strong>Description: Prints the current working directory
Example: pwd #displays the full path of the current directory
echo "You are in $(pwd)" #Combining with Other Commands
</code></pre>

{% code title="List (LS)" overflow="wrap" %}
```bash
Command: ls
Description: Lists directory contents
Example: 
    ls -l #lists files in long format, showing permissions, owner, size, and modification date
    ls -a #lists files, including hidden files (those starting with a dot)
    ls -la #list directory contents in a long format, including hidden files
    ls -l /etc/shadow
```
{% endcode %}

{% code title="Change Directory (CD)" %}
```bash
Command: cd
Description: Changes the current directory.
Example: 
cd /home/user #changes the directory to /home/user
cd /home/user  #Changing to a Specific Directory
cd .. #Moving Up One Directory Level
cd ~ #Moving to the Home Directory
cd - #Changing to the Previous Directory
cd /var/log #Using Absolute and Relative Paths
```
{% endcode %}

{% code title="Touch" %}
```bash
Command: touch
Description: Creates an empty file or updates the timestamp of an existing file
Example: 
touch newfile.txt #creates an empty file named newfile.txt
touch file1.txt file2.txt file3.txt #Creating Multiple Files at Once
touch -t 202501140948.00 newfile.txt #Using touch with a Specific Date and Time
```
{% endcode %}

{% code title="ECHO" overflow="wrap" %}
```bash
Command: echo
Description: Displays a line of text or a variable value
Example: 
    echo "Hello, World!" prints Hello, World! to the terminal
    echo "Hello, World!" > filename.txt #creates a new text file named "filename.txt" (or
    #overwrites it if it already exists) and writes the phrase "Hello, World!" into it
    echo "Hello, World!" >> filename.txt #appends the phrase "Hello, World!" to the end of the existing file named "filename.txt" (or creates the file if it doesn't exist)
```
{% endcode %}

{% code title="Remove (RM)" %}
```bash
Command: rm
Description: Removes files or directories
Example: rm file.txt #deletes file.txt
rm file1.txt file2.txt file3.txt #Removing Multiple Files
rm -r directory_name #Removing a Directory
rm -f file.txt Forcing #Removal
rm -rf directory_name #Combining Options
```
{% endcode %}

<pre class="language-bash" data-title="Copy (CP)" data-overflow="wrap"><code class="lang-bash">Command: cp
Description: Copies files or directories.
Example: 
cp file1.txt file2.txt #copies file1.txt to file2.txt
cp file1.txt ./Desktop #copies the file named "file1.txt" from the current directory to the Desktop folder.
<strong>cp file1.txt /home/user/Documents/ #Copying a File to a Directory
</strong>cp file1.txt file2.txt /home/user/Documents/ #Copying Multiple Files to a Directory
cp -r /home/user/Documents /home/user/Backup/ #Copying a Directory Recursively
</code></pre>

<pre class="language-bash" data-title="Move (MV)" data-overflow="wrap"><code class="lang-bash">Command: mv
Description: used for moving and renaming files and directories
Example: 
mv oldname.txt newname.txt #renames oldname.txt to newname.txt in the current directory.
mv file1.txt ./Desktop moves the file named "file1.txt" #from the current directory to the Desktop folder
mv file.txt /home/user/Documents/ #Moving a File to a Different Directory
<strong>mv oldname.txt /home/user/Documents/newname.txt #Renaming and Moving a File
</strong>mv /home/user/old_directory /home/user/new_directory #Moving a Directory
</code></pre>

{% code title="Concatenate (CAT)" overflow="wrap" %}
```bash
Command: cat
Description: Concatenates and displays file content.
Example: 
cat file.txt #displays the content of file.txt
cat /etc/passwd /etc/passwd #contains all the users available in the system.
cat file1.txt file2.txt #Concatenating Multiple Files
cat file1.txt file2.txt > combined.txt #Redirecting Output to a New File
cat file1.txt >> existingfile.txt #Appending to an Existing File
cat -n file.txt #Displaying Line Numbers
```
{% endcode %}

{% code title="NANO" overflow="wrap" %}
```bash
Command: nano
Description: Changes the current directory.
Example: nano file.txt #opens file.txt in the Nano editor

Saving Changes:
After editing the file, press Ctrl + O to save the changes.
Press Enter to confirm the file name.
Press Ctrl + X to exit the editor.

Exiting Without Saving:
Press Ctrl + X to exit.
If you have unsaved changes, Nano will prompt you to save them. Press N to discard changes and exit.

Cutting and Pasting Text:
To cut a line of text, press Ctrl + K.
To paste the cut text, move the cursor to the desired location and press Ctrl + U.

Searching for Text:
Press Ctrl + W to open the search prompt.
Enter the text you want to search for and press Enter
```
{% endcode %}

{% code title="VIM" %}
```bash
Command: vim
Description: Open the Vim text editor
Example: vim file.txt #opens file.txt in the Vim editor

Basic Navigation:
Press i to enter insert mode and start editing the text.
Press Esc to return to normal mode.
Use :w to save the file.
Use :q to quit Vim.
Use :wq to save and quit.

Searching for Text:
Press / followed by the text you want to search for and press Enter.
Use n to move to the next occurrence and N to move to the previous occurrence.

Copying and Pasting Text:
In normal mode, move the cursor to the beginning of the text you want to copy.
Press v to enter visual mode and select the text.
Press y to yank (copy) the selected text.
Move the cursor to the desired location and press p to paste the text.

Undo and Redo:
Press u to undo the last change.
Press Ctrl + r to redo the undone change.
```
{% endcode %}

<pre class="language-bash" data-title="Shred"><code class="lang-bash"><strong>Command: shred
</strong>Description: Overwrites a file to hide its contents and optionally deletes it
Example: shred -u file.txt #overwrites and deletes file.txt
shred -n 5 filename.txt #Specifying the Number of Overwrites
shred -u filename.txt #Removing the File After Shredding
shred -z filename.txt #Overwriting a File with Zeros
shred -n 5 -z -u filename.txt #Combining Options
</code></pre>

{% code title="Make Directory (MKDIR)" %}
```bash
Command: rmdir
Description: Creates a new directory
Example: mkdir new_dir #creates a directory named new_dir
mkdir dir1 dir2 dir3 #Creating Multiple Directories
mkdir -p parent/child/grandchild #Creating Nested Directories
mkdir -m 755 new_directory #Setting Permissions While Creating a Directory
```
{% endcode %}

{% code title="Remove Directory (RMDIR)" %}
```bash
Command: rmdir
Description: Removes an empty directory
Example: rmdir old_dir #removes the empty directory old_dir
rmdir dir1 dir2 dir3 #Removing Multiple Directories
rmdir -p parent/child/grandchild #Removing Nested Directories
```
{% endcode %}

{% code title="Link (LN)" overflow="wrap" %}
```bash
Command: ln
Description: Creates hard and symbolic links
Example: ln -s target link_name #creates a symbolic link named link_name pointing to target
ln -s source_file target_file #Creating a Symbolic (Soft) Link
ln -s /path/to/directory link_name #Creating a Symbolic Link to a Directory
ln -sf source_file target_file #Overwriting an Existing Link
```
{% endcode %}

{% code title="Clear" overflow="wrap" %}
```bash
Command: clear
Description: Clears the terminal screen
Example: clear #clears the terminal display

Using Ctrl + L:
    Pressing Ctrl + L is a keyboard achieves the same effect as the clear command
```
{% endcode %}

{% code title="Who Am I (WHOAMI)" %}
```bash
Command: whoami
Description: Displays the current logged-in user
Example: whoami #shows the username of the current user
echo "You are logged in as $(whoami)" #Using whoami with Other Commands
```
{% endcode %}

{% code title="User Add (USERADD)" overflow="wrap" %}
```bash
Command: useradd
Description: Adds a new user
Example: sudo useradd #new_user adds a new user named new_user
sudo useradd -m newuser #Creating a New User with a Home Directory
sudo useradd -s /bin/bash newuser #Creating a New User with a Specific Shell
sudo useradd -d /home/newuserdir newuser #Creating a New User with a Specific Home Directory
sudo useradd -u 1001 newuser #Creating a New User with a Specific User ID (UID)
```
{% endcode %}

{% code title="Superuser do (SUDO)" overflow="wrap" %}
```bash
Command: sudo
Description: Executes a command as another user, typically the superuser
Example: sudo apt-get update #runs the apt-get update command with superuser privileges
sudo nano /etc/hosts #Editing a System File
sudo su #Switching to the Root User
sudo -u username command #Running a Command as Another User, for example,
sudo -u john ls /home/john
```
{% endcode %}

{% code title="Add User (ADDUSER)" overflow="wrap" %}
```bash
Command: adduser
Description: Adds a new user with a more interactive interface
Example: sudo adduser new_user #interactively adds a new user named new_user
sudo adduser newuser groupname #Adding a User to a Specific Group
sudo adduser --home /home/newuserdir newuser #Creating a New User with a Specific Home Directory
sudo adduser --shell /bin/bash newuser #Creating a New User with a Specific Shell
```
{% endcode %}

{% code title="Substitute User SU" %}
```bash
Command: su
Description: Switch to another user account
Example: 
su #Switching to the Root User
su - username #Switching to a User and Loading Their Environment
su -s /bin/bash username #Switching to a User with a Specific Shell
su username #Switching to a Specific User
```
{% endcode %}

{% code title="EXIT" %}
```bash
Command: exit
Description: Exits the current shell or session
Example: exit # logs out of the current session
```
{% endcode %}

{% code title="Password (PASSWD)" %}
```bash
Command: passwd
Description: Changes a user password
Example: passwd #prompts to change the current user's password
sudo passwd username #Changing Another User's Password (as root)
sudo passwd -e username #Forcing a User to Change Password at Next Login
sudo passwd -l username #Locking a User Account
sudo passwd -u username #Unlocking a User Account
```
{% endcode %}

{% code title="Advanced Package Tool (APT)" %}
```bash
Command: apt
Description: Manages packages on Debian-based systems
Example: 
    sudo apt install package_name #installs the specified package
    sudo apt remove package_name #removes the specified package
    
    sudo apt update #update the package list
    sudo apt upgrade #upgrade installed packages to their latest versions
    apt dist-upgrade #performs a comprehensive system upgrade
    
    apt search package_name #Searching for a Package
    sudo apt autoremove #Cleaning Up Unused Packages
```
{% endcode %}

{% code title="Secure Shell (SSH)" overflow="wrap" %}
```bash
Command: ssh
Description: Connects to a remote machine via SSH
Example: ssh user@hostname #connects to the remote machine hostname as user
ssh -p port_number username@hostname #Specifying a Port, for example:
ssh -p 2222 user@example.com
ssh -i /path/to/private_key username@hostname #Using a Private Key for Authentication, for example:
ssh -i ~/.ssh/id_rsa user@example.com
ssh username@hostname command #Running a Command on a Remote Server, for example:
ssh user@example.com ls /home/user
```
{% endcode %}

{% code title="FINGER" %}
```bash
Command: finger
Description: Displays information about system users
Example: finger username #shows details about a user
finger #Displaying Information About All Users
finger username@remotehost #Displaying Information About a Remote User
```
{% endcode %}

{% code title="Manual (MAN)" %}
```bash
Command: man
Description: Displays the manual page for a command
Example: man ls ##shows the manual for the ls command
man -k keyword #Searching for a Keyword in Manual Pages, for example:
man -k copy 
man section command #Displaying a Specific Section of a Manual Page, for example:
man 5 passwd
```
{% endcode %}

{% code title="WHATIS" %}
```bash
Command: whatis
Description: Displays a brief description of a command
Example: whatis command #Displaying a Description of a Command, for example:
whatis ls 
whatis command1 command2 #Displaying Descriptions for Multiple Commands, for example:
whatis ls cp mv
```
{% endcode %}

{% code title="Client URL (CURL)" overflow="wrap" %}
```bash
Command: curl
Description: Transfers data from or to a server
Example: curl -O http://example.com/file.txt #downloads file.txt from the specified URL
curl -O http://example.com/file.txt #Downloading a File
curl -o newfile.txt http://example.com/file.txt #Saving a File with a Different Name
curl http://example.com #Fetching the Content of a URL
curl -d "param1=value1&param2=value2" -X POST http://example.com/resource #Sending Data with a POST Request
curl -x http://proxyserver:port http://example.com #Using a Proxy
```
{% endcode %}

{% code title="ZIP Archive (ZIP)" overflow="wrap" %}
```bash
Command: zip
Description: Compresses files into a zip archive
Example: zip archive_name.zip file1.txt file2.txt #Creating a ZIP Archive
zip archive.zip file1 file2 #compresses file1 and file2 into archive.zip
zip archive_name.zip file3.txt #Adding Files to an Existing ZIP Archive
zip -r archive_name.zip directory_name #Compressing a Directory
zip archive_name.zip file1.txt file2.txt -x file2.txt # Excluding Files from a ZIP Archive
```
{% endcode %}

{% code title="UNZIP Archive (UNZIP)" overflow="wrap" %}
```bash
Command: unzip
Description: Extracts files from a zip archive
Example: unzip archive.zip #extracts files from archive.zip
unzip archive_name.zip -d /path/to/directory #Extracting a ZIP Archive to a Specific Directory
unzip -l archive_name.zip #Listing the Contents of a ZIP Archive
unzip archive_name.zip file1.txt file2.txt #Extracting Specific Files from a ZIP Archive
unzip -o archive_name.zip #Overwriting Existing Files Without Prompting
```
{% endcode %}

{% code title="LESS" %}
```bash
Command: less
Description: Views file content one screen at a time
Example: less file.txt #displays file.txt content one screen at a time

Navigating in less:
Press Space to move forward one screen.
Press b to move backward one screen.
Press q to quit the less viewer.

Searching for Text:
Press / followed by the text you want to search for and press Enter.
Use n to move to the next occurrence and N to move to the previous occurrence.
```
{% endcode %}

{% code title="HEAD" %}
```bash
Command: head
Description: Displays the first part of a file
Example: head filename.txt #Displaying the First 10 Lines of a File
head -n 5 filename.txt #Specifying the Number of Lines to Display
head -c 20 filename.txt #Displaying the First Few Bytes of a File
```
{% endcode %}

{% code title="TAIL" %}
```bash
Command: tail
Description: Displays the last part of a file
Example: tail filename.txt #Displaying the Last 10 Lines of a File
tail -n 5 filename.txt #Specifying the Number of Lines to Display
tail -c 20 filename.txt #Displaying the Last Few Bytes of a File
tail -f filename.txt #Monitoring a File in Real-Time
```
{% endcode %}

{% code title="Compare (CMP)" overflow="wrap" %}
```bash
Command: cmp
Description: Compare two files byte by byte
Example: cmp file1 file2 #compares file1 and file2
cmp -l file1.txt file2.txt #Comparing Files and Displaying All Differences
cmp -b file1.txt file2.txt #Comparing Files and Displaying Differences in a Human-Readable Format
cmp -i file1.txt file2.txt #Comparing Files and Ignoring Differences in White Space
```
{% endcode %}

{% code title="DIFF" %}
```bash
Command: diff
Description: Compares files line by line
Example: diff file1 file2 #shows the differences between file1 and file2
diff -y file1.txt file2.txt #Displaying Differences Side by Side
diff -i file1.txt file2.txt #Ignoring Case Differences
diff -w file1.txt file2.txt #Ignoring White Space Differences
diff -u file1.txt file2.txt > patchfile.patch #Creating a Patch File
```
{% endcode %}

{% code title="SORT" %}
```bash
Command: sort 
Description: Sorts lines of text files
Example: sort filename.txt #Sorting a File Alphabetically
sort -r filename.txt #Sorting a File in Reverse Order
sort -n filename.txt #Sorting a File Numerically
sort -k 2 filename.txt #Sorting a File by a Specific Field
sort -u filename.txt #Sorting a File and Removing Duplicates
```
{% endcode %}

{% code title="FIND" overflow="wrap" %}
```bash
Command: find
Description: Searches for files in a directory hierarchy
Example: find /home -name "*.txt" #finds all .txt files in the /home directory
find /path/to/search -name "filename" #Finding Files by Name
find /path/to/search -type f #Finding Files by Type
find /path/to/search -size +100M #Finding Files by Size
find /path/to/search -mtime -7 #Finding Files by Modification Time
find /path/to/search -name "filename" -exec rm {} \; #Executing a Command on Found Files
```
{% endcode %}

{% code title="CHMOD" %}
```bash
Command: chmod
Description: Changes file permissions
Example: chmod 755 script.sh #sets the permissions of script.sh to rwxr-xr-x
chmod u+rwx,g+rx,o+r filename.txt #Changing Permissions Using Symbolic Mode
chmod 755 filename.txt #Changing Permissions Using Numeric Mode
chmod -R 755 directory_name #Changing Permissions Recursively
chmod go-w filename.txt #Removing Write Permission for Group and Others
```
{% endcode %}

{% code title="CHOWN" overflow="wrap" %}
```bash
Command: chown
Description: Changes file owner and group
Example: chown user:group file.txt #changes the owner and group of file.txt to user and group
sudo chown newowner filename.txt #Changing the Owner of a File
sudo chown newowner:newgroup filename.txt #Changing the Owner and Group of a File
sudo chown -R newowner directory_name #Changing the Owner of a Directory and Its Contents
sudo chown -h newowner symlink_name #Changing the Owner of a Symbolic Link
```
{% endcode %}

<pre class="language-bash" data-title="IFCONFIG"><code class="lang-bash">Command: ifconfig
Description: Display network interface information. Configures network interfaces
Example: ifconfig eth0 #displays the configuration of the eth0 interface
sudo ifconfig eth0 192.168.1.100 #Assigning an IP Address to an Interface
<strong>sudo ifconfig eth0 up #Enabling a Network Interface
</strong>sudo ifconfig eth0 down #Disabling a Network Interface
</code></pre>

{% code title="IP ADDRESS" overflow="wrap" %}
```bash
Command: ip address
Description: Displays IP addresses and interfaces
Example: ip address #Displaying All Network Interfaces and Their IP Addresses
ip address show dev eth0 #Displaying Information for a Specific Interface
sudo ip address add 192.168.1.100/24 dev eth0 #Adding an IP Address to an Interface
sudo ip address del 192.168.1.100/24 dev eth0 #Removing an IP Address from an Interface
```
{% endcode %}

{% code title="GREP" %}
```bash
Command: grep
Description: Searches for patterns in files
Example: grep "search_string" filename.txt #Searching for a Specific String in a File
grep "search_string" *.txt #Searching for a String in Multiple Files
grep -i "search_string" filename.txt #Performing a Case-Insensitive Search
grep -n "search_string" filename.txt #Displaying Line Numbers with Matches
grep -r "search_string" /path/to/directory #Recursively Searching Directories
```
{% endcode %}

{% code title="AWK" %}
```bash
Command: awk
Description: A programming language for pattern scanning and processing
Example: awk '{print $1}' file.txt #prints the first field of each line in file.txt
awk '{print $1, $3}' filename.txt #Printing Specific Columns
awk -F, '{print $1, $3}' filename.csv #Using a Specific Field Separator
awk '{print $1, $2 * $3}' filename.txt #Performing Arithmetic Operations
awk '$3 > 100' filename.txt #Filtering Lines Based on a Condition
awk '{print tolower($0)}' filename.txt #Using Built-in Functions
```
{% endcode %}

{% code title="RESOLVECTL  STATUS " %}
```bash
Command: resolvectl status
Description: Shows the current DNS settings
Example: resolvectl status #Displaying DNS Status
resolvectl status eth0 #Displaying DNS Status for a Specific Interface
resolvectl dns #Displaying DNS Servers
resolvectl dns eth0 #Displaying DNS Servers for a Specific Interface
```
{% endcode %}

{% code title="PING" %}
```bash
Command: ping
Description: Sends ICMP ECHO_REQUEST packets to network hosts
Example: ping google.com #sends ping requests to google.com
ping hostname #Pinging a Host
ping -c 4 hostname #Specifying the Number of Packets to Send
ping -i 2 hostname #Specifying the Interval Between Packets
sudo ping -f hostname #Flood Pinging a Host
```
{% endcode %}

{% code title="NETSTAT" %}
```bash
Command: netstat
Description: Displays network connections, routing tables, and interface statistics
Example: netstat -tuln #shows listening ports and their status
netstat -a #Displaying All Network Connections
netstat -l #Displaying Listening Ports
netstat -s #Displaying Network Statistics
netstat -r #Displaying Routing Table
netstat -i #Displaying Interface Statistics
```
{% endcode %}

{% code title="SS" %}
```bash
Command: ss
Description: Displays socket statistics
Example: 
    ss -tuln #shows listening sockets.
    ss -l4p #displays all listening IPv4 sockets along with the associated processes
    ss -a #Displaying All Connections
    ss -l #Displaying Listening Sockets
    ss -t #Displaying TCP Connections
    ss -u #Displaying UDP Connections
    ss -s #Displaying Summary Statistics
```
{% endcode %}

{% code title="IPTABLES" overflow="wrap" %}
```bash
Command: iptables
Description: Configures packet filtering rules
Example: sudo iptables -L #lists all current iptables rules
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT #Adding a Rule to Allow Incoming Traffic on a Specific Port
sudo iptables -D INPUT -p tcp --dport 80 -j ACCEPT #Deleting a Rule
sudo iptables-save > /etc/iptables/rules.v4 #Saving the Rules
sudo iptables-restore < /etc/iptables/rules.v4 #Restoring the Rules
```
{% endcode %}

{% code title="UFW" %}
```bash
Command: ufw
Description: Manages firewall with Uncomplicated Firewall
Example: sudo ufw enable #enables the firewall
sudo ufw disable #Disabling the Firewall
sudo ufw allow 22 #Allowing Incoming Traffic on a Specific Port
sudo ufw deny 22 #Denying Incoming Traffic on a Specific Port
sudo ufw status #Checking the Status of the Firewall
```
{% endcode %}

<pre class="language-bash" data-title="UNAME"><code class="lang-bash">Command: uname
Description: Prints system information
Example: uname -a #displays all system information
uname -s #Displaying the Kernel Name
<strong>uname -n #Displaying the Network Node Hostname
</strong>uname -r #Displaying the Kernel Release
uname -v #Displaying the Kernel Version
</code></pre>

{% code title="NEOFETCH" %}
```bash
Command: neofetch
Description: Displays system information with an aesthetic layout
Example: neofetch #shows system information in a visually appealing format
neofetch --config /path/to/config.conf #Customizing the Output
neofetch --ascii_distro none #Disabling ASCII Art
neofetch --ssh user@hostname #Displaying Information for a Remote System
```
{% endcode %}

{% code title="CAL" %}
```bash
Command: cal
Description: Displays a calendar
Example: cal #shows the current month's calendar
```
{% endcode %}

{% code title="FREE" %}
```bash
Command: free
Description: Displays memory usage
Example: free -h shows memory usage in a human-readable format
free -b #Displaying Memory Usage in Bytes
free -m #Displaying Memory Usage in Megabytes
free -g #Displaying Memory Usage in Gigabytes
```
{% endcode %}

{% code title="DF" %}
```bash
Command: df 
Description: Displays disk space usage of file systems
Example: df -h #shows disk space usage in a human-readable format
df /path/to/filesystem #Displaying Disk Space Usage for a Specific File System
df -i #Displaying Inodes Usage
```
{% endcode %}

{% code title="PS" overflow="wrap" %}
```bash
Command: ps 
Description: Displays information about active processes
Example: ps aux #shows detailed information about all running processes
ps -e #Displaying All Processes
ps -e --forest #Displaying Processes in a Tree Format
ps -ef #Displaying Processes with Full Format Listing
ps -u username #Displaying Processes for a Specific User
ps -p PID #Displaying Processes with a Specific PID
```
{% endcode %}

{% code title="TOP" overflow="wrap" %}
```bash
Command: top
Description: Displays real-time system resource usage
Example: top #shows real-time processes and system resource usage
top -o %MEM #Sorting Processes by Memory Usage
top -u username #Displaying a Specific User's Processes
top -d 5 #Changing the Refresh Interval
```
{% endcode %}

{% code title="HTOP" overflow="wrap" %}
```bash
Command: htop
Description: An interactive process viewer
Example: htop #provides an interactive view of system processes

Navigating the Interface:
Use the arrow keys to navigate through the list of processes
Press F6 to sort processes by different criteria (e.g., CPU, memory)
Press F9 to kill a process.

Filtering Processes:
Press F3 to search for a specific process by name
Press F4 to filter processes by a specific keyword

Customizing the Display:
Press F2 to enter the setup menu, where you can customize the display options, such as changing the color scheme or adding/removing columns
```
{% endcode %}

{% code title="KILL" overflow="wrap" %}
```bash
Command: kill
Description: Terminates a process by PID
Example: kill PID #Terminating a Process by PID
kill -9 PID #Forcing a Process to Terminate
kill -s SIGNAL PID #Sending a Specific Signal to a Process
kill -s SIGSTOP PID #send the SIGSTOP signal to the process, stopping it temporarily
killall process_name #Terminating All Processes with a Specific Name
```
{% endcode %}

{% code title="PKILL" overflow="wrap" %}
```bash
Command: pkill
Description: Terminates processes by name
Example: pkill process_name #Terminating Processes by Name
pkill -9 process_name #Forcing Processes to Terminate
pkill -u username #Terminating Processes by User
pkill -t pts/0 #Terminating Processes by Terminal
```
{% endcode %}

{% code title="SYSTEMCTL" overflow="wrap" %}
```bash
Command: systemctl 
Description: Manages systemd services
Example: systemctl status service_name #Checking the Status of a Service
systemctl status apache2 #systemctl status service_name, for example:
systemctl status apache2
sudo systemctl start service_name #Starting a Service, start the specified service. For example:
sudo systemctl start apache2
Stopping a Service #sudo systemctl stop service_name, for example:
sudo systemctl stop apache2
sudo systemctl restart service_name #Restarting a Service for example:
sudo systemctl restart apache2
sudo systemctl enable service_name #Enabling a Service to Start at Boot, for example:
sudo systemctl enable apache2
sudo systemctl disable service_name #Disabling a Service from Starting at Boot, for example:
sudo systemctl disable apache2
```
{% endcode %}

{% code title="HISTORY" overflow="wrap" %}
```bash
Command: history
Description: Displays the command history
Example: 
```
{% endcode %}

{% code title="REBOOT" overflow="wrap" %}
```bash
Command: reboot
Description: Reboots the system
Example: sudo reboot #restarts the system
!n #Executing a Command from History
history -c #Clearing Command History
history -w #Saving Command History
```
{% endcode %}

{% code title="SHUTDOWN" overflow="wrap" %}
```bash
Command: shutdown
Description: Shuts down or reboots the system
Example: sudo shutdown now #Shutting Down the System Immediately
sudo shutdown +10 #Scheduling a Shutdown
sudo shutdown -r now #Rebooting the System
sudo shutdown -c #Cancelling a Scheduled Shutdown
```
{% endcode %}

{% code title="TRACEROUTE" overflow="wrap" %}
```bash
Command: traceroute
Description: Traces the route packets take to a network host
Example: traceroute hostname #Tracing the Route to a Host. Display the route packets take to reach the specified hostname. For example:
traceroute google.com
traceroute -q 3 hostname #Specifying the Number of Probes per Hop
traceroute -m 20 hostname #Specifying the Maximum Number of Hops
traceroute -i eth0 hostname #Using a Specific Network Interface
```
{% endcode %}

{% code title="DIG" overflow="wrap" %}
```bash
Command: dig 
Description: Queries DNS servers
Example: dig example.com #Querying a Domain
dig example.com A #Querying a Specific Record Type
dig example.com MX #Querying the MX Records
dig example.com NS #Querying the NS Records
dig example.com ANY #Querying All Records
```
{% endcode %}

{% code title="HOST" overflow="wrap" %}
```bash
Command: host
Description: Performs DNS lookups
Example: host example.com #Querying a Domain
host -t A example.com #Querying a Specific Record Type
host -t MX example.com #Querying the MX Records
host -t NS example.com #Querying the NS Records
```
{% endcode %}

{% code title="ARP" overflow="wrap" %}
```bash
Command: arp
Description: Displays and modifies the ARP table
Example: arp -a #Displaying the ARP Cache
sudo arp -s 192.168.1.100 00:11:22:33:44:55 #Adding an Entry to the ARP Cache
sudo arp -d 192.168.1.100 #Deleting an Entry from the ARP Cache
```
{% endcode %}

{% code title="HOSTNAME" overflow="wrap" %}
```bash
Command: hostname 
Description: Displays or sets the system's hostname
Example: hostname #Displaying the Current Hostname
sudo hostname new_hostname #Setting a New Hostname
hostname -f #Displaying the Fully Qualified Domain Name (FQDN)
```
{% endcode %}

{% code title="WHOIS" %}
```bash
Command: whois
Description: Queries the WHOIS database for domain information
Example: whois example.com #Querying a Domain
whois 8.8.8.8 #Querying an IP Address
whois AS15169 #Querying an Autonomous System Number (ASN)
```
{% endcode %}
