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

### User Information

1. **who**&#x20;

It is used to get information about currently logged-in users on to system. If you don't provide any options or arguments, the command displays the following information for each logged-in user.

Login name of the user

User terminal

Date & Time of login

Remote hostname of the user

```bash
$ who
```

2\. **whoami:**&#x20;

It displays the system’s username

```bash
$ whoami
```

**3. id:**&#x20;

It display the user identification(the real and effective user and group IDs) information

{% code overflow="wrap" %}
```bash
$ id
```
{% endcode %}

**4. groups:**&#x20;

This command displays all the groups to which the user belongs.

```bash
$ group
```

**5. finger:**&#x20;

Used to check the information of any currently logged-in users. i.e. It displays user login time, tty (name), idle time, home directory, shell name, etc.

```bash
$ finger
```

This may not be available by default in many linux machines. In this case, you need to install it manually.

```bash
$ sudo apt install finger
```

**6. users:**&#x20;

Displays usernames of all users currently logged on the system.

```bash
$ users
```

**7. grep:**&#x20;

It is a powerful pattern-searching tool to find information about a specific user from the system accounts file: /etc/passwd.

```bash
$ grep -i sj /etc/passwd
```

**8. W Command:**&#x20;

It(W) is a command-line utility that displays information about currently logged-in users and what each user is doing.

```bash
w [OPTIONS] [USER]
```

**9. last or lastb:**&#x20;

**Displays a list of the last logged-in users on the system.** You can pass user names to display their login and hostname details.

```bash
last [options] [username...] [tty...]
```

**10. lastlog:**&#x20;

The `lastlog` command is used to find the details of a recent login of all users or of a given user.

```bash
$ lastlog
```

### File and directory commands

1. **pwd:**&#x20;

The pwd(Present Working Directory) command is used to print the name of the present/current working directory starting from the root.

```bash
$ pwd
```

**2. ls**:&#x20;

The `ls` command is used to list files or directories. It also accepts flags or options that change how files or directories are listed in your terminal.

```bash
 Syntax:
 ls [flags] [directory]

 Example:
 $ ls

 //Listing files & directories with time in a rever order
 $ ls -ltr

 //Home directory
 $ ls ~
```

Below is the list of possible options for `ls` command,

```bash
-a Show all (including hidden)
-R Recursive list
-r Reverse order
-t Sort by last modified
-S Sort by file size
-l Long listing format
-1 One file per line
-m Comma-­sep­arated output
-Q Quoted output
```

**3. mkdir:**&#x20;

The mkdir(make directory) command allows users to create directories or folders.

```bash
$ mkdir ubuntu
$ ls
ubuntu
```

The option '-p' is used to create multiple directories or parent directories simultaneously.

```bash
$ mkdir -p dir1/dir2/dir3
$ cd dir1/dir2/dir3
~/Desktop/Linux/dir1/dir2/dir3$
```

**4. rmdir**:&#x20;

The rmdir(remove directories) is used to remove _empty_ directories. It can be used to delete multiple empty directories as well. Safer to use compared to `rm -r FolderName`. This command can also be forced to delete non-empty directories.

Remove empty directory:

```bash
rmdir FolderName
```

Remove multiple directories:

```bash
rmdir FolderName1 FolderName2 FolderName3
```

Remove non-empty directories:

```bash
rmdir FolderName1 --ignore-fail-on-non-empty
```

Remove the entire directory tree. This command is similar to `rmdir a/b/c a/b a`:

```bash
rmdir -p a/b/c
```

**5. rm**:&#x20;

The rm(remove) command removes objects, such as files, directories, symbolic links, etc., from the file system.

Remove file:&#x20;

The rm command is used to remove or delete a file

```bash
rm file_name
```

Remove file forcefully:&#x20;

The rm command with the —f option removes a file without prompting for confirmation.

```bash
rm -f filename
```

Remove directory:&#x20;

The rm command with the —r option removes the directory and its contents recursively.

```bash
rm -r myDir
```

Remove directory forcefully:&#x20;

The rm command with the -rf option is used to forcefully remove the directory recursively.

```bash
rm -rf myDir
```

**6. touch**:&#x20;

The touch command is used to create, change, and modify timestamps in a file without any content.

**Create a new file:**&#x20;

You can use the **touch** command to create an empty file at a time.

```bash
touch file_name
```

**Create multiple files:**&#x20;

You can create multiple numbers of files at the same time.

```bash
touch file1_name file2_name file3_name
```

**Change access time:**&#x20;

The touch command with `an` option is used to change the access time of a file.

```bash
touch -a file_name
```

**Change modification time:**&#x20;

The touch command with `m` option is used to change the modified time.

```bash
touch -m file_name
```

**Use timestamp of other file:**&#x20;

The touch command with `r` option is used to get the timestamp of another file.

```bash
touch -r file2 file1
```

In the above example, we get the timestamp of file1 for file2.

**Create a file with a Specific time:**&#x20;

**The touch command with the 't' option is used to create a file with the specified time.**

```bash
touch -t 1911010000 file_name
```

**7. cat:**&#x20;

**The cat command is used to create or view the output of a single or multiple files; it can also redirect output in the terminal or to a file.**

```bash
$ cat [OPTION] [FILE]...
```

**Create a file:**&#x20;

Used to create a file with a specific name and content

```bash
cat > file_name1.txt
Hello, How are you?
```

**View file contents:**&#x20;

You can view the contents of a single or more files by mentioning the filenames.

```bash
cat file_name1 file_name2
```

**More & Less options:**&#x20;

If a file has a large number of content that won’t fit in the output terminal, then `more` & `less` Options can be used to view the content.

```bash
cat file_name1.txt | more
cat file_name1.txt | less
```

***

### File permissions

Since Linux is a multi-user operating system, it is necessary to provide security to prevent people from accessing each other’s confidential files. So Linux divides authorization into two levels,

1. **Ownership:** Each file or directory is assigned with three types of owners i.&#x20;
   1. **User:** Owner of the file who created it.&#x20;
   2. **Group:** Group of users with the same access permissions to the file or directory.
   3. **Other:** Applies to all other users on the system.

**2. Permissions:** Each file or directory has the following permissions for the above 3 types of owners.

**Read:** Give you the authority to open and read a file and list its content for a directory.

&#x20;**Write:** This gives you the authority to modify the contents of a file and add, remove, and rename files stored in the directory.

**Execute:** Give you the authority to run the program in Unix/Linux. The permissions are indicated with below characters,

```bash
  r = read permission

  w = write permission

  x = execute permission

  \- = no permission
```

The above authorization levels are represented in a diagram\[![](https://github.com/sudheerj/Linux-cheat-sheet/raw/master/images/permissions.png)

There is a need to restrict your own file/directory access to others.

**Change access:**&#x20;

The `chmod` command is used to change the access mode of a file. This command sets permissions (read, write, execute) on a file/directory for the owner, group and the other group.

```bash
chmod [reference][operator][mode] file...

Example
chmod ugo-rwx test.txt
```

There are 2 ways to use this command,

1. **Absolute mode:**&#x20;

The file permissions will be represented in a three-digit octal number. The possible permissions types are represented in a number format as below.

| Permission Type        | Number | Symbol |
| ---------------------- | ------ | ------ |
| No Permission          | 0      | ---    |
| Execute                | 1      | --x    |
| Write                  | 2      | -w-    |
| Execute + Write        | 3      | -wx    |
| Read                   | 4      | r--    |
| Read + Execute         | 5      | r-x    |
| Read + Write           | 6      | rw-    |
| Read + Write + Execute | 7      | rwx    |

Let's update the permissions in absolute mode with an example as below,

```bash
 chmode 764 test.txt
```

**2. Symbolic mode: In the symbolic mode, you can modify the permissions of a specific owner, unlike absolute mode.** The owners are represented as below,

| Owner | Description |
| ----- | ----------- |
| u     | user/owner  |
| g     | group       |
| o     | other       |
| a     | all         |

and the list of mathematical symbols to modify the file permissions as follows,

| Operator                                                                                                                          | Description            |
| --------------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| +                                                                                                                                 | Adds permission        |
| -                                                                                                                                 | Removes the permission |
| =                                                                                                                                 | Assign the permission  |
| **Changing Ownership and Group:** It is possible to change the the ownership and group of a file/directory using `chown` command. |                        |

```bash
chown user filename
chown user:group filename

Example:
chown John test.txt
chown John:Admin test.txt
```

**Change group-owner only:**&#x20;

Sometimes, you may need to change group-owner only. In this case, chgrp command needs to be used

```bash
chgrp group_name filename

Example:
sudo chgrp Administrator test.txt
```

***

### Networking

1. **Display network information:**&#x20;

`ifconfig` command is used to display all network information(ip address, ports etc)

```bash
ifconfig -ab
```

**2. Test connection to a remote machine:**&#x20;

Send an echo request to test connection of a remote machine.

```bash
ping <ip-address> or hostname

Example:
ping 10.0.0.11
```

**3. Show IP Address:**&#x20;

Display the IP address of a current machine

```bash
hostname -I
(OR)
ip addr show
```

**4. Active ports:** Shows active or listening ports

```bash
netstat -pnltu
```

**5. Find information about a domain:** `w`

`hois` command is used to find out information about a domain, such as the owner of the domain, the owner’s contact information, and the nameservers used by the domain.

```bash
whois [domain]

Example:
whois google.com
```

***

### Installing packages

1. **Install package:**

```bash
yum install package_name
```

**2. Package description:**&#x20;

The info command is used to display brief details about a package.

```bash
yum info package_name
```

**3. Uninstall package:**&#x20;

The remove command is used to remove or uninstall package name.

```bash
yum remove package_name
```

**4. Install package from local file:**&#x20;

**It is also possible to install a package from a local file named package\_name.rpm.**

```bash
rpm -i package_name.rpm
```

**5. Install from source code:**

```bash
tar zxvf sourcecode.tar.gz
cd sourcecode
./configure
make
make install
```

***

### Disk usage

1. **Synopsis:**&#x20;

`du` command is used to check the information of disk usage of files and directories on a machine

```bash
du [OPTION]... [FILE]...
```

**2. Disk usage of a directory:**&#x20;

To find out the disk usage summary of a /home/ directory tree and each of its sub-directories

```bash
du  /home/
```

**3. Disk usage in human-readable format:**&#x20;

To find out the disk usage in human-readable format

```bash
du  -h /home/
```

**4. Total disk usage of a directory:**&#x20;

To find out the total disk usage

```bash
du  -sh /home/
```

**5. Total disk usage of all files and directories:**&#x20;

To find out the total disk usage of files and directories

```bash
du  -ah /home/
```

**6. Total disk usage of all files and directories upto certain depth:**&#x20;

Print the total for a directory only if it is N or fewer levels below the command

```bash
du  -ah --max-depth 2 /home/
```

**7. Total disk usage with excluded files:**&#x20;

**To find out the total disk usage of files and directories, but exclude the files that match the given pattern.**

```bash
du -ah --exclude="*.txt" /home/
```

**8. Help:**&#x20;

This command gives information about `du`

```bash
du  --help
```

***

### System and Hardware information

1. **Print all information**:&#x20;

`uname` is mainly used to print system information.

```bash
$ uname -a
```

**2. Print kernel name**:

```bash
$ uname -s
```

**3. Print kernel release**:

```bash
$ uname -r
```

**4. Print Architecture**:

```bash
$ uname -m
```

**5. Print Operating System**:

```bash
$ uname -o
```

***

### Search Files

1. **Pattern search:**&#x20;

The `grep` command is used to search patterns in files.

```bash
grep pattern files
grep -i // Case sensitive
grep -r // Recursive
grep -v // Inverted search

Example:
grep "^hello" test.txt // Hello John
grep -i "hELLo" text.txt // Hello John
```

**2. Find files and directories:**&#x20;

The `find` command is used to find or search files and directories by file name, folder name, creation date, modification date, owner and permissions, etc and perform subsequent operations on them. i. **Search file with name:**

```bash
find ./directory_name -name file_name

Example:
find ./test -name test.txt // ./test/test.txt
```

**Search file with pattern:**

```bash
find ./directory_name -name file_pattern

Example:
find ./test -name *.txt // ./test/test.txt
```

**Search file with executable action:**

{% code overflow="wrap" %}
```bash
find ./directory_name -name file_name -exec command

Example:
find ./test -name test.txt -exec rm -i {} \; // Search file and delete it after confirmation
```
{% endcode %}

**Search for empty files or directories:**

{% code overflow="wrap" %}
```bash
The find command is used to search all empty folders and files in the entered directory or sub-directories.
```
{% endcode %}

find ./directory\_name -empty Example: find ./test -empty //./test/test1 //./test/test2 //./test/test1.txt

**Search for files with permissions:**&#x20;

The find command is used to find all the files in the mentioned directory or sub-directory with the given permissions

```bash
find ./directory_name -perm permission_code

Example:
find ./test -perm 664
```

**Search text within multiple files:**

```bash
find ./ -type f -name file_pattern -exec grep some_text  {} \;

Example:
find ./ -type f -name "*.txt" -exec grep 'World'  {} \; // Hello World
```

**3. Whereis to locate binary or source files for a command:**&#x20;

The whereis command in Linux is used to locate the binary, source, and manual page files for a command. i.e, It is used to It is used to find executables of a program, its man pages and configuration files.

{% code overflow="wrap" %}
```bash
whereis command_name

Example:
whereis netstat //netstat:  /bin/netstat /usr/share/man/man8/netstat.8.gz(i.e, executable and location of its man page)
```
{% endcode %}

**4. Locate to find files:**&#x20;

The locate command is used to find files by name. This command is faster than the find command because it searches the database for the filename instead of searching your filesystem.

```bash
locate [OPTION] PATTERN

Example:
locate "*.txt" -n 10 // 10 file search results ending with .txt extension
```

***

### SSH

SSH (Secure Shell) is a network protocol that enables secure remote connections between two systems.

1.  **Connect remote machine using an IP address or machine name:**&#x20;

    The remote server can be connected with a local user name using either hostname or IP address

```bash
ssh <host-name> or <ip-address>

Example:
ssh 192.111.66.100
ssh test.remoteserver.com
```

**2. Connect remote machine using username:**&#x20;

It is also possible to specify a user for an SSH connection.

```bash
ssh username@hostname_or_ip-address

Example:
ssh john@192.0.0.22
ssh john@test.remoteserver.com
```

**3. Connect the remote machine using a custom port.**&#x20;

**By default, the SSH server listens for a connection on port 22, but you can also specify a** custom port.

```bash
ssh <host-name> or <ip-address> -p port_number

Example:
ssh test.remoteserver.com -p 3322
```

**4. Generate SSH keys using keygen:**&#x20;

SSH Keygen generates a key pair consisting of public and private keys to improve the security of SSH connections.

```sh
ssh-keygen -t rsa
```

**5. Copying SSH keys to servers:**&#x20;

For SSH authentication, `ssh-copy-id` command will be used to copy the public key(id\_rsa.pub) to the server.

```sh
ssh-copy-id hostname_or_IP
```

**6. Copy a File Remotely over SSH:**&#x20;

The SCP tool is used to securely copy files over the SSH protocol.

{% code overflow="wrap" %}
```sh
scp fileName user@remotehost:destinationPath

Example:
scp test.txt test@10.0.0.64:/home/john/Desktop
```
{% endcode %}

**7. Edit SSH Config File:**

&#x20;SSH server options is customized by editing the settings in `sshd_config` file.

{% code overflow="wrap" %}
```sh
sudo vim /etc/ssh/sshd_config
```
{% endcode %}

**8. Run commands on a remote server:**&#x20;

**SSH commands can be executed on a remote machine using the local machine.**

{% code overflow="wrap" %}
```bash
ssh test.remoteserver.com mkdir NewDirectoryName // Creating directory on remote machine
```
{% endcode %}

**9. Restart SSH service:**&#x20;

You need to restart the service in Linux after making changes to the SSH configuration.

```bash
sudo ssh service restart
(or)
sudo sshd service restart
```
