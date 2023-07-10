---
title: "Red Hat System Administration I Part 1"

header:
  teaser: /assets/images/linux/RHCSA-Rapid-Track/red-hat.png
  overlay_image: /assets/images/linux/RHCSA-Rapid-Track/red-hat.png
  overlay_filter: 0.5

ribbon: Crimson
description: "Red Hat System Administration I"
categories:
  - Linux
  - Red Hat
  - Tutorials
tags: 
  - Linux
  - Red Hat System Administration I
toc: true
toc_sticky: true
toc_label: "On This Blog"
toc_icon: "biohazard"
classes: wide
last_modified_at: 
---
<span style="color: #909090">Category: Linux - Red Hat System Administration I</span>


# Chapter 1: Get Started with Red Hat Enterprise Linux
<table>
<tbody >
    <tr style="border:2px solid #b3adad;">
        <td style="border:2px solid #b3adad;">&nbsp;Goal</td>
        <td style="border:2px solid #b3adad;">Define open source, Linux, Linux distributions, and Red Hat Enterprise Linux.</td>
    </tr>
    <tr style="border:2px solid #b3adad;">
        <td style="border:2px solid #b3adad;">&nbsp;Objectives</td>
        <td style="border:2px solid #b3adad;">Explain the purpose of open source, Linux, Linux distributions, and Red Hat Enterprise Linux.</td>
    </tr>
</tbody>
</table>

## Section 1.1: What Is Linux?
Linux is in widespread use, worldwide. Internet users interact with Linux applications and web server systems daily, by browsing the World Wide Web and using e-commerce sites to buy and sell products.

---

### Why Linux?
- Open Source
  - Open source software is software with source code that anyone can use, study, modify, and share.
  - Some software has source code that only the person, team, or organization that created it can see, or change, or distribute. This software is called "closed source“
  - Open source does not mean it is somehow not able to be used or provided commercially, Most commonly, vendors such as Red Hat provide commercial help with deploying, supporting, and extending solutions based on open source products.
- Secure
  - When you have Windows installed, you need to download/purchase an Antivirus program to keep your computer safe from hackers and malwares.However, Linux does not require the use of such Anti-Virus programs.
- Perfect For Programmers
  - Linux supports almost all of the major programming languages (Python, C/C++, Java, Perl, Ruby, etc.). Moreover, it offers a vast range of applications useful for programming purposes.
- Variety Of Distributions
  - You will find tons of Linux distribution catered for a different set of needs. So, you can choose to install any of the available Linux distros according to your requirements.
- Free to Use
  - Linux is accessible to the public for free! However, that is not the case with Windows!
- Reliability
  - You will want to re-install Windows after a while when you encounter crashes or slowdowns on your system.
  - If you are using Linux, you will not have to worry about re-installing it just to experience a faster and a smoother system.
  - Linux helps your system run smooth for a longer period (in fact, much longer!).

---

### Linux distributions
<p align="center">
  <img src="/assets/images/linux/RHCSA-Rapid-Track/linux-distro-stickers.png" alt="Linux distributions" style="width:1000px">
</p>

---

### Red Hat Enterprise Linux Ecosystem
Red Hat Enterprise Linux (RHEL) is Red Hat's commercial production-grade Linux distribution. Red Hat develops and integrates open source software into RHEL through a multistage process.

- Red Hat participates in supporting individual open source projects. It contributes code, developer time resources, and support, and often collaborates with developers from other Linux distributions, to improve the general quality of software for everyone.

- Red Hat sponsors and integrates open source projects into the community-driven Fedora distribution. Fedora provides a free working environment to serve as a development lab and proving ground for features to be incorporated into CentOS Stream and RHEL products.

- Red Hat stabilizes the CentOS Stream software to be ready for long-term support and standardization, and integrates it into RHEL, the production-ready distribution.

<p align="center">
  <img src="/assets/images/linux/RHCSA-Rapid-Track/ecosystem.svg" alt="Linux distributions" style="width:1000px">
  <caption>The Red Hat Enterprise Linux ecosystem</caption>
</p>

---

## Section 1.2: Summary

- Open source software has source code that anyone can freely use, study, modify, and share.

- A Linux distribution is an installable operating system that is constructed from a Linux kernel and that supports user programs and libraries.

- Red Hat participates in supporting and contributing code to open source projects; sponsors and integrates project software into community-driven distributions; and stabilizes the software to offer it as supported enterprise-ready products.

- Red Hat Enterprise Linux is the open source, enterprise-ready, commercially supported Linux distribution that Red Hat provides.

- A free Red Hat Developer Subscription is a useful method for obtaining learning resources and information, including developer subscriptions to Red Hat Enterprise Linux and other Red Hat products.


---

# Chapter 2: Access the Command Line
<table>
<tbody >
    <tr style="border:2px solid #b3adad;">
        <td style="border:2px solid #b3adad;">&nbsp;Goal</td>
        <td style="border:2px solid #b3adad;">Log in to a Linux system and run simple commands
from the shell.</td>
    </tr>
    <tr style="border:2px solid #b3adad;">
        <td style="border:2px solid #b3adad;">&nbsp;Objectives</td>
        <td style="border:2px solid #b3adad;">Log in to a Linux system and run simple commands from the shell
        <br>
        Log in to the Linux system with the GNOME desktop environment to run commands from a shell prompt in a terminal program
        <br>
        Save time when running commands from a shell prompt with Bash shortcuts.
        </td>

    </tr>
</tbody>
</table>

## Section 2.1: Access the Command Line

### Introduction to the Bash Shell

A command line is a text-based interface that is used to input instructions to a computer system.
The Linux command line is provided by a program called the shell. Many shell program variants
have been developed over the years. Every user can use a different shell, but the Red Hat
recommends using the default shell for system administration.

The default user shell in Red Hat Enterprise Linux (RHEL) is the GNU Bourne-Again Shell
(bash). The bash shell is an improved version of the original Bourne Shell (sh) on UNIX systems.

The shell displays a string when it is waiting for user input, called the shell prompt. When a regular
user starts a shell, the prompt includes an ending dollar ($) character:

```python
[user@host ~]$
```
A hash (#) character replaces the dollar ($) character when the shell is running as the superuser,
root. This character indicates that it is a superuser shell, which helps to avoid mistakes that can
affect the whole system.

```python
[root@host ~]#
```
Using bash to execute commands can be powerful. The bash shell provides a scripting language
that can support task automation. The shell has capabilities that can enable or simplify operations
that are hard to accomplish at scale with graphical tools.

### Shell Basics
Commands that are entered at the shell prompt have three basic parts:
- Command to run.
- Options to adjust the behavior of the command.
- Arguments, which are typically targets of the command

### Log in to a Remote System

Linux users and administrators often need to get shell access to a remote system by connecting
to it over the network. In a modern computing environment, many headless servers are virtual
machines or are running as public or private cloud instances. These systems are not physical and
do not have real hardware consoles. They might not even provide access to their (simulated)
physical console or serial console.

``` python
[user@host ~]$ ssh remoteuser@remotehost
remoteuser@remotehost's password: password
[remoteuser@remotehost ~]$
```
The ssh command encrypts the connection to secure the communication against eavesdropping
or hijacking of the passwords and content.


`file` command -> scan file content and return the type of the file.
```python
[mohamed@server ~]$ file /etc/passwd
/etc/passwd: ASCII text
[mohamed@server ~]$ file /etc
/etc: directory
[mohamed@server ~]$ file /dev/sr0
/dev/sr0: block special (11/0)
[mohamed@server ~]$
```
`block special`  -> ISO image (Block Device)


`date` command -> return the date and the time.

```python
[mohamed@server ~]$ date
Mon Jul  3 21:32:24 EET 2023
[mohamed@server ~]$ date +%R
21:32
[mohamed@server ~]$ date +%x
07/03/2023
[mohamed@server ~]$
```

`passwd` command -> change the current user password.

```python
[mohamed@server ~]$ passwd
Changing password for user mohamed.
Current password:
```

`cat` command -> view the content of the file
```python
[mohamed@server ~]$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
```

You can also use `cat` command for concatenate the contents from multiple files
```python
[mohamed@server ~]$ cat /etc/passwd /etc/redhat-release
root:x:0:0:root:/root:/bin/bash
CentOS Linux release 8.5.2111
```

redhat-release -> stored the version of OS

You can also use `cat` command for display the contents of multiple files
```python
[mohamed@server ~]$ cat file1 file2
```

`less` command -> display one page of a file at a time and lets you scroll down.

```python
[mohamed@server ~]$ less /etc/passwd
```
Note: press `q` to quit

You can also search for a pattern in `less` command by using `/`

`head` and `tail` commands:
- Display the beginning and end of a file, respectively (10 lines of the file)
- `-n` option allows a different number of lines to be specified

```python
[mohamed@server ~]$ head /etc/passwd
[mohamed@server ~]$ tail /etc/passwd
```
`-n` option

```python
[mohamed@server ~]$ head -n 5 /etc/passwd
[mohamed@server ~]$ tail -n 5 /etc/passwd
```

`history` command -> Display a list of previously executed commands prefixed with a command number.

```python
[mohamed@server ~]$ history
    1  date
    2  date +%R
    3  date +%x
    4  passwd
    5  file
    6  file /etc/passwd
```

`!` is a metacharacter that is used to expand previous commands without having to retype them. 

```python
[mohamed@server ~]$ !3
date +%x
07/03/2023
```
Use `!!` to run the last command in history

```python
[mohamed@server ~]$ !!
date
Mon Jul  3 22:07:37 EET 2023
```

To search in `history` using `Ctrl+r` and click `Enter` to execute the commad.

```python
(reverse-i-search)`cat': cat /etc/passwd /etc/redhat-release
```

### Terminal Shortcuts

- `TAB` -> allow to quickly complete command or file name.

```python
[mohamed@server ~]$ pas
passwd       paste        pasuspender
```
if your command is so long use (`\`) to continue a long command on another line

```python
[mohamed@server ~]$ head -n 3 \
> /usr/share/dict/words \
> /usr/share/dict//linux.words
==> /usr/share/dict/words <==
1080
10-point
10th

==> /usr/share/dict//linux.words <==
1080
10-point
10th
```
#### Other Shortcuts
<p align="center">
  <img src="/assets/images/linux/RHCSA-Rapid-Track/shortcut.png" alt="Terminal Shortcuts" style="width:1000px">
</p>


```python
```

```python
```

```python
```

## Section 2.3: Access the Command Line with the Desktop
## Section 2.4: Guided Exercise: Access the Command Line with the Desktop
## Section 2.5: Execute Commands with the Bash Shell


## Section 2.8: Summary


> Thanks For Reading RH 124 Part 1 Go To [Part 2](/linux/red%20hat/tutorials/Red-Hat-System-Administration-I-P2/ "Part 2 RH124").