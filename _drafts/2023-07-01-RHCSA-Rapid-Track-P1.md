---
title: "RHCSA Rapid Track Part 1"

header:
  teaser: /assets/images/linux/RHCSA-Rapid-Track/red-hat.png
  overlay_image: /assets/images/linux/RHCSA-Rapid-Track/red-hat.png
  overlay_filter: 0.5

ribbon: Crimson
description: "Learn essential Red Hat Enterprise Linux configuration, administration, and maintenance for Linux system administrators"
categories:
  - Linux
tags: 
  - Linux
  - RHCSA
toc: true
toc_sticky: true
toc_label: "On This Blog"
toc_icon: "biohazard"
last_modified_at: 2023-07-02
classes: wide
---

<span style="color: #909090">Category: Linux</span>



# Edit Files with Vim
The fundamental design principle of Linux is that it supports storage of the information and configuration settings in text-based files. These files follow various structures such as lists of settings, INI-like formats, structured XML or YAML, and others. The advantage of storing files in a text-based structure is that they are edited with any text editor.

Vim is an improved version of the vi editor, which is distributed with Linux and UNIX systems. Vim is a highly configurable and efficient editor that provides split-screen editing, color formatting, and highlighting for editing text.

## Benefits of the Vim Editor
When a system uses a text-only shell prompt, you should know how to use at least one text editor for editing files. You can then edit text-based configuration files from a terminal window or remote logins through the ssh command or the Web Console. You also do not need access to a graphical desktop to edit files on a server, and that server might not need to run a graphical desktop environment.

The key reason to learn Vim is that it is almost always installed by default on a server for editing text-based files. The Portable Operating System Interface or POSIX standard specified the vi editor on Linux, and many other UNIX-like operating systems largely do likewise.

Vim is also used often as the vi implementation on other standard operating systems or distributions. For example, macOS currently includes a lightweight installation of Vim by default. So, Vim skills that are learned for Linux might also prove useful elsewhere.

## Get Started with Vim
You can install the Vim editor in Red Hat Enterprise Linux by using either of two packages. These two packages provide different features and Vim commands for editing text-based files.

With the vim-minimal package, you might install the vi editor with core features. This lightweight installation includes only the core features and the basic vi command. You can open a file for editing by using the vi command:

```python
[user@host ~]$ vi filename
```

Alternatively, you can use the vim-enhanced package to install the Vim editor. This package provides a more comprehensive set of features, an online help system, and a tutorial program. Use the vim command to start Vim in this enhanced mode:

```python
[user@host ~]$ vim filename
```

The core features of the Vim editor are available in both commands.

If `vim-enhanced` is installed, then a shell alias is set so that if regular users run the vi command, then they automatically get the vim command instead. This alias does not apply to the `root` user and to other users with UIDs below 200 (which system services use).

If `vim-enhanced` is installed and a regular user wants to use the `vi` command, then they might have to use the `\vi` command to override the alias temporarily. You can use `\vi --version` and `vim --version` to compare the feature sets of the two commands.

## Vim Operating Modes
The Vim editor offers various modes of operation such as command mode, extended command mode, edit mode, and visual mode. As a Vim user, always verify the current mode, because the effect of keystrokes varies between modes.


<p align="center">
  <img src="/assets/images/linux/RHCSA-Rapid-Track/vim_modes_essential.svg" alt="Vim Modes" style="width:1000px">
</p>


When you first open Vim, it starts in command mode, which is used for navigation, cut and paste, and other text modification. Pressing the required keystroke accesses specific editing functions.

* An `i` keystroke enters insert mode, where all typed text becomes file content. Pressing `Esc` returns to command mode.

* A `v` keystroke enters visual mode, where multiple characters might be selected for text manipulation. Use `Shift+V` for multiline and `Ctrl+V` for block selection. To exit the visual mode, use the `v`, `Shift+V`, or `Ctr +V` keystrokes.

* The *:* keystroke begins `extended command mode` for tasks such as writing the file (to save it) and quitting the Vim editor.

> `NOTE:` If you are unsure which mode Vim is using, then press Esc a few times to get back into command mode. It is safe to press the Esc key in command mode repeatedly.


## The Minimum, Basic Vim Workflow
Vim has efficient, coordinated keystrokes for advanced editing tasks. Although considered beneficial with practice, the capabilities of Vim can overwhelm new users.

Red Hat recommends that you learn the following Vim keys and commands:

* The `u` key undoes the most recent edit.
* The `x` key deletes a single character.
* The `:w` command writes (saves) the file and remains in command mode for more editing.
* The `:wq` command writes (saves) the file and quits Vim.
* The `:q!` command quits Vim, and discards all file changes since the last write.

Learning these commands helps a Vim user to accomplish any editing task.

## Rearrange Existing Text
In Vim, you can yank and put (copy and paste), by using the y and p command characters. Position the cursor on the first character to select, and then enter visual mode. Use the arrow keys to expand the visual selection. When ready, press y to yank the selection into memory. Position the cursor at the new location, and then press p to put the selection at the cursor.

## Visual Mode in Vim
Visual mode is useful to highlight and manipulate text in different lines and columns. You can enter various visual modes in Vim by using the following key combinations.

* Character mode : `v`
* Line mode :  `Shift+v`
* Block mode : `Ctrl+v`

Character mode highlights sentences in a block of text. The word VISUAL appears at the bottom of the screen. Press v to enter visual character mode. Shift+v enters line mode. VISUAL LINE appears at the bottom of the screen.

Visual block mode is perfect for manipulating data files. Press the Ctrl+v keystroke to enter the visual block from the cursor. VISUAL BLOCK appears at the bottom of the screen. Use the arrow keys to highlight the section to change.

>`NOTE:` First, take the time to familiarize yourself with the basic Vim capabilities. Then, expand your Vim vocabulary by learning more Vim keystrokes.
> The exercise for this section uses the vimtutor command. This tutorial, from the vim-enhanced package, is an excellent way to learn the core Vim functions.

## Vim Configuration Files
The `/etc/vimrc` and `~/.vimrc` configuration files alter the behavior of the vim editor for the entire system or for a specific user respectively. Within these configuration files, you can specify behavior such as the default tab spacing, syntax highlighting, color schemes, and more. Modifying the behavior of the vim editor is particularly useful when working with languages such as YAML, which have strict syntax requirements. Consider the following ~/.vimrc file, which sets the default tab stop (denoted by the ts characters) to two spaces while editing YAML files. The file also includes the set number parameter to display line numbers while editing all files.

```python
[user@host ~]$ cat ~/.vimrc
autocmd FileType yaml setlocal ts=2
set number
```

A complete list of `vimrc` configuration options is available in the [references](https://vimhelp.org/options.txt.html#options.txt "VIM").

---

# Configure SSH Key-based Authentication

You can configure your account for passwordless access to SSH servers that enabled key-based authentication, which is based on public key encryption (PKI).

To prepare your account, generate a cryptographically related pair of key files. One key is private and held only by you. The second key is your related public key, which is not secret. The private key acts as your authentication credential, and it must be stored securely. The public key is copied to your account on servers that you will remotely access, and verifies your use of your private key.

When you log in to your account on a remote server, the remote server uses your public key to encrypt a challenge message and send it to your SSH client. Your SSH client must then prove that it can decrypt this message, which demonstrates that you have the associated private key. If this verification succeeds, then your request is trusted, and you are granted access without giving a password.

Passwords can be easily learned or stolen, but securely stored private keys are harder to compromise.

## SSH Keys Generation
Use the `ssh-keygen` command to create a key pair. By default, the `ssh-keygen` command saves your private and public keys in the `~/.ssh/id_rsa` and `~/.ssh/id_rsa.pub` files, but you can specify a different name.

```python
[user@host ~]$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/user/.ssh/id_rsa): Enter
Created directory '/home/user/.ssh'.
Enter passphrase (empty for no passphrase): Enter
Enter same passphrase again: Enter
Your identification has been saved in /home/user/.ssh/id_rsa.
Your public key has been saved in /home/user/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:vxutUNPio3QDCyvkYm1 user@host.lab.example.com
The key's randomart image is:
+---[RSA 2048]----+
|                 |
|   .     .       |
|  o o     o      |
| . = o   o .     |
|  o + = S E .    |
| ..O o + * +     |
|.+% O . + B .    |
|=*oO . . + *     |
|++.     . +.     |
+----[SHA256]-----+
```

You can choose to provide a passphrase to ssh-keygen, which is used to encrypt your private key. Using a passphrase is recommended, so that your private key cannot be used by someone to access it. If you set a passphrase, then you must enter the passphrase each time that you use the private key. The passphrase is used locally to decrypt your private key before use, unlike your password, which must be sent in clear text across the network for use.

You can use the ssh-agent key manager locally, which caches your passphrase on first use in a login session, and then provides the passphrase for all subsequent private key use in the same login session. The ssh-agent command is discussed later in this section.

In the following example, a passphrase-protected private key is created with the public key.

```python
[user@host ~]$ ssh-keygen -f .ssh/key-with-pass
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): your_passphrase
Enter same passphrase again: your_passphrase
Your identification has been saved in .ssh/key-with-pass.
Your public key has been saved in .ssh/key-with-pass.pub.
The key fingerprint is:
SHA256:w3GGB7EyHUry4aOcNPKmhNKS7dl1YsMVLvFZJ77VxAo user@host.lab.example.com
The key's randomart image is:
+---[RSA 2048]----+
|    . + =.o ...  |
|     = B XEo o.  |
|  . o O X =....  |
| = = = B = o.    |
|= + * * S .      |
|.+ = o + .       |
|  + .            |
|                 |
|                 |
+----[SHA256]-----+
```

The ssh-keygen command -f option specifies the files to save the keys in. In the preceding example, the ssh-keygen command saved the key pair in the /home/user/.ssh/key-with-pass and /home/user/.ssh/key-with-pass.pub files.

> WARNING
> During new ssh-keygen command use, if you specify the name of an existing pair of key files, including the default id_rsa pair, you overwrite that existing key pair, which can be restored only if you have a backup for those files. Overwriting a key pair loses the original private key that is required to access accounts that you configured with the corresponding public key on remote servers.

> If you cannot restore your local private key, then you lose access to remote servers until you distribute your new public key to replace the previous public key on each server. Always create backups of your keys, if they are overwritten or lost.

Generated SSH keys are stored by default in the .ssh subdirectory of your home directory. To function correctly, the private key must be readable and writable only by the user that it belongs to (octal permissions 600). The public key is not secure, and anyone on the system might also be able to read it (octal permissions 644).

## Share the Public Key
To configure your remote account for access, copy your public key to the remote system. The ssh-copy-id command copies the public key of the SSH key pair to the remote system. You can specify a specific public key with the ssh-copy-id command, or use the default ~/.ssh/id_rsa.pub file.

```python
[user@host ~]$ ssh-copy-id -i .ssh/key-with-pass.pub user@remotehost
/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: "/home/user/.ssh/id_rsa.pub"
/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already installed
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys
user@remotehost's password: redhat
Number of key(s) added: 1

Now try logging into the machine, with:   "ssh 'user@remotehost'"
and check to make sure that only the key(s) you wanted were added.
```

After you place the public key, test the remote access, with the corresponding private key. If the configuration is correct, you access your account on the remote system without being asked for your account password. If you do not specify a private key file, then the ssh command uses the default ~/.ssh/id_rsa file if it exists.

>IMPORTANT
>If you configured a passphrase to protect your private key, then SSH requests the passphrase on first use. However, if the key authentication succeeds, then you are not asked for your account password.

```python
[user@host ~]$ ssh -i .ssh/key-with-pass user@remotehost
Enter passphrase for key '.ssh/key-with-pass': your_passphrase
...output omitted...
[user@remotehost ~]$
```

## Non-interactive Authentication with the Key Manager
If you encrypt your private key with a passphrase, then you must enter the passphrase each time that you use the private key for authentication. However, you can configure the ssh-agent key manager to cache passphrases. Then, each time you use SSH, the ssh-agent key manager provides the passphrase for you. Using a key manager is convenient and can improve security by providing fewer opportunities for other people to observe your passphrase.

The ssh-agent key manager can be configured to start automatically when you log in. The GNOME graphical desktop environment can automatically start and configure the ssh-agent key manager. If you log in to a text environment, then you must start the ssh-agent program manually for each session. Start the ssh-agent program with the following command:

```python
[user@host ~]$ eval $(ssh-agent)
Agent pid 10155
```
When you manually start the ssh-agent command, it runs additional shell commands to set environment variables that are needed for use with the ssh-add command. You can manually load your private key passphrase to the key manager by using the ssh-add command.

The following example ssh-add commands add the private keys from the default ~/.ssh/id_rsa file and then from a ~/.ssh/key-with-pass file:


```python
[user@host ~]$ ssh-add
Identity added: /home/user/.ssh/id_rsa (user@host.lab.example.com)
[user@host ~]$ ssh-add .ssh/key-with-pass
Enter passphrase for .ssh/key-with-pass: your_passphrase
Identity added: .ssh/key-with-pass (user@host.lab.example.com)
```

The following ssh command uses the default private key file to access your account on a remote SSH server:


```python
[user@host ~]$ ssh user@remotehost
Last login: Mon Mar 14 06:51:36 2022 from host.example.com
[user@remotehost ~]$
```

The following ssh command uses the ~/.ssh/key-with-pass private key to access your account on the remote server. The private key in this example was previously decrypted and added to the ssh-agent key manager; therefore the ssh command does not prompt you for the passphrase to decrypt the private key.

```python
[user@host ~]$ ssh -i .ssh/key-with-pass user@remotehost
Last login: Mon Mar 14 06:58:43 2022 from host.example.com
[user@remotehost ~]$
```
When you log out of a session that used an ssh-agent key manager, all cached passphrases are cleared from memory.

## Basic SSH Connection Troubleshooting
SSH can appear complex when remote access with key pair authentication is not succeeding. The ssh command provides three verbosity levels with the -v, -vv, and -vvv options, which respectively provide increasing debugging information during ssh command use.

The next example demonstrates the information that is provided when using the lowest verbosity option:

```python
[user@host ~]$ ssh -v user@remotehost
OpenSSH_8.7p1, OpenSSL 3.0.1 14 Dec 2021 {1}
debug1: Reading configuration data /etc/ssh/ssh_config {2}
debug1: Reading configuration data /etc/ssh/ssh_config.d/01-training.conf
debug1: /etc/ssh/ssh_config.d/01-training.conf line 1: Applying options for *
debug1: Reading configuration data /etc/ssh/ssh_config.d/50-redhat.conf
...output omitted...
debug1: Connecting to remotehost [192.168.1.10] port 22. {3}
debug1: Connection established.
...output omitted...
debug1: Authenticating to remotehost:22 as 'user' {4}
...output omitted...
debug1: Authentications that can continue: publickey,gssapi-keyex,gssapi-with-mic,password {5}
...output omitted...
debug1: Next authentication method: publickey {6}
debug1: Offering public key: /home/user/.ssh/id_rsa RSA SHA256:hDVJjD7xrUjXGZVRJQixxFV6NF/ssMjS6AuQ1+VqUc4 {7}
debug1: Server accepts key: /home/user/.ssh/id_rsa RSA SHA256:hDVJjD7xrUjXGZVRJQixxFV6NF/ssMjS6AuQ1+VqUc4 {8}
Authenticated to remotehost ([192.168.1.10]:22) using "publickey".
...output omitted...
[user@remotehost ~]$
```

- {1} OpenSSH and OpenSSL versions.
- {2} OpenSSH configuration files.
- {3} Connection to the remote host.
- {4} Trying to authenticate the user on the remote host.
- {5} Authentication methods that the remote host allows.
- {6} Trying to authenticate the user by using the SSH key.
- {7} Using the /home/user/.ssh/id_rsa key file to authenticate.
- {8} The remote hosts accepts the SSH key.

If an attempted authentication method fails, then a remote SSH server falls back to other allowed authentication methods, until all the available methods are tried. The next example demonstrates a remote access with an SSH key that fails, but then the SSH server offers password authentication that succeeds.

```python
[user@host ~]$ ssh -v user@remotehost
...output omitted...
debug1: Next authentication method: publickey
debug1: Offering public key: /home/user/.ssh/id_rsa RSA SHA256:bsB6l5R184zvxNlrcRMmYd32oBkU1LgQj09dUBZ+Z/k
debug1: Authentications that can continue: publickey,gssapi-keyex,gssapi-with-mic,password
...output omitted...
debug1: Next authentication method: password
user@remotehost's password: password
Authenticated to remotehost ([172.25.250.10]:22) using "password".
...output omitted...
[user@remotehost ~]$
```

## SSH Client Configuration
You can create the ~/.ssh/config file to preconfigure SSH connections. Within the configuration file, you can specify connection parameters such as users, keys, and ports for specific hosts. This file eliminates the need to manually specify command parameters each time that you connect to a host. Consider the following ~/.ssh/config file, which preconfigures two host connections with different users and keys:


```python
[user@host ~]$ cat ~/.ssh/config
host servera
     HostName                      servera.example.com
     User                          usera
     IdentityFile                  ~/.ssh/id_rsa_servera

host serverb
     HostName                      serverb.example.com
     User                          userb
     IdentityFile                  ~/.ssh/id_rsa_serverb
```

> REFERENCES
ssh-keygen(1), ssh-copy-id(1), ssh-agent(1), and ssh-add(1) man pages