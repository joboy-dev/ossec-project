# OSSEC HIDS Installation and Configuration Guide (Ubuntu)

This guide will walk you through the installation and configuration of **OSSEC HIDS** (Host-based Intrusion Detection System) on an Ubuntu machine. It also includes information for copying the setup across multiple servers.

---

## 📦 Prerequisites

Install the required packages:

```bash
sudo apt-get update
sudo apt-get install build-essential make zlib1g-dev libpcre2-dev libevent-dev libssl-dev libsqlite3-dev libsystemd-dev
```

---

## 📥 Downloading OSSEC

1. Visit the OSSEC [GitHub Releases](https://github.com/ossec/ossec-hids/releases) page.
2. Download the latest version of the source code (e.g., `.tar.gz` file).

As of this guide, the latest version is `3.8.0`. Replace `<version>` with the appropriate version number.

```bash
mv ~/Downloads/ossec-hids-<version>.tar.gz ~/
tar xzvf ossec-hids-<version>.tar.gz
cd ossec-hids-<version>
```

---

## 🔧 Installing OSSEC

Make the install script executable and run it:

```bash
chmod +x install.sh
sudo ./install.sh
```

You will be prompted with the following options:

### Step-by-step Prompts

> ❗ Replace inputs where necessary.

1. **Type of installation**:
    ```
    What kind of installation do you want (server, agent, local, hybrid or help)? 
    > server
    ```

2. **Install Location**:
    ```
    Choose where to install OSSEC [/var/ossec]: 
    > (Press ENTER)
    ```

3. **Email Notifications**:
    ```
    Do you want e-mail notification? (y/n) [y]: 
    > y

    What's your e-mail address? 
    > email@gmail.com

    SMTP server found. Use it? (y/n) 
    > n

    What's your SMTP server ip/host?
    > smtp.gmail.com
    ```

4. **Integrity Check Daemon**:
    ```
    Do you want to run the integrity check daemon? (y/n) [y]: 
    > y
    ```

5. **Rootkit Detection Engine**:
    ```
    Do you want to run the rootkit detection engine? (y/n) [y]: 
    > y
    ```

6. **Active Response**:
    ```
    Do you want to enable active response? (y/n) [y]: 
    > y
    ```

7. **Firewall Drop Response**:
    ```
    Do you want to enable the firewall-drop response? (y/n) [y]: 
    > y
    ```

8. **Whitelist IPs**:
    ```
    Do you want to add more IPs to the white list? (y/n)? 
    > n
    ```

9. **Remote Syslog**:
    ```
    Do you want to enable remote syslog (port 514 udp)? (y/n) [y]: 
    > y
    ```

10. **Default Logs to Monitor**:
    - `/var/log/auth.log`
    - `/var/log/syslog`
    - `/var/log/dpkg.log`
    - `/var/log/apache2/error.log`
    - `/var/log/apache2/access.log`

---

## 🔐 Allow Passwordless OSSEC Control

To allow `sudo` usage in your app without a password prompt:

1. Open the `sudoers` file:
   ```bash
   sudo visudo
   ```

2. Add the following line to the bottom, replacing `<yourusername>` with your actual username:
   ```bash
   <yourusername> ALL=(ALL) NOPASSWD: /var/ossec/bin/ossec-control
   ```

---

## 🚀 Useful OSSEC Commands

| Action         | Command                                      |
|----------------|----------------------------------------------|
| Start OSSEC    | `sudo /var/ossec/bin/ossec-control start`    |
| Stop OSSEC     | `sudo /var/ossec/bin/ossec-control stop`     |
| OSSEC Config   | `/var/ossec/etc/ossec.conf`                  |
| Manage Agents  | `sudo /var/ossec/bin/manage_agents`          |

Read more about managing agents: [OSSEC Docs](http://www.ossec.net/docs/docs/programs/manage_agents.html)

---

## 🧑‍💻 Switch to Root (Optional)

If needed:

```bash
sudo -i
```

---

## 🔁 Copying Setup to Another Server

To replicate OSSEC setup on another server:

1. Copy your downloaded `.tar.gz` file.
2. Repeat the installation steps on the new server.
3. Optionally automate installation using shell scripts and agent registration.

---

## 📁 Directory Structure

- Main installation directory: `/var/ossec`
- Configuration: `/var/ossec/etc/ossec.conf`
- Control script: `/var/ossec/bin/ossec-control`

---

## ✅ Final Checklist

- [x] OSSEC installed and configured as a **server**
- [x] Daemons like `ossec-logcollector`, `ossec-maild`, etc., running
- [x] Email & active response setup
- [x] Passwordless sudo for `/var/ossec/bin/ossec-control`
- [x] `ossec.conf` monitoring desired logs
- [x] `manage_agents` ready to connect with remote agents

---

## 🧠 Very Important Tips

- If you plan to integrate OSSEC with the built web frontend, ensure `/var/ossec/bin/ossec-control` and other necessary scripts is accessible via `sudo` without password prompts. To do this, do the following
    1. Run this command
        `sudo visudo`

    2. Paste the following at the bottom of the file and save:
        `<yourusername> ALL=(ALL) NOPASSWD: /var/ossec/bin/ossec-control`
        `<yourusername> ALL=(ALL) NOPASSWD: /opt/ossec-dashboard/scripts/sync_ossec_alerts.sh`

    3. Replace <yourusername> with your computer username. THis is to prevent passwordless login for sudo commands used in the app for ossec services

- Keep your SMTP configuration secure — avoid hardcoding credentials.

---

**Happy Monitoring! 🚨**