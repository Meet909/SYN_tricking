# SYN_tricking

**SYN_tricking** is a simple tool that allows you to deceive scanning tools (such as [nmap](https://nmap.org)) that use **SYN scan**.

A **SYN scan** is a method used in network scanning to discover which ports on a target machine are open — without completing a full connection (also known as a half-open scan).

## 🧠 How It Works

SYN_tricking launches a thread pool where each thread listens on all available network interfaces.  
When it receives a TCP packet with the **SYN** flag set on a **closed port**, it responds with a **SYN/ACK** packet, emulating the behavior of an open port.

This tricks port scanners into falsely identifying closed ports as open.

## ⚙️ Installation and Usage

```bash
meson setup build
meson install -C build
```

Use firewall to prevent the OS kernel's TCP/IP stack from processing certain incoming packets -  TCP SYN packets that we would like to handle manually. We need to drop or filter them before they reach the kernel
```bash
sudo iptables -I INPUT -p tcp --dport 100 -j DROP
sudo ./SYN_tricking 192.168.0.0
```

Use nmap TCP SYN (Stealth) Scan (-sS) to check how nicely we tricked him :)
```bash
sudo nmap -sS 192.168.0.0 -p 100
```
