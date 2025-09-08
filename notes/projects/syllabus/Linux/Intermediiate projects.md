Here is a Bash script to automate Nmap scans with options for stealth scan, aggressive scan, all port scan, and more:
yurraj => (cse) bbsbec
```bash
#!/bin/bash

echo "Let's perform an Nmap scan..."

echo "-----------------------------------------------
Select the type of scan you want to perform:
1. Stealth Scan (SYN Scan)
2. Aggressive Scan
3. All Port Scan
4. Specific Port Scan
5. Service Version Detection
6. Operating System Detection
7. Script Scan
8. Ping Scan
------------------------------------------------"

read -p "Option you selected ==> " option

read -p "Enter the target IP or hostname: " target

case "$option" in
    1)
        echo "Performing Stealth Scan (SYN Scan)..."
        nmap -sS "$target"
        ;;
    2)
        echo "Performing Aggressive Scan..."
        nmap -A "$target"
        ;;
    3)
        echo "Performing All Port Scan..."
        nmap -p- "$target"
        ;;
    4)
        read -p "Enter the specific port(s) to scan (comma-separated for multiple ports): " ports
        echo "Performing Specific Port Scan on ports: $ports..."
        nmap -p "$ports" "$target"
        ;;
    5)
        echo "Performing Service Version Detection..."
        nmap -sV "$target"
        ;;
    6)
        echo "Performing Operating System Detection..."
        nmap -O "$target"
        ;;
    7)
        echo "Performing Script Scan..."
        nmap -sC "$target"
        ;;
    8)
        echo "Performing Ping Scan..."
        nmap -sn "$target"
        ;;
    *)
        echo "Invalid option selected."
        ;;
esac
```

### Explanation

1. **Prompt for Scan Type**: The script prompts the user to select the type of Nmap scan they want to perform.
2. **Prompt for Target**: The script asks for the target IP or hostname to scan.
3. **Case Statement**: Based on the user's selection, the script executes the corresponding Nmap command.
    - **Stealth Scan (SYN Scan)**: `nmap -sS`
    - **Aggressive Scan**: `nmap -A`
    - **All Port Scan**: `nmap -p-`
    - **Specific Port Scan**: `nmap -p`
    - **Service Version Detection**: `nmap -sV`
    - **Operating System Detection**: `nmap -O`
    - **Script Scan**: `nmap -sC`
    - **Ping Scan**: `nmap -sn`

You can save this script to a file, make it executable, and run it to perform various Nmap scans interactively. Make sure you have Nmap installed on your system.

Here are separate Bash scripts to automate Gobuster, Hashcat, John the Ripper, Naabu, Rustscan, FFUF, Hydra, and Medusa with different options for each tool.

### Gobuster Automation
jaskaran => (cse)
```bash
#!/bin/bash

#!/bin/bash

echo "Let's perform a Gobuster scan..."

echo "-----------------------------------------------
Select the type of scan you want to perform:
1. Directory Scan
2. DNS Subdomain Scan
3. Virtual Host Scan
4. Fuzzing Mode
5. GCS Bucket Enumeration
6. AWS S3 Bucket Enumeration
7. TFTP Enumeration
8. Show Version
------------------------------------------------"

read -p "Option you selected ==> " option

read -p "Enter the target URL or IP: " target
read -p "Enter the wordlist path: " wordlist

case "$option" in
    1)
        echo "Performing Directory Scan..."
        gobuster dir -u "$target" -w "$wordlist"
        ;;
    2)
        echo "Performing DNS Subdomain Scan..."
        gobuster dns -d "$target" -w "$wordlist"
        ;;
    3)
        echo "Performing Virtual Host Scan..."
        gobuster vhost -u "$target" -w "$wordlist"
        ;;
    4)
        read -p "Enter the FUZZ keyword URL: " fuzz_url
        echo "Performing Fuzzing Mode..."
        gobuster fuzz -u "$fuzz_url" -w "$wordlist"
        ;;
    5)
        echo "Performing GCS Bucket Enumeration..."
        gobuster gcs -u "$target" -w "$wordlist"
        ;;
    6)
        echo "Performing AWS S3 Bucket Enumeration..."
        gobuster s3 -u "$target" -w "$wordlist"
        ;;
    7)
        echo "Performing TFTP Enumeration..."
        gobuster tftp -u "$target" -w "$wordlist"
        ;;
    8)
        echo "Showing Gobuster Version..."
        gobuster version
        ;;
    *)
        echo "Invalid option selected."
        ;;
esac

```

### Hashcat Automation
RMit Sachin(cse)
```bash
#!/bin/bash

echo "Let's perform a Hashcat cracking..."

echo "-----------------------------------------------
Select the type of hash you want to crack:
1. MD5
2. SHA1
3. SHA256
4. NTLM
5. WPA/WPA2
------------------------------------------------"

read -p "Option you selected ==> " option

read -p "Enter the hash file path: " hash_file
read -p "Enter the wordlist path: " wordlist

case "$option" in
    1)
        echo "Cracking MD5 hashes..."
        hashcat -m 0 "$hash_file" "$wordlist"
        ;;
    2)
        echo "Cracking SHA1 hashes..."
        hashcat -m 100 "$hash_file" "$wordlist"
        ;;
    3)
        echo "Cracking SHA256 hashes..."
        hashcat -m 1400 "$hash_file" "$wordlist"
        ;;
    4)
        echo "Cracking NTLM hashes..."
        hashcat -m 1000 "$hash_file" "$wordlist"
        ;;
    5)
        echo "Cracking WPA/WPA2 handshakes..."
        hashcat -m 2500 "$hash_file" "$wordlist"
        ;;
    *)
        echo "Invalid option selected."
        ;;
esac
```

### John the Ripper Automation
vivek => (cse) sha256 sha512
 ```bash
#!/bin/bash

echo "Let's perform a John the Ripper cracking..."

echo "-----------------------------------------------
Select the type of hash you want to crack:
1. MD5
2. SHA1
3. NTLM
------------------------------------------------"

read -p "Option you selected ==> " option

read -p "Enter the hash file path: " hash_file

case "$option" in
    1)
        echo "Cracking MD5 hashes..."
        john --format=raw-md5 "$hash_file"
        ;;
    2)
        echo "Cracking SHA1 hashes..."
        john --format=raw-sha1 "$hash_file"
        ;;
    3)
        echo "Cracking NTLM hashes..."
        john --format=nt "$hash_file"
        ;;
    *)
        echo "Invalid option selected."
        ;;
esac

john --show "$hash_file"
```

### Naabu Automation
Aman => (it)
```bash
#!/bin/bash

echo "Let's perform a Naabu scan..."

echo "-----------------------------------------------
Select the type of scan you want to perform:
1. Default Scan
2. Scan specific ports
3. Scan all ports
------------------------------------------------"

read -p "Option you selected ==> " option

read -p "Enter the target IP or range: " target

case "$option" in
    1)
        echo "Performing Default Scan..."
        naabu -host "$target"
        ;;
    2)
        read -p "Enter the specific port(s) to scan (comma-separated for multiple ports): " ports
        echo "Performing Specific Port Scan on ports: $ports..."
        naabu -host "$target" -p "$ports"
        ;;
    3)
        echo "Performing All Port Scan..."
        naabu -host "$target" -p -1
        ;;
    *)
        echo "Invalid option selected."
        ;;
esac
```

### Rustscan Automation
muskesh => (it)
```bash
#!/bin/bash

echo "Let's perform a Rustscan..."

echo "-----------------------------------------------
Select the type of scan you want to perform:
1. Default Scan
2. Scan specific ports
3. Scan all ports
------------------------------------------------"

read -p "Option you selected ==> " option

read -p "Enter the target IP or range: " target

case "$option" in
    1)
        echo "Performing Default Scan..."
        rustscan -a "$target"
        ;;
    2)
        read -p "Enter the specific port(s) to scan (comma-separated for multiple ports): " ports
        echo "Performing Specific Port Scan on ports: $ports..."
        rustscan -a "$target" -p "$ports"
        ;;
    3)
        echo "Performing All Port Scan..."
        rustscan -a "$target" -p 1-65535
        ;;
    *)
        echo "Invalid option selected."
        ;;
esac
```

### FFUF Automation
kalash=> (it)
```bash
#!/bin/bash

echo "Let's perform a FFUF scan..."

echo "-----------------------------------------------
Select the type of scan you want to perform:
1. Directory Brute Force
2. Virtual Host Brute Force
------------------------------------------------"

read -p "Option you selected ==> " option

read -p "Enter the target URL: " target
read -p "Enter the wordlist path: " wordlist

case "$option" in
    1)
        echo "Performing Directory Brute Force..."
        ffuf -u "$target/FUZZ" -w "$wordlist"
        ;;
    2)
        echo "Performing Virtual Host Brute Force..."
        ffuf -u "http://FUZZ.$target" -w "$wordlist"
        ;;
    *)
        echo "Invalid option selected."
        ;;
esac
```

### Hydra Automation
skashi => (it)
```bash
#!/bin/bash

echo "Let's perform a Hydra brute force attack..."

echo "-----------------------------------------------
Select the type of attack you want to perform:
1. FTP
2. SSH
3. HTTP
4. SMB
------------------------------------------------"

read -p "Option you selected ==> " option

read -p "Enter the target IP or hostname: " target
read -p "Enter the username: " username
read -p "Enter the password list path: " passlist

case "$option" in
    1)
        echo "Performing FTP brute force attack..."
        hydra -l "$username" -P "$passlist" ftp://"$target"
        ;;
    2)
        echo "Performing SSH brute force attack..."
        hydra -l "$username" -P "$passlist" ssh://"$target"
        ;;
    3)
        echo "Performing HTTP brute force attack..."
        read -p "Enter the URL path (e.g., /login): " urlpath
        hydra -l "$username" -P "$passlist" http-form-post "$target$urlpath"
        ;;
    4)
        echo "Performing SMB brute force attack..."
        hydra -l "$username" -P "$passlist" smb://"$target"
        ;;
    *)
        echo "Invalid option selected."
        ;;
esac
```

### Medusa Automation

```bash
#!/bin/bash

echo "Let's perform a Medusa brute force attack..."

echo "-----------------------------------------------
Select the type of attack you want to perform:
1. FTP
2. SSH
3. HTTP
4. SMB
------------------------------------------------"

read -p "Option you selected ==> " option

read -p "Enter the target IP or hostname: " target
read -p "Enter the username: " username
read -p "Enter the password list path: " passlist

case "$option" in
    1)
        echo "Performing FTP brute force attack..."
        medusa -h "$target" -u "$username" -P "$passlist" -M ftp
        ;;
    2)
        echo "Performing SSH brute force attack..."
        medusa -h "$target" -u "$username" -P "$passlist" -M ssh
        ;;
    3)
        echo "Performing HTTP brute force attack..."
        read -p "Enter the URL path (e.g., /login): " urlpath
        medusa -h "$target" -u "$username" -P "$passlist" -M http -m DIR:"$urlpath"
        ;;
    4)
        echo "Performing SMB brute force attack..."
        medusa -h "$target" -u "$username" -P "$passlist" -M smb
        ;;
    *)
        echo "Invalid option selected."
        ;;
esac
```

Each script is designed to automate the usage of a specific tool with common options. Save each script to a file, make them executable, and run them as needed. Ensure the respective tool is installed and properly configured on your system before running the scripts.