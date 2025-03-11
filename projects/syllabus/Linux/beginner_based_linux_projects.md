Certainly! Here are sample scripts for each of the mentioned projects. You might need to adjust them based on your specific requirements.

### 1. Automated Backup Script

```bash
#!/bin/bash

# Define backup source and destination
SOURCE_DIR="/path/to/source"
DEST_DIR="/path/to/destination"

# Find and copy files modified in the last 24 hours
find "$SOURCE_DIR" -type f -mtime -1 -exec cp --parents {} "$DEST_DIR" \;

echo "Backup completed successfully."
```

### 2. Git Repository Cleaner

```bash
#!/bin/bash

# Navigate to your git repository
cd /path/to/your/repo

# Fetch all branches
git fetch --all

# Loop through branches and delete if they haven't been used recently
for branch in $(git branch -r | grep -v '\->'); do
    if [[ $(git log -1 --since='1 year ago' -s --pretty=oneline "$branch") == "" ]]; then
        git push origin --delete "${branch#origin/}"
    fi
done

echo "Old branches deleted successfully."
```

### 3. Log Rotation Script

```bash
#!/bin/bash

LOG_FILE="/var/log/example.log"
ROTATED_LOG_FILE="/var/log/example.log.1"

# Rotate logs
mv "$LOG_FILE" "$ROTATED_LOG_FILE"
touch "$LOG_FILE"

# Restart service if needed
# systemctl restart your-service

echo "Log rotation completed successfully."
```

### 4. Automated System Update

```bash
#!/bin/bash

# Update the package list
sudo apt-get update

# Upgrade the system
sudo apt-get -y upgrade

# Send update report via email (requires mailutils)
sudo apt-get -y dist-upgrade | mail -s "System Update Report" your-email@example.com

echo "System update completed successfully."
```

### 5. Disk Space Monitor

```bash
#!/bin/bash

THRESHOLD=80

# Check disk usage
df -H | grep -vE '^Filesystem|tmpfs|cdrom' | awk '{ print $5 " " $1 }' | while read output; do
  usage=$(echo $output | awk '{ print $1}' | sed 's/%//g')
  partition=$(echo $output | awk '{ print $2 }')

  if [ $usage -ge $THRESHOLD ]; then
    echo "Warning: $partition usage is at $usage%" | mail -s "Disk Space Alert" your-email@example.com
  fi
done
```

### 6. Automated User Management

```bash
#!/bin/bash

# Create a new user
USERNAME="newuser"
PASSWORD="password"

useradd -m "$USERNAME"
echo "$USERNAME:$PASSWORD" | chpasswd

# Add user to sudo group
usermod -aG sudo "$USERNAME"

echo "User $USERNAME created and added to sudo group."
```

### 7. File Organization Script

```bash
#!/bin/bash

SOURCE_DIR="/path/to/source"
DEST_DIR="/path/to/destination"

# Organize files by extension
for file in "$SOURCE_DIR"/*; do
  ext="${file##*.}"
  mkdir -p "$DEST_DIR/$ext"
  mv "$file" "$DEST_DIR/$ext"
done

echo "Files organized by extension."
```

### 8. Network Health Check

```bash
#!/bin/bash

REPORT="/tmp/network_health_report.txt"

echo "Network Health Report" > $REPORT
echo "=====================" >> $REPORT

# Ping test
ping -c 4 google.com >> $REPORT

# Check open ports
netstat -tuln >> $REPORT

# Check network interfaces
ifconfig >> $REPORT

# Send report via email
mail -s "Network Health Report" your-email@example.com < $REPORT

echo "Network health check completed."
```

### 9. Process Monitoring and Management

```bash
#!/bin/bash

# Set CPU usage threshold
THRESHOLD=80

# Get the top 10 processes by CPU usage
ps aux --sort=-%cpu | head -n 11 > /tmp/top_processes.txt

# Check if any process exceeds the threshold
awk -v threshold=$THRESHOLD '$3 > threshold {print $0}' /tmp/top_processes.txt | while read -r process; do
  pid=$(echo $process | awk '{print $2}')
  echo "Killing process $pid due to high CPU usage."
  kill -9 $pid
done

echo "Process monitoring and management completed."
```

### 10. Automated Software Deployment

```bash
#!/bin/bash

# Navigate to your application directory
cd /path/to/your/app

# Pull the latest changes from the repository
git pull origin main

# Build the project (adjust this command based on your project's build system)
./build.sh

# Restart the application service
systemctl restart your-app-service

echo "Software deployment completed successfully."
```

These scripts are basic and might need additional error checking and customization to fit specific environments. Let me know if you need further adjustments or more detailed explanations for any of these scripts!