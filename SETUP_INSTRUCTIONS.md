AWS Cowrie Honeypot - Complete Setup Instructions
A step-by-step guide to deploy a distributed SSH/Telnet honeypot using AWS EC2 and Raspberry Pi.

📋 Table of Contents

Prerequisites
Part 1: AWS EC2 Setup
Part 2: Raspberry Pi ELK Stack Setup
Part 3: Deploy Cowrie Honeypot
Part 4: Configure Kibana Dashboard
Part 5: Testing & Verification
Troubleshooting


Prerequisites
Required:

✅ AWS account with EC2 access (free tier eligible)
✅ Raspberry Pi 4B (4GB+ RAM recommended, 64GB storage)
✅ Tailscale account (free tier: https://tailscale.com)
✅ SSH client (Terminal on Mac/Linux, PuTTY on Windows)
✅ Basic Linux command line knowledge

Recommended:

Static/Elastic IP for EC2 (optional but helpful)
External storage for Raspberry Pi (USB drive or NAS)

Time Estimate:

First time: 3-5 hours
Experienced: 1-2 hours


Part 1: AWS EC2 Setup
Step 1.1: Launch EC2 Instance

Log into AWS Console → Navigate to EC2 → Click "Launch Instance"
Configure Instance:

   Name: cowrie-honeypot
   AMI: Ubuntu Server 22.04 LTS (64-bit x86)
   Instance Type: t3.micro (1 vCPU, 1GB RAM) - Free tier eligible

Key Pair:

Create new key pair or select existing
Download and save your .pem file securely
On Mac/Linux: chmod 400 your-key.pem


Network Settings - Configure Security Group:
Click "Edit" on Network Settings, then "Add security group rule" for each:

   Rule 1 - Admin SSH (Port 2200):
   ├─ Type: Custom TCP
   ├─ Port Range: 2200
   ├─ Source: My IP (auto-detects your IP)
   └─ Description: Admin SSH access
   
   Rule 2 - Honeypot SSH (Port 22):
   ├─ Type: SSH
   ├─ Port Range: 22
   ├─ Source: Anywhere IPv4 (0.0.0.0/0)
   └─ Description: Honeypot SSH (fake)
   
   Rule 3 - Honeypot Telnet (Port 23):
   ├─ Type: Custom TCP
   ├─ Port Range: 23
   ├─ Source: Anywhere IPv4 (0.0.0.0/0)
   └─ Description: Honeypot Telnet (fake)
⚠️ CRITICAL: You MUST add port 2200 BEFORE running the setup script!

Storage:

   Size: 20 GB
   Type: gp3 (General Purpose SSD)

Click "Launch Instance"
Wait for instance state to show "Running" (2-3 minutes)
Note your Public IPv4 address - you'll need this!

Step 1.2: Initial Connection
Connect to your instance using SSH:
Mac/Linux:
bashssh -i /path/to/your-key.pem ubuntu@YOUR_EC2_PUBLIC_IP
Windows (PuTTY):

Convert .pem to .ppk using PuTTYgen
Host: ubuntu@YOUR_EC2_PUBLIC_IP
Port: 22
Auth: Browse to your .ppk file

First connection will ask: Are you sure you want to continue connecting?

Type: yes and press Enter

You should now see:
ubuntu@ip-xxx-xxx-xxx-xxx:~$
Step 1.3: Download Setup Files
bash# Create project directory
mkdir -p ~/aws-cowrie
cd ~/aws-cowrie

# Download setup script
wget https://raw.githubusercontent.com/YOUR_REPO/aws-setup.sh
# OR manually create it from aws-setup.sh file provided

# Make executable
chmod +x aws-setup.sh
Step 1.4: Run Setup Script
⚠️ BEFORE running: Verify port 2200 is in your Security Group!
bash# Run the setup script
./aws-setup.sh
The script will:

✅ Ask for confirmation about Security Group
✅ Update system packages (takes 3-5 minutes)
✅ Move SSH from port 22 → port 2200
✅ Install Docker & Docker Compose v2
✅ Install Tailscale

Important Notes:

Your current SSH session will NOT disconnect
The script will show you the test command for port 2200
Test port 2200 in a NEW terminal before closing current session

Step 1.5: Test New SSH Port
Open a NEW terminal/window and test:
bashssh -p 2200 -i /path/to/your-key.pem ubuntu@YOUR_EC2_PUBLIC_IP
✅ If successful: You'll connect normally
❌ If fails: Security Group isn't configured - add port 2200 rule
Step 1.6: Reconnect and Setup Tailscale
bash# Logout and login with new port
exit
ssh -p 2200 -i /path/to/your-key.pem ubuntu@YOUR_EC2_PUBLIC_IP

# Initialize Tailscale
sudo tailscale up

# Follow the URL in terminal to authenticate
# Note your Tailscale IP (format: 100.x.x.x)
tailscale ip -4
Save this Tailscale IP - you'll need it later!

Part 2: Raspberry Pi ELK Stack Setup
Step 2.1: Prepare Raspberry Pi
bash# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker pi
rm get-docker.sh

# Install Docker Compose v2
DOCKER_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
sudo mkdir -p /usr/local/lib/docker/cli-plugins
sudo curl -SL "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-linux-x86_64" -o /usr/local/lib/docker/cli-plugins/docker-compose
sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# Logout and login again
exit
# Then reconnect
Step 2.2: Install Tailscale on Pi
bash# Install Tailscale
curl -fsSL https://tailscale.com/install.sh | sh

# Connect to Tailscale network
sudo tailscale up

# Get your Pi's Tailscale IP
tailscale ip -4
Save this IP - your AWS instance will use it!
Step 2.3: Create ELK Stack
bash# Create directory structure
mkdir -p ~/raspberry-pi-elk/{elasticsearch,logstash,kibana}
cd ~/raspberry-pi-elk
Step 2.4: Create docker-compose.yml for ELK
bashnano docker-compose.yml
Paste this content:
yamlversion: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.10.0
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
      - xpack.security.enabled=false
      - xpack.security.enrollment.enabled=false
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"
    networks:
      - elk
    restart: unless-stopped

  logstash:
    image: docker.elastic.co/logstash/logstash:8.10.0
    container_name: logstash
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline
      - ./logstash/config:/usr/share/logstash/config
    ports:
      - "5044:5044"
    networks:
      - elk
    depends_on:
      - elasticsearch
    restart: unless-stopped

  kibana:
    image: docker.elastic.co/kibana/kibana:8.10.0
    container_name: kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    networks:
      - elk
    depends_on:
      - elasticsearch
    restart: unless-stopped

networks:
  elk:
    driver: bridge

volumes:
  elasticsearch_data:
Save: Ctrl+O, Enter, Ctrl+X
Step 2.5: Configure Logstash Pipeline
bashmkdir -p logstash/pipeline logstash/config
nano logstash/pipeline/cowrie.conf
Paste this content:
rubyinput {
  beats {
    port => 5044
  }
}

filter {
  # Parse Cowrie JSON logs
  if [log_type] == "cowrie_honeypot" {
    
    # Add GeoIP data for source IPs
    if [src_ip] {
      geoip {
        source => "src_ip"
        target => "geoip"
      }
    }
    
    # Categorize events
    if [eventid] == "cowrie.login.success" {
      mutate {
        add_field => { "event_category" => "authentication_success" }
      }
    }
    
    if [eventid] == "cowrie.login.failed" {
      mutate {
        add_field => { "event_category" => "authentication_failure" }
      }
    }
    
    if [eventid] == "cowrie.command.input" {
      mutate {
        add_field => { "event_category" => "command_execution" }
      }
    }
    
    if [eventid] =~ /download/ {
      mutate {
        add_field => { "event_category" => "malware_download" }
      }
    }
    
    # Add timestamp
    date {
      match => [ "timestamp", "ISO8601" ]
      target => "@timestamp"
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "cowrie-honeypot-%{+YYYY.MM.dd}"
  }
  
  # Uncomment for debugging
  # stdout { codec => rubydebug }
}
Save: Ctrl+O, Enter, Ctrl+X
Step 2.6: Start ELK Stack
bashcd ~/raspberry-pi-elk

# Start services
docker compose up -d

# Check status (wait 2-3 minutes for startup)
docker compose ps

# Should show all three services as "Up"
Step 2.7: Verify ELK Stack
bash# Test Elasticsearch
curl -X GET "localhost:9200/_cluster/health?pretty"
# Should return: "status" : "yellow" or "green"

# Test Logstash
nc -zv localhost 5044
# Should return: Connection to localhost 5044 port [tcp/*] succeeded!

# Test Kibana
curl -I localhost:5601
# Should return: HTTP/1.1 302 Found
Access Kibana in browser:
http://RASPBERRY_PI_IP:5601
You should see the Kibana welcome screen!

Part 3: Deploy Cowrie Honeypot
Step 3.1: Create Configuration Files
On your AWS EC2 instance:
bashcd ~/aws-cowrie
Step 3.2: Create docker-compose.yml
bashnano docker-compose.yml
Paste this content:
yamlversion: '3'

services:
  cowrie:
    image: cowrie/cowrie:latest
    container_name: cowrie
    restart: unless-stopped
    ports:
      - "22:2222"    # SSH honeypot
      - "23:2223"    # Telnet honeypot
    volumes:
      - cowrie_logs:/cowrie/cowrie-git/var/log/cowrie
      - cowrie_downloads:/cowrie/cowrie-git/var/lib/cowrie/downloads
    networks:
      - cowrie_net

  filebeat:
    image: docker.elastic.co/beats/filebeat:8.10.0
    container_name: filebeat
    user: root
    restart: unless-stopped
    volumes:
      - ./filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - cowrie_logs:/var/log/cowrie:ro
    depends_on:
      - cowrie
    networks:
      - cowrie_net

networks:
  cowrie_net:
    driver: bridge

volumes:
  cowrie_logs:
  cowrie_downloads:
Save: Ctrl+O, Enter, Ctrl+X
Step 3.3: Create filebeat.yml
bashnano filebeat.yml
Paste this content (REPLACE TAILSCALE_IP!):
yamlfilebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/cowrie/cowrie.json
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      log_type: cowrie_honeypot
      environment: production

processors:
  - add_host_metadata:
      netinfo.enabled: true
  - add_cloud_metadata: ~
  - add_docker_metadata: ~

output.logstash:
  hosts: ["100.x.x.x:5044"]  # ← REPLACE with your Pi's Tailscale IP!
  compression_level: 3
  
logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
⚠️ IMPORTANT: Replace 100.x.x.x with your Raspberry Pi's Tailscale IP!
Save: Ctrl+O, Enter, Ctrl+X
Step 3.4: Deploy Honeypot
bash# Start the honeypot
docker compose up -d

# Check status
docker compose ps

# Should show both cowrie and filebeat as "Up"
Step 3.5: Verify Honeypot
bash# Check Cowrie logs
docker logs cowrie

# Should see:
# "Ready to accept SSH connections"
# "CowrieSSHFactory starting on 2222"

# Check Filebeat logs
docker logs filebeat

# Should see:
# "Connection to ... established"
Step 3.6: Test Connectivity to Pi
bash# Test connection from EC2 to Pi
nc -zv 100.x.x.x 5044

# Replace 100.x.x.x with your Pi's Tailscale IP
# Should return: Connection succeeded!

Part 4: Configure Kibana Dashboard
Step 4.1: Access Kibana
Open browser and go to:
http://RASPBERRY_PI_IP:5601
Step 4.2: Create Index Pattern

Click "Explore on my own" (or skip welcome screen)
Navigate to ☰ Menu → Management → Stack Management
Under Kibana, click "Index Patterns" (or "Data Views" in newer versions)
Click "Create index pattern" (or "Create data view")
Index pattern name: cowrie-honeypot-*
Click "Next step"
Time field: Select @timestamp
Click "Create index pattern"

Step 4.3: View Live Data

Go to ☰ Menu → Analytics → Discover
Select your cowrie-honeypot-* index pattern
You should see logs appearing in real-time!

Step 4.4: Create Visualizations
Login Attempts Timeline:

Go to ☰ Menu → Analytics → Visualize Library
Click "Create visualization"
Select "Line" or "Area" chart
Index pattern: cowrie-honeypot-*
Metrics: Count
Buckets: Date Histogram on @timestamp
Click "Update" and "Save"

Top Attacking Countries:

Create new visualization
Select "Pie" chart
Metrics: Count
Buckets: Terms on geoip.country_name.keyword
Size: 10
Click "Update" and "Save"

Geographic Map:

Create new visualization
Select "Maps"
Click "Add layer" → "Documents"
Index pattern: cowrie-honeypot-*
Geospatial field: geoip.location
Click "Update" and "Save"

Most Common Usernames:

Create new visualization
Select "Data table"
Metrics: Count
Buckets: Terms on username.keyword
Size: 20
Click "Update" and "Save"

Step 4.5: Create Dashboard

Go to ☰ Menu → Analytics → Dashboard
Click "Create dashboard"
Click "Add from library"
Select all your visualizations
Arrange them on the dashboard
Click "Save"
Name it: Cowrie Honeypot Overview

Step 4.6: Set Auto-Refresh

In your dashboard, click the calendar icon (top right)
Click "Refresh every" dropdown
Select "30 seconds" or "1 minute"
Dashboard now updates automatically!


Part 5: Testing & Verification
Step 5.1: Generate Test Traffic
From your local machine (NOT the EC2 instance):
bash# Try connecting to the honeypot
ssh root@YOUR_EC2_PUBLIC_IP

# When prompted for password, type anything:
password123

# Try some commands:
whoami
ls
cat /etc/passwd
exit
Step 5.2: Verify Logs Captured
On EC2 (check Cowrie logs):
bashdocker logs cowrie | tail -50

# You should see your connection logged
On Raspberry Pi (check Elasticsearch):
bashcurl "localhost:9200/cowrie-honeypot-*/_search?pretty" | head -50

# You should see JSON data with your test attack
In Kibana:

Go to Discover
Search for your IP address
You should see your connection attempt!

Step 5.3: Monitor Real Attacks
Within 24 hours, you'll start seeing real attacks from internet scanners:

Brute force login attempts from China, Russia, Brazil
Common usernames: root, admin, user, test
Common passwords: 123456, password, admin, root
Automated scanning bots trying thousands of credentials


Troubleshooting
Issue: Can't Connect to EC2 on Port 2200
Solution:
bash# Check Security Group has port 2200 open
# AWS Console → EC2 → Security Groups → Your group → Inbound rules

# Test from local machine:
nc -zv YOUR_EC2_IP 2200

# If fails, add rule for port 2200 in Security Group
Issue: Filebeat Can't Connect to Logstash
Solution:
bash# On EC2, test Tailscale connectivity:
nc -zv 100.x.x.x 5044

# If fails, check Tailscale:
sudo tailscale status

# On Pi, verify Logstash listening:
docker logs logstash | grep 5044
sudo netstat -tlnp | grep 5044
Issue: No Data in Kibana
Solution:
bash# Check Elasticsearch indices:
curl "localhost:9200/_cat/indices?v"

# Should see: cowrie-honeypot-YYYY.MM.DD

# If no indices, check Logstash:
docker logs logstash | grep -i error

# Check Filebeat:
docker logs filebeat | grep -i error
Issue: Cowrie Not Capturing Attacks
Solution:
bash# Verify Cowrie is listening:
docker logs cowrie | grep -i "ready to accept"

# On EC2, check ports:
sudo netstat -tlnp | grep -E ":(22|23)"

# Should show docker-proxy listening

# Test honeypot from external IP:
ssh root@YOUR_EC2_PUBLIC_IP
Issue: High Disk Usage on Raspberry Pi
Solution:
bash# Check disk space:
df -h

# Clean old Docker logs:
docker system prune -a

# Implement log rotation:
# Add to /etc/logrotate.d/cowrie:
/var/lib/docker/volumes/*/_data/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
Issue: Elasticsearch Yellow Status
Solution:
This is normal for single-node clusters. Yellow means:

Primary shards: ✅ Allocated
Replica shards: ⚠️ Unassigned (expected with one node)

To disable replicas if desired:
bashcurl -X PUT "localhost:9200/cowrie-honeypot-*/_settings" -H 'Content-Type: application/json' -d'
{
  "index" : {
    "number_of_replicas" : 0
  }
}'

Next Steps
Security Hardening

Close Port 22 from Internet:

AWS Console → EC2 → Security Groups
Edit inbound rules
Remove port 22 rule for honeypot (keep only 2200)
Keep port 22 for honeypot traffic


Enable CloudWatch Monitoring:

AWS Console → CloudWatch
Create alarms for CPU, disk, network


Setup Automated Backups:

bash   # On Raspberry Pi, backup Elasticsearch data:
   docker exec elasticsearch \
     /usr/share/elasticsearch/bin/elasticsearch-snapshot \
     create backup_repo snapshot_1
Advanced Features

Discord Webhooks for real-time alerts
AbuseIPDB Integration for IP reputation checking
Automated threat reporting
Custom Cowrie filesystem for more realistic honeypot
Session recording playback in Kibana

Maintenance Schedule
Daily:

Check Kibana dashboard for anomalies
Review new attack patterns

Weekly:

Review disk space on both systems
Check for Docker updates: docker compose pull
Export interesting findings

Monthly:

Full system updates: sudo apt-get update && upgrade
Backup Elasticsearch data
Review and rotate logs


Additional Resources

Cowrie Documentation: https://cowrie.readthedocs.io/
Elastic Stack Guide: https://www.elastic.co/guide/
Tailscale Docs: https://tailscale.com/kb/
Docker Compose: https://docs.docker.com/compose/


Support
For issues specific to this setup:

Check logs: docker logs [container_name]
Review this troubleshooting section
Consult official documentation for each component


⚠️ Disclaimer: This honeypot is for cybersecurity research and educational purposes only. Always comply with applicable laws and regulations. Never deploy on production networks or systems containing real data.
