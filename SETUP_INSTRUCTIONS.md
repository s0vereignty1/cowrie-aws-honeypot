# AWS Cowrie Honeypot - Complete Setup Instructions

A step-by-step guide to deploy a distributed SSH/Telnet honeypot using AWS EC2 and Raspberry Pi.

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Part 1: AWS EC2 Setup](#part-1-aws-ec2-setup)
3. [Part 2: Raspberry Pi ELK Stack Setup](#part-2-raspberry-pi-elk-stack-setup)
4. [Part 3: Deploy Cowrie Honeypot](#part-3-deploy-cowrie-honeypot)
5. [Part 4: Configure Kibana Dashboard](#part-4-configure-kibana-dashboard)
6. [Part 5: Testing & Verification](#part-5-testing--verification)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required:
- ✅ AWS account with EC2 access (free tier eligible)
- ✅ Raspberry Pi 4B or Equivelent (4GB+ RAM recommended, 64GB storage)
- ✅ Tailscale account (free tier: https://tailscale.com)
- ✅ SSH client (Terminal on Mac/Linux, PuTTY on Windows)
- ✅ Basic Linux command line knowledge

### Recommended:
- Static/Elastic IP for EC2 (optional but helpful)
- External storage for Raspberry Pi (USB drive or NAS)

### Time Estimate:
- **First time**: 3-5 hours
- **Experienced**: 1-2 hours

---

## Part 1: AWS EC2 Setup

### Step 1.1: Launch EC2 Instance

1. Log into **AWS Console** → Navigate to **EC2** → Click **"Launch Instance"**

2. **Configure Instance:**
   
   | Setting | Value |
   |---------|-------|
   | Name | `cowrie-honeypot` |
   | AMI | Ubuntu Server 22.04 LTS (64-bit x86) |
   | Instance Type | t3.micro (1 vCPU, 1GB RAM) - Free tier eligible |

3. **Key Pair:**
   - Create new key pair or select existing
   - **Download and save** your `.pem` file securely
   - On Mac/Linux: 
   
   ```bash
   chmod 400 your-key.pem
   ```

4. **Network Settings - Configure Security Group:**
   
   Click **"Edit"** on Network Settings, then **"Add security group rule"** for each:
   
   **Rule 1 - Admin SSH (Port 2200):**
   ```
   Type: Custom TCP
   Port Range: 2200
   Source: My IP (auto-detects your IP)
   Description: Admin SSH access
   ```
   
   **Rule 2 - Honeypot SSH (Port 22):**
   ```
   Type: SSH
   Port Range: 22
   Source: Anywhere IPv4 (0.0.0.0/0)
   Description: Honeypot SSH (fake)
   ```
   
   **Rule 3 - Honeypot Telnet (Port 23):**
   ```
   Type: Custom TCP
   Port Range: 23
   Source: Anywhere IPv4 (0.0.0.0/0)
   Description: Honeypot Telnet (fake)
   ```
  ![Example AWS Security Group](https://paradoxal.s-ul.eu/PADSTL8W)

   
   ⚠️ **CRITICAL**: You MUST add port 2200 BEFORE running the setup script!

5. **Storage:**
   ```
   Size: 20 GB
   Type: gp3 (General Purpose SSD)
   ```

6. Click **"Launch Instance"**

7. Wait for instance state to show **"Running"** (2-3 minutes)

8. **Note your Public IPv4 address** - you'll need this!

### Step 1.2: Initial Connection

Connect to your instance using SSH:

**Mac/Linux:**
```bash
ssh -i /path/to/your-key.pem ubuntu@YOUR_EC2_PUBLIC_IP
```

**Windows (PuTTY):**
- Convert `.pem` to `.ppk` using PuTTYgen
- Host: `ubuntu@YOUR_EC2_PUBLIC_IP`
- Port: `22`
- Auth: Browse to your `.ppk` file

**First connection will ask:** `Are you sure you want to continue connecting?`
- Type: `yes` and press Enter

You should now see:
```bash
ubuntu@ip-xxx-xxx-xxx-xxx:~$
```

### Step 1.3: Download Setup Files

```bash
# Create project directory
mkdir -p ~/aws-cowrie
cd ~/aws-cowrie

# Download setup script
wget https://raw.githubusercontent.com/s0vereignty1/cowrie-aws-honeypot/main/honeypot_setup.sh
# OR manually create it from aws-setup.sh file provided

# Make executable
chmod +x honeypot_setup.sh
```

### Step 1.4: Run Setup Script

⚠️ **BEFORE running**: Verify port 2200 is in your Security Group!

```bash
# Run the setup script
./aws-setup.sh
```

**The script will:**
1. ✅ Ask for confirmation about Security Group
2. ✅ Update system packages (takes 3-5 minutes)
3. ✅ Move SSH from port 22 → port 2200
4. ✅ Install Docker & Docker Compose v2
5. ✅ Install Tailscale

**Important Notes:**
- Your current SSH session will **NOT** disconnect
- The script will show you the test command for port 2200
- **Test port 2200 in a NEW terminal** before closing current session

### Step 1.5: Test New SSH Port

**Open a NEW terminal/window** and test:

```bash
ssh -p 2200 -i /path/to/your-key.pem ubuntu@YOUR_EC2_PUBLIC_IP
```

✅ **If successful**: You'll connect normally  
❌ **If fails**: Security Group isn't configured - add port 2200 rule

### Step 1.6: Reconnect and Setup Tailscale

```bash
# Logout and login with new port
exit
ssh -p 2200 -i /path/to/your-key.pem ubuntu@YOUR_EC2_PUBLIC_IP

# Initialize Tailscale
sudo tailscale up

# Follow the URL in terminal to authenticate
# Note your Tailscale IP (format: 100.x.x.x)
tailscale ip -4
```

**Save this Tailscale IP** - you'll need it later!

---

## Part 2: Raspberry Pi ELK Stack Setup

### Step 2.1: Prepare Raspberry Pi

```bash
# Update system
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
```

### Step 2.2: Install Tailscale on Pi

```bash
# Install Tailscale
curl -fsSL https://tailscale.com/install.sh | sh

# Connect to Tailscale network
sudo tailscale up

# Get your Pi's Tailscale IP
tailscale ip -4
```

**Save this IP** - your AWS instance will use it!

### Step 2.3: Create ELK Stack

```bash
# Create directory structure
mkdir -p ~/raspberry-pi-elk/{elasticsearch,logstash,kibana}
cd ~/raspberry-pi-elk
```

### Step 2.4: Create docker-compose.yml for ELK

```bash
nano docker-compose.yml
```

**Paste this content:**

```yaml
version: '3.8'

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
```

Save: `Ctrl+O`, `Enter`, `Ctrl+X`

### Step 2.5: Configure Logstash Pipeline

```bash
mkdir -p logstash/pipeline logstash/config
nano logstash/pipeline/cowrie.conf
```

**Paste this content:**

input {
  beats {
    port => 5044
    type => "cowrie"
  }
}

filter {
  if [type] == "cowrie" or [log_type] == "cowrie" {
    # Parse timestamp
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601" ]
        target => "@timestamp"
      }
    }
    
    # GeoIP enrichment
    if [src_ip] {
      geoip {
        source => "src_ip"
        target => "geoip"
        fields => [
          "city_name",
          "country_name",
          "country_code2",
          "country_code3",
          "continent_code",
          "location",
          "region_name",
          "timezone"
        ]
      }
      
      geoip {
        source => "src_ip"
        target => "geoip_asn"
        default_database_type => "ASN"
      }
    }
    
    # Tag successful logins
    if [eventid] == "cowrie.login.success" {
      mutate {
        add_tag => ["authentication", "successful_login", "alert"]
      }
    }
    
    # Tag failed logins
    if [eventid] == "cowrie.login.failed" {
      mutate {
        add_tag => ["authentication", "failed_login"]
      }
    }
    
    # Tag and detect dangerous commands
    if [eventid] == "cowrie.command.input" {
      mutate {
        add_tag => ["command"]
      }
      
      if [input] =~ /wget|curl|chmod|\/bin\/sh|bash|nc|nmap|perl|python/ {
        mutate {
          add_tag => ["dangerous_command", "alert"]
        }
      }
    }
    
    # Tag session events
    if [eventid] == "cowrie.session.connect" {
      mutate {
        add_tag => ["session_start"]
      }
    }
    
    if [eventid] == "cowrie.session.closed" {
      mutate {
        add_tag => ["session_end"]
      }
    }
    
    # Tag malware downloads
    if [eventid] == "cowrie.session.file_download" {
      mutate {
        add_tag => ["malware_download", "file_download", "alert"]
      }
    }
    
    # Set daily index pattern
    mutate {
      add_field => {
        "[@metadata][index]" => "cowrie-%{+YYYY.MM.dd}"
      }
    }
    
    # Clean up unnecessary fields
    mutate {
      remove_field => ["agent", "ecs", "host", "log", "input"]
    }
  }
}

output {
  if [type] == "cowrie" or [log_type] == "cowrie" {
    elasticsearch {
      hosts => ["elasticsearch:9200"]
      index => "%{[@metadata][index]}"
      document_type => "_doc"
    }
  }
}

Save: `Ctrl+O`, `Enter`, `Ctrl+X`

### Step 2.6: Start ELK Stack

```bash
cd ~/raspberry-pi-elk

# Start services
docker compose up -d

# Check status (wait 2-3 minutes for startup)
docker compose ps

# Should show all three services as "Up"
```

### Step 2.7: Verify ELK Stack

**Test Elasticsearch:**
```bash
curl -X GET "localhost:9200/_cluster/health?pretty"
```

Expected output:
```json
{
  "cluster_name" : "docker-cluster",
  "status" : "yellow",
  "number_of_nodes" : 1
}
```
✅ Status should be "yellow" or "green"

**Test Logstash:**
```bash
nc -zv localhost 5044
```

Expected output:
```
Connection to localhost 5044 port [tcp/*] succeeded!
```

**Test Kibana:**
```bash
curl -I localhost:5601
```

Expected output:
```
HTTP/1.1 302 Found
```

**Access Kibana in browser:**
```
http://RASPBERRY_PI_IP:5601
```

You should see the Kibana welcome screen!

---

## Part 3: Deploy Cowrie Honeypot

### Step 3.1: Create Configuration Files

**On your AWS EC2 instance:**

```bash
cd ~/aws-cowrie
```

### Step 3.2: Create docker-compose.yml

```bash
nano docker-compose.yml
```

**Paste this content:**

```yaml
version: '3'

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
```

Save: `Ctrl+O`, `Enter`, `Ctrl+X`

### Step 3.3: Create filebeat.yml

```bash
nano filebeat.yml
```

**Paste this content (REPLACE TAILSCALE_IP!):**

```yaml
filebeat.inputs:
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
```

**⚠️ IMPORTANT:** Replace `100.x.x.x` with your Raspberry Pi's Tailscale IP!

Save: `Ctrl+O`, `Enter`, `Ctrl+X`

### Step 3.4: Deploy Honeypot

```bash
# Start the honeypot
docker compose up -d

# Check status
docker compose ps

# Should show both cowrie and filebeat as "Up"
```

### Step 3.5: Verify Honeypot

**Check Cowrie logs:**
```bash
docker logs cowrie
```

Expected output:
```
2025-11-26T00:00:00+0000 [-] CowrieSSHFactory starting on 2222
2025-11-26T00:00:00+0000 [-] Ready to accept SSH connections
2025-11-26T00:00:00+0000 [-] CowrieTelnetFactory starting on 2223
```

**Check Filebeat logs:**
```bash
docker logs filebeat
```

Expected output:
```
Connection to backoff(async(tcp://100.x.x.x:5044)) established
```

### Step 3.6: Test Connectivity to Pi

```bash
# Test connection from EC2 to Pi (replace with your Pi's Tailscale IP)
nc -zv 100.x.x.x 5044
```

Expected output:
```
Connection to 100.x.x.x 5044 port [tcp/*] succeeded!
```

✅ If this succeeds, logs are flowing from EC2 → Pi!

---

## Part 4: Configure Kibana Dashboard

### Step 4.1: Access Kibana

Open browser and go to:
```
http://RASPBERRY_PI_IP:5601
```

### Step 4.2: Create Index Pattern

1. Click **"Explore on my own"** (or skip welcome screen)
2. Navigate to **☰ Menu → Management → Stack Management**
3. Under **Kibana**, click **"Index Patterns"** (or "Data Views" in newer versions)
4. Click **"Create index pattern"** (or "Create data view")
5. **Index pattern name**: `cowrie-honeypot-*`
6. Click **"Next step"**
7. **Time field**: Select `@timestamp`
8. Click **"Create index pattern"**

### Step 4.3: View Live Data

1. Go to **☰ Menu → Analytics → Discover**
2. Select your `cowrie-honeypot-*` index pattern
3. You should see logs appearing in real-time!

### Step 4.4: Create Visualizations

**Login Attempts Timeline:**
1. Go to **☰ Menu → Analytics → Visualize Library**
2. Click **"Create visualization"**
3. Select **"Line"** or **"Area"** chart
4. **Index pattern**: `cowrie-honeypot-*`
5. **Metrics**: Count
6. **Buckets**: Date Histogram on `@timestamp`
7. Click **"Update"** and **"Save"**

**Top Attacking Countries:**
1. Create new visualization
2. Select **"Pie"** chart
3. **Metrics**: Count
4. **Buckets**: Terms on `geoip.country_name.keyword`
5. **Size**: 10
6. Click **"Update"** and **"Save"**

**Geographic Map:**
1. Create new visualization
2. Select **"Maps"**
3. Click **"Add layer"** → **"Documents"**
4. **Index pattern**: `cowrie-honeypot-*`
5. **Geospatial field**: `geoip.location`
6. Click **"Update"** and **"Save"**

**Most Common Usernames:**
1. Create new visualization
2. Select **"Data table"**
3. **Metrics**: Count
4. **Buckets**: Terms on `username.keyword`
5. **Size**: 20
6. Click **"Update"** and **"Save"**

### Step 4.5: Create Dashboard

1. Go to **☰ Menu → Analytics → Dashboard**
2. Click **"Create dashboard"**
3. Click **"Add from library"**
4. Select all your visualizations
5. Arrange them on the dashboard
6. Click **"Save"**
7. Name it: `Cowrie Honeypot Overview`

### Step 4.6: Set Auto-Refresh

1. In your dashboard, click the calendar icon (top right)
2. Click **"Refresh every"** dropdown
3. Select **"30 seconds"** or **"1 minute"**
4. Dashboard now updates automatically!

---

## Part 5: Testing & Verification

### Step 5.1: Generate Test Traffic

From your local machine (NOT the EC2 instance):

```bash
# Try connecting to the honeypot
ssh root@YOUR_EC2_PUBLIC_IP
```

When prompted for password, type anything:
```
password: admin123
```

Try some commands:
```bash
whoami
ls
cat /etc/passwd
exit
```

### Step 5.2: Verify Logs Captured

**On EC2 (check Cowrie logs):**
```bash
docker logs cowrie | tail -50
```

You should see your connection logged:
```json
{
  "eventid": "cowrie.login.success",
  "username": "root",
  "password": "admin123",
  "src_ip": "YOUR_IP"
}
```

**On Raspberry Pi (check Elasticsearch):**
```bash
curl "localhost:9200/cowrie-honeypot-*/_search?pretty" | head -50
```

You should see JSON data with your test attack:
```json
{
  "_source": {
    "eventid": "cowrie.login.success",
    "username": "root",
    "src_ip": "YOUR_IP",
    "geoip": {
      "country_name": "United States"
    }
  }
}
```

**In Kibana:**
1. Go to **Discover**
2. Search for your IP address in the search bar
3. You should see your connection attempt with all details!

### Step 5.3: Monitor Real Attacks

Within **24 hours**, you'll start seeing real attacks from internet scanners:

**Common attack patterns:**

| Source | Common Usernames | Common Passwords |
|--------|------------------|------------------|
| 🇨🇳 China | `root`, `admin`, `test` | `123456`, `password`, `admin` |
| 🇷🇺 Russia | `ubuntu`, `user`, `guest` | `root`, `password123`, `admin123` |
| 🇧🇷 Brazil | `administrator`, `admin` | `12345678`, `admin`, `password` |

**Automated scanning bots** will try thousands of credentials within hours!

---

## Troubleshooting

### Issue: Can't Connect to EC2 on Port 2200

**Check Security Group:**
```bash
# AWS Console → EC2 → Security Groups → Your group → Inbound rules
# Verify port 2200 is open to your IP
```

**Test from local machine:**
```bash
nc -zv YOUR_EC2_IP 2200
```

**If fails:** Add rule for port 2200 in Security Group

---

### Issue: Filebeat Can't Connect to Logstash

**On EC2, test Tailscale connectivity:**
```bash
nc -zv 100.x.x.x 5044
```

**If fails, check Tailscale status:**
```bash
sudo tailscale status
```

**On Pi, verify Logstash is listening:**
```bash
docker logs logstash | grep 5044
sudo netstat -tlnp | grep 5044
```

Expected output:
```
tcp        0      0 0.0.0.0:5044            0.0.0.0:*               LISTEN      1234/docker-proxy
```

---

### Issue: No Data in Kibana

**Check Elasticsearch indices:**
```bash
curl "localhost:9200/_cat/indices?v"
```

Expected output:
```
health status index                   pri rep docs.count
yellow open   cowrie-honeypot-2025.11.26   1   1       1234
```

**If no indices, check Logstash for errors:**
```bash
docker logs logstash | grep -i error
```

**Check Filebeat for errors:**
```bash
docker logs filebeat | grep -i error
```

---

### Issue: Cowrie Not Capturing Attacks

**Verify Cowrie is listening:**
```bash
docker logs cowrie | grep -i "ready to accept"
```

**Check ports on EC2:**
```bash
sudo netstat -tlnp | grep -E ":(22|23)"
```

Expected output:
```
tcp6       0      0 :::22                   :::*                    LISTEN      1234/docker-proxy
tcp6       0      0 :::23                   :::*                    LISTEN      5678/docker-proxy
```

**Test honeypot from external machine:**
```bash
ssh root@YOUR_EC2_PUBLIC_IP
# Try password: admin123
```

---

### Issue: High Disk Usage on Raspberry Pi

**Check disk space:**
```bash
df -h
```

**Clean old Docker logs:**
```bash
docker system prune -a
```

**Implement log rotation (create `/etc/logrotate.d/cowrie`):**
```bash
sudo nano /etc/logrotate.d/cowrie
```

Add:
```
/var/lib/docker/volumes/*/_data/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
```

---

### Issue: Elasticsearch Yellow Status

This is **normal** for single-node clusters:
- ✅ Primary shards: Allocated
- ⚠️ Replica shards: Unassigned (expected with one node)

**To disable replicas (optional):**
```bash
curl -X PUT "localhost:9200/cowrie-honeypot-*/_settings" -H 'Content-Type: application/json' -d'
{
  "index" : {
    "number_of_replicas" : 0
  }
}'
```

---

## Next Steps

### Security Hardening

**1. Close Port 22 from Internet:**

AWS Console → EC2 → Security Groups → Edit inbound rules:
- Keep port 2200 for admin access (your IP only)
- Keep port 22 for honeypot traffic (0.0.0.0/0)
- Keep port 23 for honeypot traffic (0.0.0.0/0)

**2. Enable CloudWatch Monitoring:**

```bash
# AWS Console → CloudWatch → Create alarms
# Set up alerts for:
# - CPU > 80%
# - Disk > 85%
# - Network anomalies
```

**3. Setup Automated Backups:**

On Raspberry Pi:
```bash
# Create backup script
nano ~/backup-elk.sh
```

Add:
```bash
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/mnt/usb/elk-backups"

# Backup Elasticsearch data
docker exec elasticsearch \
  curl -X PUT "localhost:9200/_snapshot/backup_repo/snapshot_${DATE}?wait_for_completion=true"

echo "Backup completed: snapshot_${DATE}"
```

Make executable and schedule:
```bash
chmod +x ~/backup-elk.sh

# Add to crontab (daily at 2 AM)
crontab -e
# Add line:
0 2 * * * /home/pi/backup-elk.sh >> /var/log/elk-backup.log 2>&1
```

### Advanced Features

**1. Discord Webhooks for real-time alerts:**

Create webhook in Discord, then add to logstash output:
```ruby
output {
  http {
    url => "https://discord.com/api/webhooks/YOUR_WEBHOOK"
    http_method => "post"
    format => "json"
    mapping => {
      "content" => "New honeypot attack from %{src_ip}"
    }
  }
}
```

**2. AbuseIPDB Integration:**

Check IP reputation:
```bash
curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=1.2.3.4" \
  -H "Key: YOUR_API_KEY" \
  -H "Accept: application/json"
```

**3. Automated threat reporting script:**

```bash
nano ~/report-threats.sh
```

```bash
#!/bin/bash
# Report IPs with >50 login attempts to AbuseIPDB

API_KEY="YOUR_ABUSEIPDB_KEY"

curl "localhost:9200/cowrie-honeypot-*/_search" -H 'Content-Type: application/json' -d'
{
  "size": 0,
  "aggs": {
    "top_ips": {
      "terms": {
        "field": "src_ip.keyword",
        "size": 100,
        "min_doc_count": 50
      }
    }
  }
}' | jq -r '.aggregations.top_ips.buckets[].key' | while read ip; do
  echo "Reporting $ip to AbuseIPDB..."
  curl https://api.abuseipdb.com/api/v2/report \
    --data-urlencode "ip=$ip" \
    --data "categories=18,22" \
    --data "comment=SSH brute force detected by honeypot" \
    -H "Key: $API_KEY"
done
```

### Maintenance Schedule

**Daily:**
```bash
# Check Kibana dashboard
# Look for anomalies in attack patterns
# Review unique IPs and geolocations
```

**Weekly:**
```bash
# Check disk space
df -h

# Check for Docker updates
docker compose pull
docker compose up -d

# Export interesting findings
curl "localhost:9200/cowrie-honeypot-*/_search?pretty" > weekly-report.json
```

**Monthly:**
```bash
# Full system updates
sudo apt-get update && sudo apt-get upgrade -y

# Backup Elasticsearch data
~/backup-elk.sh

# Rotate logs
docker system prune -f

# Review and document findings
```

---

## Additional Resources

- **Cowrie Documentation**: https://cowrie.readthedocs.io/
- **Elastic Stack Guide**: https://www.elastic.co/guide/
- **Tailscale Docs**: https://tailscale.com/kb/
- **Docker Compose**: https://docs.docker.com/compose/

---

## Support

For issues specific to this setup:
1. Check logs: `docker logs [container_name]`
2. Review this troubleshooting section
3. Consult official documentation for each component

---

**⚠️ Disclaimer:** This honeypot is for cybersecurity research and educational purposes only. Always comply with applicable laws and regulations. Never deploy on production networks or systems containing real data.

---

**🎉 Congratulations!** You now have a fully operational distributed honeypot system capturing real-world cyber attacks!
