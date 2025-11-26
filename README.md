# SSH/Telnet Honeypot - Threat Intelligence Research Project

>  honeypot deployment on AWS EC2 capturing and analyzing real-world cyberattacks over a 3-week period.

[![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat&logo=docker&logoColor=white)](https://www.docker.com/)
[![AWS](https://img.shields.io/badge/AWS-232F3E?style=flat&logo=amazon-aws&logoColor=white)](https://aws.amazon.com/)
[![ELK Stack](https://img.shields.io/badge/ELK-005571?style=flat&logo=elastic&logoColor=white)](https://www.elastic.co/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)

## 📊 Project Overview

Deployed a Cowrie SSH/Telnet honeypot to capture real attacker behavior, analyze attack patterns, and gather threat intelligence. The system logged all connection attempts, credentials, commands, and malware downloads for analysis.

**Duration:** October 28 - November 17, 2024 (20 days) (Still Ongoing)

### Key Statistics
- 🌍 **415 unique attacker IPs** from 70+ countries
- 🔌 **5,588 total connection attempts**
- 🔐 **724 failed authentication attempts**

## 🏗️ Architecture
```
┌─────────────────┐         ┌──────────────────┐
│   AWS EC2       │         │  Raspberry Pi    │
│                 │         │                  │
│  ┌──────────┐   │         │  ┌────────────┐  │
│  │ Cowrie   │   │ Tailscale│ │Elasticsearch│ │
│  │ Honeypot │◄──┼─────────┼─►│  Logstash  │  │
│  └────┬─────┘   │   VPN   │  │   Kibana   │  │
│       │         │         │  └────────────┘  │
│  ┌────▼─────┐   │         │                  │
│  │ Filebeat │   │         │   Log Analysis   │
│  └──────────┘   │         │   & Visualization│
└─────────────────┘         └──────────────────┘
```

**Components:**
- **Honeypot:** Cowrie (SSH/Telnet emulation)
- **Log Shipping:** Filebeat → Logstash
- **Storage:** Elasticsearch
- **Visualization:** Kibana
- **Network:** Tailscale mesh VPN
- **Containerization:** Docker & Docker Compose

[📖 Detailed Architecture Documentation](docs/architecture.md)

## 🔍 Key Findings

### Top Attack Patterns

**Most Targeted Credentials:**
| Username | Attempts | Target Type |
|----------|----------|-------------|
| admin | 124 | Generic admin accounts |
| root | 112 | Linux root access |
| pi | 14 | Raspberry Pi devices |
| ubnt | 11 | Ubiquiti routers |

**Most Common Passwords:**
| Password | Attempts | Notes |
|----------|----------|-------|
| 123456 | 138 | Weak default |
| root | 45 | Username=password |
| ubnt | 11 | Ubiquiti default |
| raspberry | 7 | Raspberry Pi default |

**Top Attacker:** 
- IP: `61.51.182.90` (China)
- Attempts: 3,572 connections (64% of all traffic)
- Pattern: Automated botnet scanner

### Technologies Used
- **Cloud Platform:** AWS EC2 (Ubuntu 24.04)
- **Honeypot:** Cowrie
- **Containerization:** Docker, Docker Compose
- **Log Pipeline:** Filebeat, Logstash, Elasticsearch, Kibana (ELK Stack)
- **Networking:** Tailscale VPN, iptables
- **Analysis:** Kibana dashboards, Python (optional)

## 📸 Screenshots

### Kibana Dashboard
![Kibana Dashboard](https://paradoxal.s-ul.eu/4ZoUgCC4)

### Attack Geolocation Map
![Attack Map](https://paradoxal.s-ul.eu/5wj8c8X1)

### Discord Webhook Alerts With Abuse IPDB Integration
![Webhooks](https://paradoxal.s-ul.eu/kN1lR4Ol)

## 💡 Lessons Learned

**Technical Skills:**
- Hands-on experience with cloud security infrastructure
- Log aggregation with ELK Stack
- Container orchestration and networking
- Threat Analysis 

## 🚀 Future Enhancements

- [ ] Add HTTP/HTTPS honeypot (Glastopf)
- [ ] Machine learning for attack pattern detection
- [ ] Multi-region deployment for broader coverage

## 👨‍💻Setup Instructions 
If you want to do this yourself I have included some setup instructions and a setup script at [SETUP INSTRUCTIONS](SETUP_INSTRUCTIONS.md)

## 📝 License

MIT License - See [LICENSE](LICENSE) for details

## 🤝 Contributing

This was a personal project for me but if any of the config files have issues let me know.

## 📧 Contact

s0v - [LinkedIn](https://www.linkedin.com/in/michael-miller-15a594227) | [Portfolio](your-site) | [Email](pdxl5555@gmail.com)

---

**Disclaimer:** This honeypot was deployed in an isolated environment for educational and research purposes only. No production systems were compromised in this research. 
