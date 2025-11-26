#!/usr/bin/env python3
"""
AbuseIPDB Honeypot Enrichment Service
Checks new IPs against AbuseIPDB and sends Discord alerts for high-risk IPs
Version: 2.0 - Fixed duplicate alerts
"""

import requests
import time
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import json
import sys

# ============================================================================
# CONFIGURATION
# ============================================================================

ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY_HERE"
DISCORD_WEBHOOK = "YOUR_DISCORD_WEBHOOK_URL_HERE"
ES_HOST = "http://localhost:9200"

# Rate limiting
MAX_API_CALLS_PER_DAY = 950  # Leave buffer (1000 limit)
MIN_SECONDS_BETWEEN_CALLS = 1.5  # Slightly more than 1 sec for safety

# Alert threshold
HIGH_RISK_THRESHOLD = 75  # Alert on scores >= 75%
MODERATE_RISK_THRESHOLD = 50  # Track but less urgent

# Check interval
CHECK_INTERVAL_SECONDS = 60  # Check for new IPs every 60 seconds

# ============================================================================
# GLOBAL STATE
# ============================================================================

es = Elasticsearch([ES_HOST])
checked_ips = {}  # Cache: {ip: {abuse_data, timestamp}}
last_api_call_time = 0
api_calls_today = 0
daily_reset_time = datetime.now().date()
alerted_ips = set()  # Track IPs we've already alerted on

# ============================================================================
# ABUSEIPDB FUNCTIONS
# ============================================================================

def check_abuseipdb(ip):
    """
    Check IP against AbuseIPDB with rate limiting and caching
    Returns: abuse_data dict or None
    """
    global last_api_call_time, api_calls_today, daily_reset_time
    
    # Reset daily counter if new day
    current_date = datetime.now().date()
    if current_date != daily_reset_time:
        api_calls_today = 0
        daily_reset_time = current_date
        print(f"\n📅 New day - API call counter reset")
    
    # Check cache first (valid for 24 hours)
    if ip in checked_ips:
        cache_time = checked_ips[ip].get('cached_at')
        if cache_time and (datetime.now() - cache_time).total_seconds() < 86400:
            print(f"  💾 Cache hit: {ip}")
            return checked_ips[ip]['data']
    
    # Check rate limits
    if api_calls_today >= MAX_API_CALLS_PER_DAY:
        print(f"  ⚠️  Daily API limit reached ({MAX_API_CALLS_PER_DAY})")
        return None
    
    # Rate limiting: wait between calls
    time_since_last = time.time() - last_api_call_time
    if time_since_last < MIN_SECONDS_BETWEEN_CALLS:
        wait_time = MIN_SECONDS_BETWEEN_CALLS - time_since_last
        time.sleep(wait_time)
    
    # Make API call
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": ""
        }
        
        print(f"  🔍 Checking AbuseIPDB...", end=" ", flush=True)
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()['data']
            
            # Update tracking
            api_calls_today += 1
            last_api_call_time = time.time()
            
            # Cache result
            checked_ips[ip] = {
                'data': data,
                'cached_at': datetime.now()
            }
            
            score = data.get('abuseConfidenceScore', 0)
            reports = data.get('totalReports', 0)
            print(f"✓ Score: {score}% | Reports: {reports}")
            print(f"  📊 API calls today: {api_calls_today}/{MAX_API_CALLS_PER_DAY}")
            
            return data
            
        elif response.status_code == 429:
            print(f"❌ Rate limited!")
            return None
        else:
            print(f"❌ Error {response.status_code}")
            return None
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return None

# ============================================================================
# ELASTICSEARCH FUNCTIONS
# ============================================================================

def get_enriched_ips():
    """
    Get set of IPs that have already been enriched
    Returns: set of IP addresses
    """
    try:
        query = {
            "size": 0,
            "query": {
                "exists": {"field": "abuseipdb"}
            },
            "aggs": {
                "enriched_ips": {
                    "terms": {
                        "field": "src_ip",
                        "size": 10000
                    }
                }
            }
        }
        
        result = es.search(index="cowrie-*", body=query)
        enriched_ips = {bucket['key'] for bucket in result['aggregations']['enriched_ips']['buckets']}
        
        return enriched_ips
        
    except Exception as e:
        print(f"❌ Error getting enriched IPs: {e}")
        return set()

def get_all_recent_ips():
    """
    Get all unique IPs from last 24 hours
    Returns: set of IP addresses
    """
    try:
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"exists": {"field": "src_ip"}},
                        {"range": {"@timestamp": {"gte": "now-24h"}}}
                    ]
                }
            },
            "aggs": {
                "unique_ips": {
                    "terms": {
                        "field": "src_ip",
                        "size": 100
                    }
                }
            }
        }
        
        result = es.search(index="cowrie-*", body=query)
        all_ips = {bucket['key'] for bucket in result['aggregations']['unique_ips']['buckets']}
        
        return all_ips
        
    except Exception as e:
        print(f"❌ Error getting recent IPs: {e}")
        return set()

def get_new_ips():
    """
    Get IPs that haven't been enriched yet
    Returns: list of unique IPs that need checking
    """
    try:
        # Get already enriched IPs
        enriched_ips = get_enriched_ips()
        
        # Get all recent IPs
        all_ips = get_all_recent_ips()
        
        # Return only IPs that haven't been enriched
        new_ips = list(all_ips - enriched_ips)
        
        return new_ips
        
    except Exception as e:
        print(f"❌ Error getting new IPs: {e}")
        return []

def get_ip_geo_data(ip):
    """
    Get geographic data for IP from most recent event
    """
    try:
        query = {
            "size": 1,
            "query": {"term": {"src_ip": ip}},
            "sort": [{"@timestamp": "desc"}]
        }
        
        result = es.search(index="cowrie-*", body=query)
        
        if result['hits']['total']['value'] > 0:
            source = result['hits']['hits'][0]['_source']
            geoip = source.get('geoip', {})
            
            return {
                'country_name': geoip.get('country_name', 'Unknown'),
                'city_name': geoip.get('city_name', 'Unknown'),
                'region_name': geoip.get('region_name', 'Unknown')
            }
    except:
        pass
    
    return {
        'country_name': 'Unknown',
        'city_name': 'Unknown',
        'region_name': 'Unknown'
    }

def update_elasticsearch(ip, abuse_data):
    """
    Update all documents with this IP to include AbuseIPDB data
    """
    try:
        update_body = {
            "script": {
                "source": """
                    ctx._source.abuseipdb = params.abuse_data;
                    ctx._source.threat_score = params.score;
                    ctx._source.enriched_at = params.enriched_at;
                """,
                "params": {
                    "abuse_data": abuse_data,
                    "score": abuse_data.get('abuseConfidenceScore', 0),
                    "enriched_at": datetime.utcnow().isoformat()
                }
            },
            "query": {
                "term": {"src_ip": ip}
            }
        }
        
        result = es.update_by_query(
            index="cowrie-*",
            body=update_body,
            conflicts="proceed",
            refresh=True
        )
        
        updated = result.get('updated', 0)
        print(f"  ✓ Updated {updated} document(s) in Elasticsearch")
        
    except Exception as e:
        print(f"  ❌ Error updating Elasticsearch: {e}")

# ============================================================================
# DISCORD FUNCTIONS
# ============================================================================

def send_discord_alert(ip, abuse_data, geo_data):
    """
    Send Discord alert for high-risk IPs (only once per IP)
    """
    global alerted_ips
    
    # Check if we've already alerted on this IP
    if ip in alerted_ips:
        print(f"  ℹ️  Already alerted on this IP, skipping Discord notification")
        return
    
    score = abuse_data.get('abuseConfidenceScore', 0)
    reports = abuse_data.get('totalReports', 0)
    
    # Determine alert level and color
    if score >= HIGH_RISK_THRESHOLD:
        title = "🚨 HIGH-RISK IP DETECTED"
        description = f"Known bad actor with {score}% threat score"
        color = 16711680  # Red
    elif score >= MODERATE_RISK_THRESHOLD:
        title = "⚠️ MODERATE-RISK IP DETECTED"
        description = f"Suspicious IP with {score}% threat score"
        color = 16744192  # Orange
    else:
        # Don't alert on low-risk IPs
        return
    
    # Get country flag emoji
    country_code = abuse_data.get('countryCode', '')
    flag = get_flag_emoji(country_code)
    
    payload = {
        "content": f"{title}",
        "embeds": [{
            "title": f"{flag} Threat Intelligence Alert",
            "description": description,
            "color": color,
            "fields": [
                {
                    "name": "IP Address",
                    "value": f"`{ip}`",
                    "inline": True
                },
                {
                    "name": "Abuse Score",
                    "value": f"**{score}%**",
                    "inline": True
                },
                {
                    "name": "Total Reports",
                    "value": str(reports),
                    "inline": True
                },
                {
                    "name": "Country",
                    "value": abuse_data.get('countryName', 'Unknown'),
                    "inline": True
                },
                {
                    "name": "City",
                    "value": geo_data.get('city_name', 'Unknown'),
                    "inline": True
                },
                {
                    "name": "ISP",
                    "value": abuse_data.get('isp', 'Unknown'),
                    "inline": True
                },
                {
                    "name": "Domain",
                    "value": abuse_data.get('domain', 'N/A'),
                    "inline": True
                },
                {
                    "name": "Usage Type",
                    "value": abuse_data.get('usageType', 'Unknown'),
                    "inline": True
                },
                {
                    "name": "Last Reported",
                    "value": format_date(abuse_data.get('lastReportedAt')),
                    "inline": True
                }
            ],
            "footer": {
                "text": f"AbuseIPDB Threat Intelligence • First seen in honeypot"
            },
            "timestamp": datetime.utcnow().isoformat()
        }]
    }
    
    try:
        response = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
        if response.status_code == 204:
            print(f"  ✓ Discord alert sent!")
            # Mark this IP as alerted
            alerted_ips.add(ip)
        else:
            print(f"  ❌ Discord error: {response.status_code}")
    except Exception as e:
        print(f"  ❌ Discord exception: {e}")

def get_flag_emoji(country_code):
    """Convert country code to flag emoji"""
    if not country_code or len(country_code) != 2:
        return "🏴"
    
    # Convert country code to flag emoji
    return ''.join(chr(127397 + ord(c)) for c in country_code.upper())

def format_date(date_str):
    """Format ISO date to readable format"""
    if not date_str:
        return "Unknown"
    try:
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except:
        return date_str

# ============================================================================
# STATISTICS
# ============================================================================

def print_statistics():
    """Print enrichment statistics"""
    try:
        # Count enriched IPs
        result = es.count(
            index="cowrie-*",
            body={"query": {"exists": {"field": "abuseipdb"}}}
        )
        enriched = result['count']
        
        # Count total unique IPs
        total_result = es.search(
            index="cowrie-*",
            body={
                "size": 0,
                "aggs": {
                    "unique_ips": {
                        "cardinality": {"field": "src_ip"}
                    }
                }
            }
        )
        total = total_result['aggregations']['unique_ips']['value']
        
        percentage = (enriched / total * 100) if total > 0 else 0
        
        print(f"\n📊 Statistics:")
        print(f"   Enriched IPs: {enriched}/{total} ({percentage:.1f}%)")
        print(f"   Cached IPs: {len(checked_ips)}")
        print(f"   Alerted IPs: {len(alerted_ips)}")
        print(f"   API calls today: {api_calls_today}/{MAX_API_CALLS_PER_DAY}")
        
    except Exception as e:
        print(f"❌ Error getting statistics: {e}")

# ============================================================================
# MAIN LOOP
# ============================================================================

def main():
    """Main enrichment loop"""
    global alerted_ips
    
    print("=" * 70)
    print("🔍 AbuseIPDB Honeypot Enrichment Service v2.0")
    print("=" * 70)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Elasticsearch: {ES_HOST}")
    print(f"Check interval: {CHECK_INTERVAL_SECONDS} seconds")
    print(f"High-risk threshold: {HIGH_RISK_THRESHOLD}%")
    print(f"Moderate-risk threshold: {MODERATE_RISK_THRESHOLD}%")
    print(f"API key configured: {'Yes ✓' if ABUSEIPDB_API_KEY != 'YOUR_ABUSEIPDB_API_KEY_HERE' else 'No ✗'}")
    print(f"Duplicate prevention: Enabled ✓")
    print("=" * 70)
    
    # Validate configuration
    if ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_API_KEY_HERE":
        print("\n❌ ERROR: AbuseIPDB API key not configured!")
        print("   Please edit this file and add your API key.")
        print("   Get one free at: https://www.abuseipdb.com/api")
        sys.exit(1)
    
    if DISCORD_WEBHOOK == "YOUR_DISCORD_WEBHOOK_URL_HERE":
        print("\n⚠️  WARNING: Discord webhook not configured!")
        print("   Alerts will not be sent. Edit DISCORD_WEBHOOK to enable.")
        input("   Press Enter to continue without Discord alerts...")
    
    # Load already enriched IPs to prevent re-alerting
    try:
        enriched = get_enriched_ips()
        alerted_ips = enriched.copy()
        print(f"📋 Loaded {len(alerted_ips)} previously enriched IPs (won't re-alert)")
    except Exception as e:
        print(f"⚠️  Could not load enriched IPs: {e}")
    
    iteration = 0
    processed_this_session = set()
    
    while True:
        try:
            iteration += 1
            print(f"\n🔄 Check #{iteration} - {datetime.now().strftime('%H:%M:%S')}")
            print("-" * 70)
            
            # Get new IPs that need enrichment
            new_ips = get_new_ips()
            
            # Filter out IPs already processed in this session
            new_ips = [ip for ip in new_ips if ip not in processed_this_session]
            
            if not new_ips:
                print("✓ No new IPs to check")
            else:
                print(f"📋 Found {len(new_ips)} new IP(s) to check")
                
                for i, ip in enumerate(new_ips, 1):
                    print(f"\n[{i}/{len(new_ips)}] Processing: {ip}")
                    
                    # Mark as processed immediately
                    processed_this_session.add(ip)
                    
                    # Check AbuseIPDB
                    abuse_data = check_abuseipdb(ip)
                    
                    if abuse_data:
                        # Get geo data
                        geo_data = get_ip_geo_data(ip)
                        
                        # Update Elasticsearch (marks IP as enriched)
                        update_elasticsearch(ip, abuse_data)
                        
                        # Send Discord alert if meets threshold (only once per IP)
                        score = abuse_data.get('abuseConfidenceScore', 0)
                        if score >= MODERATE_RISK_THRESHOLD:
                            send_discord_alert(ip, abuse_data, geo_data)
                        else:
                            print(f"  ℹ️  Score below threshold ({score}%), no alert sent")
                    else:
                        print(f"  ⚠️  Could not get AbuseIPDB data")
                    
                    # Small delay between IPs
                    if i < len(new_ips):
                        time.sleep(1)
            
            # Print statistics every 10 iterations
            if iteration % 10 == 0:
                print_statistics()
                print(f"   Processed this session: {len(processed_this_session)}")
            
            # Wait before next check
            print(f"\n💤 Sleeping for {CHECK_INTERVAL_SECONDS} seconds...")
            time.sleep(CHECK_INTERVAL_SECONDS)
            
        except KeyboardInterrupt:
            print("\n\n👋 Shutting down gracefully...")
            print_statistics()
            print(f"Total IPs processed this session: {len(processed_this_session)}")
            break
            
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            print("   Continuing in 30 seconds...")
            time.sleep(30)

if __name__ == "__main__":
    main()
