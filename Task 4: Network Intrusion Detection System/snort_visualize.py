#!/usr/bin/env python3
# snort_visualize.py
# Purpose: Visualize Snort alerts using Pandas + Matplotlib

import os
import re
import sys
from collections import Counter

try:
    import pandas as pd
    import matplotlib.pyplot as plt
except Exception as e:
    print("Missing required modules. Install with:")
    print("python3 -m pip install pandas matplotlib --break-system-packages")
    print("Detailed error:", e)
    sys.exit(1)

# =========[ Configuration ]=========
ALERT_FILE = 'snort_alerts.csv'   # change path if needed (e.g. /var/log/snort/snort_alerts.csv)

# =========[ Step 1: Verify file exists ]=========
if not os.path.isfile(ALERT_FILE):
    print(f"Alert file not found: {ALERT_FILE}")
    print("Make sure you exported your Snort alerts to this file.")
    sys.exit(1)

# =========[ Step 2: Read file safely (fixed version) ]=========
try:
    with open(ALERT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip()]  # ignore empty lines
    raw = pd.DataFrame(lines, columns=['raw'])
except Exception as e:
    print("Failed to read alert file:", e)
    sys.exit(1)

# =========[ Step 3: Define field extraction functions ]=========
def extract_protocol(text):
    m = re.search(r'\{([A-Z]+)\}', text)
    if m:
        return m.group(1)
    for kw in ('ICMP','TCP','UDP','HTTP','SSH','DNS','RDP'):
        if kw in text:
            return kw
    return 'UNKNOWN'

def extract_first_ip(text):
    m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', text)
    return m.group(1) if m else 'Unknown'

def extract_dest_ip(text):
    m = re.search(r'->\s*(\d{1,3}(?:\.\d{1,3}){3})', text)
    if m:
        return m.group(1)
    ips = re.findall(r'(\d{1,3}(?:\.\d{1,3}){3})', text)
    if len(ips) >= 2:
        return ips[-1]
    return 'Unknown'

# =========[ Step 4: Apply extractions ]=========
raw['Protocol'] = raw['raw'].apply(lambda x: extract_protocol(x))
raw['Source'] = raw['raw'].apply(lambda x: extract_first_ip(x))
raw['Destination'] = raw['raw'].apply(lambda x: extract_dest_ip(x))

# =========[ Step 5: Clean DataFrame ]=========
df = raw.copy()
df = df[df['Protocol'] != 'UNKNOWN']   # optional filter
if df.empty:
    print("⚠️ No recognizable alerts found after parsing. Check your alert file format.")
    print(raw['raw'].head(15).to_string(index=False))
    sys.exit(0)

# =========[ Step 6: Count alerts per protocol & source ]=========
protocol_counts = Counter(df['Protocol'].tolist())
source_counts = Counter(df['Source'].tolist())

pc_df = pd.DataFrame.from_dict(protocol_counts, orient='index', columns=['count']).sort_values('count', ascending=False)
sc_df = pd.DataFrame.from_dict(source_counts, orient='index', columns=['count']).sort_values('count', ascending=False).head(10)

# =========[ Step 7: Plot graphs ]=========
# Plot 1: Alerts by Protocol
plt.figure(figsize=(8,5))
pc_df['count'].plot(kind='bar', color='steelblue')
plt.title('Snort Alerts by Protocol')
plt.xlabel('Protocol')
plt.ylabel('Count')
plt.tight_layout()
plt.savefig('protocols.png', dpi=150)
print("✅ Saved graph: protocols.png")
plt.show()

# Plot 2: Top Source IPs
plt.figure(figsize=(8,5))
sc_df['count'].plot(kind='bar', color='darkorange')
plt.title('Top Source IPs (Top 10)')
plt.xlabel('Source IP')
plt.ylabel('Alert Count')
plt.tight_layout()
plt.savefig('sources.png', dpi=150)
print("✅ Saved graph: sources.png")
plt.show()

# =========[ Step 8: Wrap up ]=========
print("\n📊 Visualization Complete.")
print(f"Processed alerts from: {ALERT_FILE}")
print("If plots appear empty, open the CSV and confirm alert lines are present.")
print("Sample data:")
print(raw['raw'].head(10).to_string(index=False))