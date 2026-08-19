# Splunk Detection Dashboard: Brute Force Login Investigation

**Case File for: Brightleaf Consulting**
**Analyst: Anjola**
**Platform: Splunk Enterprise**

---

## Overview

This project builds a working Splunk detection dashboard around a real SSH brute force scenario, the same underlying attack pattern investigated in the original Wazuh based SOC lab, but rebuilt and re-analyzed in a second SIEM platform. It demonstrates SPL query writing, field extraction, detection logic, and dashboard construction, core Splunk skills that complement rather than duplicate the earlier Wazuh work.

---

## Scenario

Brightleaf Consulting's authentication logs were ingested into Splunk for analysis. The dataset contains two separate SSH brute force attempts against a single user account, followed by an unrelated login from a second employee shortly afterward. The goal was to detect the brute force pattern using Splunk's search processing language (SPL), quantify the true scope of failed authentication activity, and visualize the findings on a dashboard.

---

## Data Ingested

A custom authentication log (`brightleaf-auth.log`) was uploaded to Splunk via the Add Data wizard, containing 19 raw SSH authentication events spanning two attack bursts and one legitimate login.

**Source type:** `brightleaf_auth`
**Host:** `brightleaf-server`

---

## Investigation Steps

### 1. Initial Search: Literal Phrase Match

The first search used a single exact phrase:

```
source="brightleaf-auth.log" "Failed password"
```

This returned **11 events**. While useful as a starting point, this search only matched lines containing the literal string "Failed password", missing other authentication failure indicators phrased differently in the log, such as PAM's "authentication failures" messages.

### 2. Broadened Search: Catching All Failure Indicators

To capture the true scope of failed authentication activity, the search was expanded:

```
source="brightleaf-auth.log" "Failed password" OR source="brightleaf-auth.log" "authentication failures"
```

This returned **14 events**, three more than the initial search. This gap is a meaningful finding in its own right: a detection search built around a single exact phrase will under-report real authentication failure activity if the underlying system logs the same category of event using inconsistent wording. Any real detection rule built on log content should account for this kind of phrasing variance, not just one known string.

### 3. Field Extraction and Detection Logic

To move from a raw keyword search to an actual detection, the username and source IP were extracted from the raw event text using SPL's `rex` command, then aggregated:

```
source="brightleaf-auth.log" "Failed password" | rex field=_raw "for (?<user>\S+) from (?<src_ip>\S+)" | stats count by user src_ip | where count >= 3
```

**Result:** `user=anjyy`, `src_ip=192.168.56.1`, `count=10`

This confirms 10 failed password attempts for a single account from a single source IP, well above the threshold of 3 used to flag suspicious brute force behavior. This search was saved as a reusable Splunk report titled **"Brute Force Detection - Failed Logins."**

### 4. Manual Reconciliation

To verify Splunk's counts were accurate rather than assumed, the raw log file was manually reviewed line by line and cross checked against each search result:

| Burst | Time | Failed password lines | PAM failure lines | Total failure indicators |
|---|---|---|---|---|
| First attempt | 21:30 to 21:31 | 3 | 2 | 5 |
| Second attempt | 22:31 | 7 | 1 | 8 |
| priya.nair | 22:45 | 1 | 0 | 1 |
| **Total** | | **11** | **3** | **14** |

This matches exactly with both Splunk search results (11 and 14 respectively), confirming the searches were accurate and the discrepancy between them was fully understood and explained, not a tool error.

---

## Dashboard

A Classic Dashboard titled **"Brightleaf Security Dashboard"** was built containing two panels:

**Panel 1: Brute Force Detection - Failed Logins by User**
A statistics table showing the saved detection report result: user, source IP, and failure count, the equivalent of an alert result in a real SOC environment.

**Panel 2: All Authentication Events Timeline**
A full event listing of all 19 raw authentication events in chronological order, giving an analyst the complete picture, both failed and successful logins, across the entire timeframe, for manual review alongside the automated detection panel.

---

## Findings

**Finding 1: Confirmed brute force attack.** User `anjyy` experienced 10 failed SSH login attempts from source IP `192.168.56.1` across two distinct bursts (21:30 and 22:31), before an eighth attempt in the second burst succeeded. This matches a textbook credential brute force pattern, repeated failures followed by an eventual success from the same source.

**Finding 2: Single keyword searches under-report failure activity.** A search built on the exact phrase "Failed password" missed 3 legitimate authentication failure events that were logged under different wording (PAM authentication failure messages). Any detection logic relying on a single string match should be reviewed for this kind of blind spot.

**Finding 3: A second account authenticated from the same source IP shortly after the breach.** User `priya.nair` logged in successfully from `192.168.56.1`, the same IP responsible for the brute force attempts, roughly 14 minutes after the compromised `anjyy` account's successful login. This timing warrants further investigation, it may represent a legitimate second user coincidentally sharing a network address, or lateral movement using the same attacking machine following the initial compromise.

---

## Recommendations

**Immediate:**
- Reset credentials for the `anjyy` account and investigate what actions were taken during the compromised session
- Determine whether `priya.nair`'s login from the same source IP was legitimate or represents further compromise
- Block or restrict `192.168.56.1` at the network level pending investigation

**Detection logic:**
- Replace single keyword searches with broader detection logic that accounts for multiple phrasings of the same failure category, as demonstrated in this investigation
- Formalize the saved brute force detection report into a scheduled Splunk alert, so this pattern triggers a real time notification rather than requiring manual search

**Process level:**
- Enforce account lockout after a defined number of failed login attempts, so an account cannot sustain 10 consecutive failures without automatic intervention
- Consider correlating login source IPs against a known-good asset list, flagging any successful authentication from an IP previously associated with failed login activity, exactly the `priya.nair` pattern identified in Finding 3
- Run this same investigation methodology across other authentication sources in the environment to confirm this was an isolated incident
