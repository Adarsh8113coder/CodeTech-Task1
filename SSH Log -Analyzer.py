#!/usr/bin/env python3

import re
import argparse
import json
import urllib.request
import urllib.error
from collections import defaultdict
from datetime import datetime, timedelta

_GEO_CACHE = {}


def geolocate_ip(ip):
    """
    Look up the country for an IP using the free ip-api.com endpoint
    (no API key required, rate-limited to 45 requests/minute).
    Returns a dict like {"country": "United States", "countryCode": "US"}
    or None if the lookup fails (e.g. private IP, no internet, rate limit).
    """
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]

    private_prefixes = ("10.", "192.168.", "127.", "169.254.")
    if ip.startswith(private_prefixes) or ip.startswith("172."):
        octets = ip.split(".")
        if ip.startswith("172.") and len(octets) > 1 and 16 <= int(octets[1]) <= 31:
            _GEO_CACHE[ip] = None
            return None
        if not ip.startswith("172."):
            _GEO_CACHE[ip] = None
            return None

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode"
        with urllib.request.urlopen(url, timeout=3) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            result = {"country": data["country"], "countryCode": data["countryCode"]}
        else:
            result = None
    except (urllib.error.URLError, TimeoutError, Exception):
        result = None

    _GEO_CACHE[ip] = result
    return result

FAILED_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+'
    r'Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)'
)
ACCEPTED_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+'
    r'Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+)'
)

CURRENT_YEAR = datetime.now().year


def parse_timestamp(month, day, time_str):
    """Convert syslog-style timestamp fragments into a datetime object."""
    ts_str = f"{CURRENT_YEAR} {month} {day} {time_str}"
    return datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")


def parse_log(filepath):
    """Read the log file and extract failed/successful login events."""
    failed_events = []  
    success_events = []  

    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            fm = FAILED_RE.search(line)
            if fm:
                ts = parse_timestamp(fm["month"], fm["day"], fm["time"])
                failed_events.append((ts, fm["user"], fm["ip"]))
                continue

            am = ACCEPTED_RE.search(line)
            if am:
                ts = parse_timestamp(am["month"], am["day"], am["time"])
                success_events.append((ts, am["user"], am["ip"]))

    return failed_events, success_events


def detect_bruteforce(failed_events, threshold, window_minutes):
    """
    Flag IPs with more than `threshold` failed attempts within any
    `window_minutes` sliding window.
    """
    by_ip = defaultdict(list)
    for ts, user, ip in failed_events:
        by_ip[ip].append(ts)

    alerts = []
    for ip, timestamps in by_ip.items():
        timestamps.sort()
        window = timedelta(minutes=window_minutes)
        left = 0
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > window:
                left += 1
            count_in_window = right - left + 1
            if count_in_window > threshold:
                alerts.append({
                    "ip": ip,
                    "count": count_in_window,
                    "window_start": timestamps[left],
                    "window_end": timestamps[right],
                })
                break
    return alerts


def detect_success_after_failures(failed_events, success_events, threshold):
    """Flag successful logins from an IP that also had many prior failures."""
    fail_counts = defaultdict(int)
    for _, _, ip in failed_events:
        fail_counts[ip] += 1

    suspicious = []
    for ts, user, ip in success_events:
        if fail_counts.get(ip, 0) >= threshold:
            suspicious.append({
                "ip": ip,
                "user": user,
                "time": ts,
                "prior_failures": fail_counts[ip],
            })
    return suspicious


def detect_foreign_logins(success_events, allowed_countries):
    """
    Flag successful logins whose IP resolves to a country NOT in
    allowed_countries (a list of country codes like ["US", "CA"]).
    If allowed_countries is empty, this check is skipped.
    """
    if not allowed_countries:
        return []

    flagged = []
    allowed_set = {c.upper() for c in allowed_countries}
    for ts, user, ip in success_events:
        geo = geolocate_ip(ip)
        if geo is None:
            continue  
        if geo["countryCode"].upper() not in allowed_set:
            flagged.append({
                "ip": ip,
                "user": user,
                "time": ts,
                "country": geo["country"],
                "countryCode": geo["countryCode"],
            })
    return flagged


def print_report(failed_events, success_events, bruteforce_alerts, compromise_alerts, foreign_alerts=None):
    print("=" * 60)
    print("AUTH LOG ANALYSIS REPORT")
    print("=" * 60)

    print(f"\nTotal failed login attempts: {len(failed_events)}")
    print(f"Total successful logins:     {len(success_events)}")

    ip_counts = defaultdict(int)
    for _, _, ip in failed_events:
        ip_counts[ip] += 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    if top_ips:
        print("\nTop source IPs by failed attempts:")
        for ip, count in top_ips:
            print(f"  {ip:<20} {count} failures")

    # Top targeted usernames
    user_counts = defaultdict(int)
    for _, user, _ in failed_events:
        user_counts[user] += 1
    top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    if top_users:
        print("\nMost targeted usernames:")
        for user, count in top_users:
            print(f"  {user:<20} {count} attempts")

    # 
    print(f"\n{'-' * 60}")
    print("BRUTE-FORCE ALERTS")
    print("-" * 60)
    if bruteforce_alerts:
        for a in bruteforce_alerts:
            print(f"  [ALERT] {a['ip']} — {a['count']} failed attempts "
                  f"between {a['window_start']} and {a['window_end']}")
    else:
        print("  None detected.")


    print(f"\n{'-' * 60}")
    print("POSSIBLE COMPROMISE (success after repeated failures)")
    print("-" * 60)
    if compromise_alerts:
        for a in compromise_alerts:
            print(f"  [WARNING] {a['ip']} logged in as '{a['user']}' at {a['time']} "
                  f"after {a['prior_failures']} prior failures")
    else:
        print("  None detected.")

    #
    if foreign_alerts is not None:
        print(f"\n{'-' * 60}")
        print("LOGINS FROM UNEXPECTED COUNTRIES")
        print("-" * 60)
        if foreign_alerts:
            for a in foreign_alerts:
                print(f"  [WARNING] {a['ip']} ({a['country']}, {a['countryCode']}) "
                      f"logged in as '{a['user']}' at {a['time']}")
        else:
            print("  None detected.")

    print("\n" + "=" * 60)
def main():
    parser = argparse.ArgumentParser(description="Analyze Linux auth logs for suspicious SSH activity.")
    parser.add_argument("logfile", help="Path to auth.log or secure log file")
    parser.add_argument("--threshold", type=int, default=5,
                         help="Failed attempts threshold to trigger brute-force alert (default: 5)")
    parser.add_argument("--window", type=int, default=5,
                         help="Time window in minutes for brute-force detection (default: 5)")
    parser.add_argument("--allowed-countries", nargs="*", default=None,
                         help="List of expected country codes for successful logins, "
                              "e.g. --allowed-countries US CA. Flags successful logins "
                              "from any other country. Requires internet access "
                              "(uses the free ip-api.com lookup).")
    args = parser.parse_args()

    failed_events, success_events = parse_log(args.logfile)
    bruteforce_alerts = detect_bruteforce(failed_events, args.threshold, args.window)
    compromise_alerts = detect_success_after_failures(failed_events, success_events, args.threshold)

    foreign_alerts = None
    if args.allowed_countries is not None:
        foreign_alerts = detect_foreign_logins(success_events, args.allowed_countries)

    print_report(failed_events, success_events, bruteforce_alerts, compromise_alerts, foreign_alerts)


if __name__ == "__main__":
    main()
