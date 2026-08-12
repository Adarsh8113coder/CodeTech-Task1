## SSH Auth Log Analyzer

A Python tool that parses Linux SSH authentication logs to detect suspicious 
activity in real time. Built to understand how SOC analysts and SIEM tools 
identify attacks from raw log data.

### Features
- Parses standard Linux auth.log / secure log format
- Detects brute-force attempts using a sliding time window
- Flags successful logins that follow repeated failed attempts (possible compromise)
- Geolocates login IPs and flags logins from unexpected countries (via ip-api.com)
- Generates a readable summary report: top attacking IPs, most targeted usernames, and alerts

### Usage
\`\`\`bash
python LogAnalyzer.py auth.log --threshold 5 --window 5 --allowed-countries US
\`\`\`

### What I learned
- Regex-based log parsing
- Sliding window algorithms for time-based pattern detection
- Working with external APIs (IP geolocation)
- CLI tool design with argparse
