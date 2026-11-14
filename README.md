# Brute-Force Login Detector

This Python tool analyzes Linux SSH authentication logs and alerts when an attacker attempts a brute-force attack or successfully logs in after repeated failures. Its detection rules use a sliding time window and tunable thresholds to catch automated attacks while ignoring everyday mistakes like mistyped passwords.

## Detection Rules

| Rule | Severity | What it catches |
|------|----------|-----------------|
| Success after failures | Critical | A successful login from an IP after 3+ failed attempts, which likely means a compromised account |
| Sliding time window (5 failures in 10 min) | Medium | Fast, automated brute-force attacks from a single IP, while ignoring occasional mistyped passwords |

A password sprayer can stay under the brute-force threshold if it succeeds before reaching 5 failures. In the sample log, it failed only 4 times before logging in. The success-after-failures rule catches this, because a successful login right after repeated failures from the same IP is a strong sign of a compromised account.

## How to Run

```
python3 brute_force_detector.py
```

Settings like `THRESHOLD` and `WINDOW` are at the top of the script and
can be tuned for different environments.

## Sample Output

```
==================================================
 ATTACKER LOGIN ATTEMPTS: auth.log
==================================================

[CRITICAL] Possible account compromise

Compromise alert: User apatel from IP 198.51.100.23 at 2026-11-07 04:10:42 after 4 failed attempts.

[MEDIUM] Brute-force activity

Brute force alert: IP 203.0.113.77 had 5 failed attempts between 2026-11-07 02:41:05 and 2026-11-07 02:41:09.
```

The sample log uses IP addresses from ranges reserved for documentation
(RFC 5737), so no real systems are referenced.

## Limitations

- Distributed attacks: Detection is IP-based, so an attacker who spreads attempts across many IPs (for example, a botnet) can keep each IP under the threshold.
- Low-and-slow attacks: An attacker who spaces attempts more than a few minutes apart never gets 5 failures inside one 10-minute window.
- Hardcoded year: Linux auth logs omit the year, so the tool assumes every entry is from 2026. Logs from other years show incorrect dates, and logs that span New Year’s can produce wrong time calculations.
- Hardcoded Filename: The tool only reads a file named auth.log in the same folder. To analyze a different log, a user must rename their file or edit the code. A future version would accept the file path as a command-line argument.

## What I Learned

I learned how to read logs, the kinds of attack methods intruders use, and what those attacks look like in a computer’s logs. The hardest part of the coding was automating the IP detection, so the tool could find every IP and count how many failed attempts it took before a successful login. Apart from the coding, it was also difficult to choose the thresholds and conditions that separate a valid user making a password mistake from an attacker trying to get in, and sometimes succeeding. One bug I learned from was a stale variable that labeled the wrong user as compromised. It taught me to always test against output I already know is correct, and that’s my advice to anyone building a project like this.
