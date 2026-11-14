from datetime import datetime, timedelta


THRESHOLD = 5
FRAME_OFFSET = THRESHOLD - 1
WINDOW = timedelta(minutes=10)
MIN_FAILURES_BEFORE_SUCCESS = 3

TITLE = ("==================================================\n "
         "ATTACKER LOGIN ATTEMPTS: auth.log\n"
         "==================================================\n")


def parse_auth_log(line):
    """Return the timestamp, IP address, and username from one auth log line."""
    parts = line.split()
    time_text = "2026 " + " ".join(parts[0:3])
    timestamp = datetime.strptime(time_text, "%Y %b %d %H:%M:%S")
    ip_address = parts[parts.index("from")+1]
    username = parts[parts.index("from")-1]
    return timestamp, ip_address, username


def find_brute_force(failed_ip_timestamps):
    """ Returns the alerts of brute force attacks past THRESHOLD"""
    alerts = []
    for ip, times in failed_ip_timestamps.items():
        number_of_frames = len(times) - THRESHOLD + 1
        for i in range(number_of_frames):
            first = times[i]
            last = times[i+FRAME_OFFSET]
            if last - first <= WINDOW:
                alerts.append((ip, first, last))
                break
    return alerts


def print_alerts(compromise_alerts, brute_force_alerts):
    """Print a report of compromise and brute-force alerts, grouped by severity."""
    print(TITLE)

    print("[CRITICAL] Possible account compromise\n")
    for username, ip_address, timestamp, prior_failures in compromise_alerts:
        print(
            f"Compromise alert: User {username} from IP "
            f"{ip_address} at {timestamp} after {prior_failures} failed attempts.\n"
        )

    print("[MEDIUM] Brute-force activity\n")
    for ip, first, last in brute_force_alerts:
        print(
            f"Brute force alert: IP {ip} had {THRESHOLD} "
            f"failed attempts between {first} and {last}.\n"
        )


def main():
    """Read auth.log once, track failed and successful logins, 
    run all detection rules, and print the report."""
    failed_ip_timestamps = {}
    compromise_alerts = []
    with open("auth.log") as f:
        for line in f:
            if "Failed password" in line or "Accepted password" in line:   # outer gate
                timestamp, ip_address, username = parse_auth_log(line)
                if "Failed password" in line:
                    if ip_address not in failed_ip_timestamps:
                        failed_ip_timestamps[ip_address] = []
                    failed_ip_timestamps[ip_address].append(timestamp)
                elif "Accepted password" in line:
                    prior_failures = len(
                        failed_ip_timestamps.get(ip_address, []))
                    if prior_failures >= MIN_FAILURES_BEFORE_SUCCESS:
                        compromise_alerts.append(
                            (username, ip_address, timestamp, prior_failures))
    brute_force_alerts = find_brute_force(failed_ip_timestamps)

    print_alerts(compromise_alerts, brute_force_alerts)


if __name__ == "__main__":
    main()
