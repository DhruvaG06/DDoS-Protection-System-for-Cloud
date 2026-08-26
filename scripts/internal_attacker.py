"""OneChance Internal Cloud Workload Attack Simulator.

Simulates an internal compromised cloud workload generating rapid abnormal traffic
toward the internal demo application/service via the OneChance Gateway.

Demonstrates that OneChance detects and mitigates both EXTERNAL and INTERNAL cloud attacks.
"""

import argparse
import time
import httpx
from colorama import Fore, Style, init

init(autoreset=True)


def run_internal_attack(gateway_url: str = "http://localhost:8000", duration_seconds: int = 10, rate_per_sec: int = 25):
    """Execute controlled internal cloud attack burst."""
    print(f"\n{Fore.RED}{'='*65}")
    print(f"{Fore.RED}{' [!] ONECHANCE INTERNAL CLOUD ATTACK SIMULATION STARTED '.center(65)}")
    print(f"{Fore.RED}{'='*65}{Style.RESET_ALL}\n")
    print(f"{Fore.YELLOW}Target Gateway      : {gateway_url}")
    print(f"{Fore.YELLOW}Attack Origin       : INTERNAL_WORKLOAD (Simulated Compromised Pod/Service)")
    print(f"{Fore.YELLOW}Target Path         : /api/expensive-operation")
    print(f"{Fore.YELLOW}Traffic Rate        : ~{rate_per_sec} requests/sec for {duration_seconds}s\n")

    client = httpx.Client(base_url=gateway_url, timeout=3.0)
    start_time = time.time()
    total_requests = 0
    blocked_count = 0
    challenged_count = 0
    allowed_count = 0

    headers = {
        "user-agent": "Internal-Compromised-Microservice/1.0",
        "x-attack-origin": "internal",
        "x-workload-id": "internal-attacker-pod-99",
        "x-forwarded-for": "10.0.9.99",  # Internal subnet IP
    }

    try:
        while time.time() - start_time < duration_seconds:
            loop_start = time.time()
            for _ in range(rate_per_sec):
                try:
                    resp = client.get("/api/expensive-operation?iterations=1000", headers=headers)
                    total_requests += 1

                    decision = resp.headers.get("x-decision", "UNKNOWN")
                    risk_score = resp.headers.get("x-risk-score", "0")
                    threat_level = resp.headers.get("x-threat-level", "LOW")

                    if decision == "BLOCK" or resp.status_code in [403, 429]:
                        blocked_count += 1
                        print(f"  {Fore.RED}[BLOCK {resp.status_code}] Req #{total_requests:03d} | Risk: {risk_score}/100 | Threat: {threat_level} | Decision: BLOCK")
                    elif decision == "CHALLENGE":
                        challenged_count += 1
                        print(f"  {Fore.YELLOW}[CHALLENGE] Req #{total_requests:03d} | Risk: {risk_score}/100 | Threat: {threat_level} | Decision: CHALLENGE")
                    else:
                        allowed_count += 1
                        print(f"  {Fore.GREEN}[ALLOW] Req #{total_requests:03d} | Risk: {risk_score}/100 | Status: {resp.status_code}")

                except Exception as e:
                    print(f"  {Fore.LIGHTBLACK_EX}[ERR] Request failed: {e}")

                time.sleep(1.0 / rate_per_sec)

            # Sleep remainder of second if needed
            elapsed = time.time() - loop_start
            if elapsed < 1.0:
                time.sleep(1.0 - elapsed)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Attack simulation interrupted by user.")

    print(f"\n{Fore.CYAN}{'='*65}")
    print(f"{Fore.CYAN}{' INTERNAL ATTACK SIMULATION COMPLETED '.center(65)}")
    print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Total Internal Requests Sent : {total_requests}")
    print(f"  {Fore.GREEN}Allowed                      : {allowed_count}")
    print(f"  {Fore.YELLOW}Challenged                   : {challenged_count}")
    print(f"  {Fore.RED}Blocked                      : {blocked_count}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OneChance Internal Cloud Attack Simulator")
    parser.add_argument("--url", default="http://localhost:8000", help="Gateway URL")
    parser.add_argument("--duration", type=int, default=8, help="Duration in seconds")
    parser.add_argument("--rate", type=int, default=20, help="Requests per second")
    args = parser.parse_args()

    run_internal_attack(gateway_url=args.url, duration_seconds=args.duration, rate_per_sec=args.rate)
