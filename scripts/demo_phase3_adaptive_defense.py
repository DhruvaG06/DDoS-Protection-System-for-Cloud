"""OneChance Phase 3 Adaptive Defense Demonstration Script.

Demonstrates 4 controlled scenarios:
- Scenario A (Normal Traffic) -> ALLOW
- Scenario B (Suspicious Traffic) -> CHALLENGE
- Scenario C (Malicious Flood) -> BLOCK
- Scenario D (Repeated Challenge Failures) -> CHALLENGE -> BLOCK (Adaptive Behavior)
"""

import time
import httpx
from colorama import Fore, Style, init

init(autoreset=True)

GATEWAY_URL = "http://localhost:8000"


def print_banner(title: str):
    print(f"\n{Fore.CYAN}{'='*65}")
    print(f"{Fore.YELLOW}{title.center(65)}")
    print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")


def print_decision(res_dict: dict, headers: dict, status_code: int):
    decision = headers.get("x-decision", res_dict.get("decision", "UNKNOWN"))
    risk_score = headers.get("x-risk-score", res_dict.get("risk_score", "N/A"))
    threat_level = headers.get("x-threat-level", res_dict.get("threat_level", "N/A"))
    reasons = res_dict.get("reasons", [])

    color = Fore.GREEN if decision == "ALLOW" else (Fore.YELLOW if decision == "CHALLENGE" else Fore.RED)

    print(f"  {Fore.WHITE}HTTP Status  : {color}{status_code}")
    print(f"  {Fore.WHITE}Decision     : {color}{Style.BRIGHT}{decision}")
    print(f"  {Fore.WHITE}Risk Score   : {color}{risk_score}/100")
    print(f"  {Fore.WHITE}Threat Level : {color}{threat_level}")
    if reasons:
        print(f"  {Fore.WHITE}Reasons      :")
        for r in reasons:
            print(f"    {Fore.LIGHTBLACK_EX}- {r}")
    print()


def run_scenario_a():
    print_banner("SCENARIO A: Normal Traffic (ALLOW)")
    print(f"{Fore.WHITE}Sending benign request to GET /api/products...")
    try:
        resp = httpx.get(f"{GATEWAY_URL}/api/products", headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0)"}, timeout=5.0)
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text}
        print_decision(body, dict(resp.headers), resp.status_code)
    except Exception as e:
        print(f"{Fore.RED}Connection error: {e}")


def run_scenario_b():
    print_banner("SCENARIO B: Suspicious Rapid Requests (CHALLENGE)")
    print(f"{Fore.WHITE}Simulating rapid requests to trigger medium risk threshold...")
    client = httpx.Client(base_url=GATEWAY_URL, timeout=5.0)
    for i in range(12):
        resp = client.get("/api/search?q=ddos", headers={"user-agent": "ScraperBot/1.0"})
        if resp.status_code == 403 or resp.headers.get("x-decision") == "CHALLENGE":
            body = resp.json()
            print(f"{Fore.YELLOW}Request #{i+1} triggered CHALLENGE!")
            print_decision(body, dict(resp.headers), resp.status_code)
            
            # Extract challenge token
            token = body.get("challenge_token") or resp.headers.get("x-challenge-token")
            if token:
                print(f"{Fore.CYAN}Submitting challenge token verification: {token}...")
                v_resp = client.post("/api/challenge/verify", json={"challenge_token": token})
                print(f"Verification Result: {v_resp.json()}\n")
                
                # Retry with challenge token header
                allowed_resp = client.get("/api/search?q=ddos", headers={"x-challenge-token": token})
                print(f"{Fore.GREEN}Retried request with verified token:")
                print_decision(allowed_resp.json() if allowed_resp.headers.get("content-type") == "application/json" else {}, dict(allowed_resp.headers), allowed_resp.status_code)
            break
        time.sleep(0.05)


def run_scenario_c():
    print_banner("SCENARIO C: High-Risk Malicious Request (BLOCK)")
    print(f"{Fore.WHITE}Sending request with synthetic compromised internal headers...")
    try:
        # High burst / endpoint anomaly pattern
        resp = httpx.get(
            f"{GATEWAY_URL}/api/expensive-operation",
            headers={
                "user-agent": "Internal-Compromised-Botnet/2.0",
                "x-forwarded-for": "10.0.9.99",
            },
            timeout=5.0,
        )
        try:
            body = resp.json()
        except Exception:
            body = {}
        print_decision(body, dict(resp.headers), resp.status_code)
    except Exception as e:
        print(f"{Fore.RED}Connection error: {e}")


def run_scenario_d():
    print_banner("SCENARIO D: Adaptive Transition (CHALLENGE -> Repeated Failures -> BLOCK)")
    print(f"{Fore.WHITE}Simulating repeated invalid challenge responses...")
    client = httpx.Client(base_url=GATEWAY_URL, timeout=5.0)
    
    # 1. Trigger challenge
    for i in range(10):
        resp = client.get("/api/login", headers={"user-agent": "SuspectClient/1.0"})
        if resp.status_code in [403, 429] or resp.headers.get("x-decision") in ["CHALLENGE", "BLOCK"]:
            print(f"{Fore.YELLOW}Triggered initial security state:")
            print_decision(resp.json(), dict(resp.headers), resp.status_code)
            break

    print(f"{Fore.CYAN}Submitting 3 invalid challenge tokens sequentially...")
    for fail_attempt in range(1, 4):
        v_resp = client.post("/api/challenge/verify", json={"challenge_token": f"invalid_token_{fail_attempt}"})
        v_data = v_resp.json()
        print(f"Attempt #{fail_attempt} -> Status: {v_data.get('status')}, Failed Attempts: {v_data.get('failed_attempts')}, Is Blocked: {v_data.get('is_blocked')}")

    print(f"\n{Fore.RED}Checking fast-path gateway response for blocked IP:")
    blk_resp = client.get("/api/products")
    print_decision(blk_resp.json(), dict(blk_resp.headers), blk_resp.status_code)


if __name__ == "__main__":
    print_banner("OneChance Phase 3 Adaptive Defense Demonstration")
    print(f"{Fore.WHITE}Make sure OneChance API Gateway is running on http://localhost:8000")
    print(f"{Fore.WHITE}Starting test scenarios...\n")
    
    run_scenario_a()
    run_scenario_b()
    run_scenario_c()
    run_scenario_d()

    print_banner("Phase 3 Adaptive Defense Demonstration Completed")
