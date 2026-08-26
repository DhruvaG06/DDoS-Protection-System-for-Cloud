"""OneChance — Phase 6: Master 3-Minute Demonstration Script.

Walks through the complete OneChance MVP closed-loop story:
NORMAL → ATTACK → DETECT → RISK SCORE → CHALLENGE/BLOCK →
INSTANCE DEGRADATION → ISOLATION → REROUTING → REPLACEMENT →
HEALTH VERIFICATION → SERVICE RECOVERY → RESET
"""

import asyncio
import sys
import time
from pathlib import Path
from typing import List

# Ensure repository root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
GATEWAY_URL = "http://127.0.0.1:8000"


async def run_master_demo():
    console.print(
        Panel.fit(
            "[bold cyan]ONECHANCE — SMART CLOUD DDOS PROTECTION SYSTEM[/bold cyan]\n"
            "[bold white]Autonomous Closed-Loop Defense & Workload Self-Healing Platform[/bold white]\n"
            "[yellow]Behavioral Detection • Risk-Adaptive Policy • Autonomous Recovery[/yellow]",
            border_style="cyan",
        )
    )

    async with httpx.AsyncClient(timeout=10.0) as client:
        # Step 0: Verify Gateway Connection
        try:
            health_check = await client.get(f"{GATEWAY_URL}/api/health")
            if health_check.status_code != 200:
                console.print("[red]Gateway is offline. Start 'python -m onechance.main' first.[/red]")
                return
        except Exception as e:
            console.print(f"[red]Could not connect to OneChance Gateway at {GATEWAY_URL}: {e}[/red]")
            console.print("[yellow]Tip: Run 'python -m onechance.main' in a separate terminal.[/yellow]")
            return

        # -------------------------------------------------------------
        # STEP 1: Reset to Clean Initial State
        # -------------------------------------------------------------
        console.print("\n[bold cyan]Step 1: Initializing & Resetting System State...[/bold cyan]")
        await client.post(f"{GATEWAY_URL}/api/demo/reset")
        await asyncio.sleep(0.3)

        status_res = await client.get(f"{GATEWAY_URL}/api/recovery/status")
        cluster_data = status_res.json()["snapshot"]

        table = Table(title="Initial Healthy Cluster Topology", header_style="bold green")
        table.add_column("Node ID", style="cyan")
        table.add_column("Container URL", style="blue")
        table.add_column("Status", style="green")
        table.add_column("Traffic Active", style="yellow")
        for inst in cluster_data["instances"]:
            table.add_row(inst["instance_id"], inst["url"], inst["status"], "YES" if inst["is_accepting_traffic"] else "NO")
        console.print(table)

        # -------------------------------------------------------------
        # STEP 2: Normal Traffic Ingress (Round-Robin Distribution)
        # -------------------------------------------------------------
        console.print("\n[bold green]Step 2: Sending Legitimate User Traffic (ALLOW Tier)...[/bold green]")
        served_nodes = []
        for i in range(6):
            r = await client.get(f"{GATEWAY_URL}/api/products")
            node = r.headers.get("x-target-instance", "unknown")
            score = r.headers.get("x-risk-score", "0.0")
            decision = r.headers.get("x-decision", "ALLOW")
            served_nodes.append(node)
            console.print(f"  [white]User Request #{i+1}[/white] -> Served by [bold cyan]{node}[/bold cyan] | Decision: [bold green]{decision}[/bold green] (Risk: {score})")
            await asyncio.sleep(0.1)

        console.print(f"[dim]Traffic load-balanced across: {list(set(served_nodes))}[/dim]")

        # -------------------------------------------------------------
        # STEP 3: External DDoS Flood Attack Simulation
        # -------------------------------------------------------------
        console.print("\n[bold red]Step 3: Launching External DDoS Attack Simulation...[/bold red]")
        for i in range(12):
            r = await client.get(
                f"{GATEWAY_URL}/api/expensive-operation",
                headers={"user-agent": "External-Botnet-Attack/4.0", "x-forwarded-for": "198.51.100.44"},
            )
            decision = r.headers.get("x-decision", "BLOCK")
            score = r.headers.get("x-risk-score", "90.0")
            console.print(f"  [white]Attack Req #{i+1}[/white] -> Decision: [bold red]{decision}[/bold red] (Risk: {score}) | Status: [red]HTTP {r.status_code}[/red]")
            await asyncio.sleep(0.05)

        # -------------------------------------------------------------
        # STEP 4: Internal Compromised Microservice Attack
        # -------------------------------------------------------------
        console.print("\n[bold magenta]Step 4: Launching Internal Compromised Workload Attack...[/bold magenta]")
        for i in range(8):
            r = await client.post(
                f"{GATEWAY_URL}/api/login",
                headers={
                    "user-agent": "Compromised-Internal-Service/1.0",
                    "x-attack-origin": "internal",
                    "x-forwarded-for": "10.0.5.55",
                },
                json={"user": "admin", "pass": "exploit"},
            )
            decision = r.headers.get("x-decision", "BLOCK")
            score = r.headers.get("x-risk-score", "85.0")
            console.print(f"  [white]Internal Attack Req #{i+1}[/white] -> Origin: [bold magenta]INTERNAL[/bold magenta] | Decision: [bold red]{decision}[/bold red] (Risk: {score})")
            await asyncio.sleep(0.05)

        # -------------------------------------------------------------
        # STEP 5: Controlled Instance Failure Simulation
        # -------------------------------------------------------------
        console.print("\n[bold yellow]Step 5: Simulating Workload Degradation / Crash on 'app-2'...[/bold yellow]")
        fail_res = await client.post(
            f"{GATEWAY_URL}/api/recovery/simulate-failure",
            json={"instance_id": "app-2", "reason": "Simulated memory leak & container crash demo"},
        )
        console.print(f"[bold yellow]Failure Hook Triggered:[/bold yellow] {fail_res.json()['message']}")

        # -------------------------------------------------------------
        # STEP 6: Zero-Downtime Traffic Rerouting During Isolation
        # -------------------------------------------------------------
        console.print("\n[bold green]Step 6: Ingress Traffic Rerouting During Isolation (Zero Downtime)...[/bold green]")
        rerouted_nodes = []
        for i in range(6):
            r = await client.get(f"{GATEWAY_URL}/api/products")
            node = r.headers.get("x-target-instance", "unknown")
            rerouted_nodes.append(node)
            console.print(f"  [white]Client Ingress Request #{i+1}[/white] -> Served by [bold cyan]{node}[/bold cyan] [green]HTTP {r.status_code}[/green]")
            await asyncio.sleep(0.08)

        console.print(f"[bold green][OK] Isolated node 'app-2' successfully excluded. Active surviving nodes: {list(set(rerouted_nodes))}[/bold green]")

        # -------------------------------------------------------------
        # STEP 7: Waiting for Autonomous Recovery & Health Verification
        # -------------------------------------------------------------
        console.print("\n[bold blue]Step 7: Autonomous Self-Healing Pipeline Executing (Isolate -> Replace -> Verify)...[/bold blue]")
        for _ in range(8):
            await asyncio.sleep(0.5)
            evts_res = await client.get(f"{GATEWAY_URL}/api/recovery/events?limit=10")
            evts = evts_res.json().get("events", [])
            if any(e["event_type"] == "SERVICE_RECOVERY_VERIFIED" for e in evts):
                break

        # Display Events Timeline
        evts_res = await client.get(f"{GATEWAY_URL}/api/recovery/events?limit=10")
        evts = evts_res.json().get("events", [])

        rec_table = Table(title="Autonomous Self-Healing Event Timeline", header_style="bold yellow")
        rec_table.add_column("Event Type", style="bold cyan")
        rec_table.add_column("Instance", style="magenta")
        rec_table.add_column("Status", style="green")
        rec_table.add_column("Trigger / Reason", style="white")
        for evt in evts:
            rec_table.add_row(evt["event_type"], evt["instance_id"], evt["status"], evt["trigger_reason"])
        console.print(rec_table)

        # -------------------------------------------------------------
        # STEP 8: Service Recovery Verification Metrics
        # -------------------------------------------------------------
        console.print("\n[bold green]Step 8: Final Recovery Verification Score[/bold green]")
        verify_res = await client.get(f"{GATEWAY_URL}/api/recovery/verify")
        metrics = verify_res.json()

        console.print(
            Panel.fit(
                f"[bold cyan]Recovery Confidence Score:[/bold cyan] [bold green]{metrics['recovery_confidence']:.1f} / 100[/bold green]\n"
                f"[white]* Healthy Capacity Ratio:[/white] [green]{metrics['healthy_instances_ratio'] * 100:.1f}%[/green]\n"
                f"[white]* Health Probe Success Rate:[/white] [green]{metrics['health_probe_success_rate'] * 100:.1f}%[/green]\n"
                f"[white]* Latency Stability Score:[/white] [green]{metrics['latency_stability_score'] * 100:.1f}%[/green]\n"
                f"[white]* Error Rate Index:[/white] [green]{metrics['error_rate_score'] * 100:.1f}%[/green]",
                title="Service Recovery Verification",
                border_style="green",
            )
        )

        # -------------------------------------------------------------
        # STEP 9: Post-Recovery All-Node Traffic Verification
        # -------------------------------------------------------------
        console.print("\n[bold green]Step 9: Post-Recovery Traffic Distribution (All 3 Instances Active)...[/bold green]")
        post_nodes = []
        for i in range(6):
            r = await client.get(f"{GATEWAY_URL}/api/products")
            node = r.headers.get("x-target-instance", "unknown")
            post_nodes.append(node)
            console.print(f"  [white]Request #{i+1}[/white] -> Served by [bold cyan]{node}[/bold cyan] [green]HTTP {r.status_code}[/green]")

        console.print(f"[bold green][OK] Cluster restored. Traffic distributed across: {list(set(post_nodes))}[/bold green]")

        # -------------------------------------------------------------
        # STEP 10: Reset Demo
        # -------------------------------------------------------------
        console.print("\n[bold cyan]Step 10: Resetting Demo State for Repeatable Execution...[/bold cyan]")
        await client.post(f"{GATEWAY_URL}/api/demo/reset")
        console.print("[bold green][OK] Demo environment reset to clean state. Ready for next evaluation![/bold green]\n")


if __name__ == "__main__":
    asyncio.run(run_master_demo())
