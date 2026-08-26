"""OneChance — Phase 4: Autonomous Self-Healing & Service Recovery Interactive Demo.

Demonstrates OneChance's Core USP:
DDoS protection does not end when traffic is blocked; OneChance isolates unhealthy workloads,
reroutes traffic, restores healthy capacity, and verifies full service recovery.

Closed-Loop Workflow:
DETECT → ISOLATE → REROUTE → REPLACE → HEALTH CHECK → REINTRODUCE → VERIFY RECOVERY
"""

import asyncio
import time
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

GATEWAY_URL = "http://localhost:8000"


async def run_phase4_demo():
    console.print(
        Panel.fit(
            "[bold cyan]ONECHANCE — PHASE 4 DEMONSTRATION[/bold cyan]\n"
            "[bold white]Autonomous Self-Healing & Service Recovery[/bold white]\n"
            "[yellow]Detect → Isolate → Reroute → Replace → Health Check → Reintroduce → Verify[/yellow]",
            border_style="cyan",
        )
    )

    async with httpx.AsyncClient(timeout=10.0) as client:
        # Step 0: Check Gateway connection
        try:
            health_resp = await client.get(f"{GATEWAY_URL}/api/health")
            if health_resp.status_code != 200:
                console.print("[red]Gateway is not running on http://localhost:8000. Please start onechance.main first.[/red]")
                return
        except Exception as e:
            console.print(f"[red]Could not connect to Gateway at {GATEWAY_URL}: {e}[/red]")
            console.print("[yellow]Tip: Run 'python -m onechance.main' in another terminal first.[/yellow]")
            return

        # Reset state for fresh demo
        await client.post(f"{GATEWAY_URL}/api/recovery/reset")
        time.sleep(0.5)

        # -------------------------------------------------------------
        # STEP 1: Inspect Initial Cluster State
        # -------------------------------------------------------------
        console.print("\n[bold green]Step 1: Inspecting Initial Multi-Instance Cluster State...[/bold green]")
        status_resp = await client.get(f"{GATEWAY_URL}/api/recovery/status")
        status_data = status_resp.json()

        table = Table(title="Initial Managed Cluster State", header_style="bold magenta")
        table.add_column("Instance ID", style="cyan")
        table.add_column("Container URL", style="blue")
        table.add_column("Status", style="green")
        table.add_column("Accepting Traffic", style="yellow")
        table.add_column("Latency (ms)", style="white")

        for inst in status_data["snapshot"]["instances"]:
            table.add_row(
                inst["instance_id"],
                inst["url"],
                inst["status"],
                "YES" if inst["is_accepting_traffic"] else "NO",
                f"{inst['average_latency_ms']:.1f}",
            )
        console.print(table)

        # -------------------------------------------------------------
        # STEP 2: Send Normal Ingress Traffic (Round-Robin Distribution)
        # -------------------------------------------------------------
        console.print("\n[bold green]Step 2: Sending Ingress Requests Through Gateway...[/bold green]")
        served_nodes = []
        for i in range(6):
            resp = await client.get(f"{GATEWAY_URL}/api/products")
            node = resp.headers.get("x-target-instance", "unknown")
            served_nodes.append(node)
            console.print(f"  [white]Request #{i+1}[/white] -> Served by [bold cyan]{node}[/bold cyan] [green]HTTP {resp.status_code}[/green]")

        console.print(f"[dim]Traffic distributed across: {list(set(served_nodes))}[/dim]")

        # -------------------------------------------------------------
        # STEP 3: Trigger Deterministic Failure Simulation on app-2
        # -------------------------------------------------------------
        console.print("\n[bold red]Step 3: Triggering Controlled Failure Simulation on 'app-2'...[/bold red]")
        console.print("[yellow]Simulating container crash / resource starvation on node app-2...[/yellow]")
        fail_resp = await client.post(
            f"{GATEWAY_URL}/api/recovery/simulate-failure",
            json={"instance_id": "app-2", "reason": "Simulated memory leak & container crash"},
        )
        console.print(f"[bold red]Failure Event Registered:[/bold red] {fail_resp.json()['message']}")

        # -------------------------------------------------------------
        # STEP 4: Traffic Rerouting During Isolation
        # -------------------------------------------------------------
        console.print("\n[bold yellow]Step 4: Testing Ingress Traffic During Isolation (Zero Downtime)...[/bold yellow]")
        rerouted_nodes = []
        for i in range(4):
            resp = await client.get(f"{GATEWAY_URL}/api/products")
            node = resp.headers.get("x-target-instance", "unknown")
            rerouted_nodes.append(node)
            console.print(f"  [white]Client Request #{i+1}[/white] -> Served by [bold cyan]{node}[/bold cyan] [green]HTTP {resp.status_code}[/green]")

        console.print(f"[bold green]✓ Traffic seamlessly rerouted across healthy nodes: {list(set(rerouted_nodes))}[/bold green]")
        assert "app-2" not in rerouted_nodes, "Isolated node should not serve traffic!"

        # Wait briefly for autonomous recovery pipeline to complete health verification
        console.print("\n[bold blue]Step 5: Waiting for Autonomous Recovery Pipeline to Complete...[/bold blue]")
        for _ in range(5):
            await asyncio.sleep(0.6)
            events_resp = await client.get(f"{GATEWAY_URL}/api/recovery/events?limit=10")
            events = events_resp.json()["events"]
            if any(e["event_type"] == "SERVICE_RECOVERY_VERIFIED" for e in events):
                break

        # -------------------------------------------------------------
        # STEP 6: Display Structured Recovery Event Timeline
        # -------------------------------------------------------------
        events_resp = await client.get(f"{GATEWAY_URL}/api/recovery/events?limit=10")
        events = events_resp.json()["events"]

        event_table = Table(title="Autonomous Self-Healing Event Timeline", header_style="bold cyan")
        event_table.add_column("Event Type", style="bold yellow")
        event_table.add_column("Instance", style="magenta")
        event_table.add_column("Status", style="green")
        event_table.add_column("Explainability Reason / Details", style="white")

        for evt in events:
            event_table.add_row(
                evt["event_type"],
                evt["instance_id"],
                evt["status"],
                evt["trigger_reason"],
            )
        console.print(event_table)

        # -------------------------------------------------------------
        # STEP 7: Recovery Verification & Confidence Score
        # -------------------------------------------------------------
        console.print("\n[bold green]Step 7: Service Recovery Verification Metrics[/bold green]")
        verify_resp = await client.get(f"{GATEWAY_URL}/api/recovery/verify")
        metrics = verify_resp.json()

        console.print(
            Panel.fit(
                f"[bold cyan]Operational Recovery Confidence:[/bold cyan] [bold green]{metrics['recovery_confidence']:.1f} / 100[/bold green]\n"
                f"[white]• Healthy Capacity Ratio:[/white] [green]{metrics['healthy_instances_ratio'] * 100:.1f}%[/green]\n"
                f"[white]• Health Probe Success Rate:[/white] [green]{metrics['health_probe_success_rate'] * 100:.1f}%[/green]\n"
                f"[white]• Latency Stability Score:[/white] [green]{metrics['latency_stability_score'] * 100:.1f}%[/green]\n"
                f"[white]• Error Rate Index:[/white] [green]{metrics['error_rate_score'] * 100:.1f}%[/green]\n"
                f"[dim]Verified at {metrics['verified_at']}[/dim]",
                title="Service Recovery Verification Summary",
                border_style="green",
            )
        )

        # -------------------------------------------------------------
        # STEP 8: Post-Recovery Ingress Traffic Test
        # -------------------------------------------------------------
        console.print("\n[bold green]Step 8: Post-Recovery Traffic Ingress (All 3 Nodes Active)...[/bold green]")
        post_nodes = []
        for i in range(6):
            resp = await client.get(f"{GATEWAY_URL}/api/products")
            node = resp.headers.get("x-target-instance", "unknown")
            post_nodes.append(node)
            console.print(f"  [white]Request #{i+1}[/white] -> Served by [bold cyan]{node}[/bold cyan] [green]HTTP {resp.status_code}[/green]")

        console.print(f"[bold green]✓ Full capacity restored. Traffic distributed across: {list(set(post_nodes))}[/bold green]\n")


if __name__ == "__main__":
    asyncio.run(run_phase4_demo())
