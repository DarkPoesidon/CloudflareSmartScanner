import os
import sys
import subprocess
import time
import socket
import ssl
import threading
import ipaddress
from urllib.parse import urlparse
from datetime import datetime
from collections import deque

# ==========================================
# 1. AUTO-DEPENDENCY MANAGER
# ==========================================
def ensure_dependencies():
    packages = ["aiohttp", "questionary", "rich"]
    for pkg in packages:
        try:
            __import__(pkg)
        except ImportError:
            print(f"[*] Missing library '{pkg}'. Installing automatically...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

ensure_dependencies()

import asyncio
import aiohttp
import questionary
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.live import Live

# ==========================================
# 2. GLOBAL CONFIGURATION & STATE
# ==========================================
TIMEOUT_SECS     = 10
MAX_CONCURRENT   = 80
RETRY_COUNT      = 2
LAST_PASSED_FILE = "last_passed.txt"

scanner_state = "RUNNING"
stats = {"done": 0, "total": 0, "open": 0, "dead": 0}
recent_hits = deque(maxlen=8)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept":          "text/html,application/xhtml+xml,*/*;q=0.9",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection":      "close",
}

# ==========================================
# 3. KEYBOARD LISTENER
# ==========================================
def kb_listener():
    """Listens for keyboard input natively without blocking the async loop."""
    global scanner_state
    if sys.platform == "win32":
        import msvcrt
        while scanner_state != "STOPPED":
            if msvcrt.kbhit():
                try:
                    char = msvcrt.getch().decode('utf-8', 'ignore').lower()
                    if char == 'q': scanner_state = "STOPPED"
                    elif char == 'p': scanner_state = "PAUSED"
                    elif char == 'r': scanner_state = "RUNNING"
                except Exception:
                    pass
            time.sleep(0.05)
    else:
        import tty, termios, select
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while scanner_state != "STOPPED":
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    char = sys.stdin.read(1).lower()
                    if char == 'q': scanner_state = "STOPPED"
                    elif char == 'p': scanner_state = "PAUSED"
                    elif char == 'r': scanner_state = "RUNNING"
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def parse_input(path: str) -> list[tuple[str, str]]:
    targets = []
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            
            lbl = ""
            val = line
            
            if "|" in line:
                lbl, val = line.split("|", 1)
                lbl = lbl.strip()
                val = val.strip()
            
            val = val.strip("'\"")

            # Handle CIDR IP Ranges (e.g., 104.18.2.0/24)
            if "/" in val and not val.startswith("http"):
                try:
                    network = ipaddress.ip_network(val, strict=False)
                    for ip in network.hosts(): 
                        ip_str = str(ip)
                        t_lbl = f"{lbl} {ip_str}" if lbl else ip_str
                        targets.append((t_lbl.strip(), f"https://{ip_str}"))
                    continue
                except ValueError:
                    pass 

            # Standard Domain / Single IP
            if val.startswith("http://") or val.startswith("https://"):
                url = val
                final_lbl = lbl if lbl else url.split("//", 1)[1].split("/")[0]
            else:
                url = "https://" + val
                final_lbl = lbl if lbl else val
            
            targets.append((final_lbl, url))
            
    return targets

# ==========================================
# 4. LAYERED VALIDATION ENGINE
# ==========================================
async def pre_flight_layer_check(url: str, timeout_val: int) -> str:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host: return "PARSE_ERR"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    
    loop = asyncio.get_running_loop()
    
    try:
        await asyncio.wait_for(loop.getaddrinfo(host, port), timeout=timeout_val)
    except Exception: return "DNS_FAILED"
        
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout_val)
        w.close()
        try: await w.wait_closed()
        except Exception: pass 
    except Exception: return "TCP_FAILED"
        
    if parsed.scheme == "https":
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout=timeout_val)
            w.close()
            try: await w.wait_closed()
            except Exception: pass
        except ssl.SSLError: return "TLS_FAILED"
        except Exception: return "TLS_CONN_FAILED"

    return "PASSED"

async def check_url(session: aiohttp.ClientSession, label: str, url: str, semaphore: asyncio.Semaphore):
    last_err = "UNKNOWN"

    while scanner_state == "PAUSED": await asyncio.sleep(0.5)
    if scanner_state == "STOPPED": return label, url, None, 0, "ABORTED"

    async with semaphore:
        # Accurate Timer: starts only after connection slot is acquired
        timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECS)
        start = time.monotonic() 
        
        while scanner_state == "PAUSED": await asyncio.sleep(0.5)
        if scanner_state == "STOPPED": return label, url, None, 0, "ABORTED"

        layer_timeout = max(3, TIMEOUT_SECS // 2)
        layer_status = await pre_flight_layer_check(url, timeout_val=layer_timeout)
        
        if layer_status != "PASSED":
            if url.startswith("https://"):
                http_url = "http://" + url[8:]
                fallback_status = await pre_flight_layer_check(http_url, timeout_val=layer_timeout)
                if fallback_status == "PASSED":
                    url = http_url 
                else:
                    return label, url, None, int((time.monotonic() - start) * 1000), layer_status
            else:
                return label, url, None, int((time.monotonic() - start) * 1000), layer_status

        for attempt in range(RETRY_COUNT + 1):
            while scanner_state == "PAUSED": await asyncio.sleep(0.5)
            if scanner_state == "STOPPED": return label, url, None, 0, "ABORTED"

            try:
                async with session.get(url, timeout=timeout, allow_redirects=True, ssl=False) as resp:
                    return label, url, resp.status, int((time.monotonic() - start) * 1000), None
            except asyncio.TimeoutError:
                last_err = "HTTP_TIMEOUT"
                if attempt < RETRY_COUNT:
                    await asyncio.sleep(0.3)
                    continue
                break
            except Exception as e:
                last_err = f"HTTP_ERR: {str(e)[:30]}"
                break

    return label, url, None, int((time.monotonic() - start) * 1000), last_err

# ==========================================
# 5. DASHBOARD UI BUILDER
# ==========================================
def status_label(status: int) -> str:
    if status < 300: return f"[green]HTTP {status} OK[/green]"
    if status < 400: return f"[cyan]HTTP {status} REDIR[/cyan]"
    if status < 500: return f"[yellow]HTTP {status} WARN[/yellow]"
    return f"[red]HTTP {status} ERR[/red]"

def format_latency(latency: int) -> str:
    if latency < 200: return f"[bold green]{latency}ms[/bold green]"
    if latency < 500: return f"[bold yellow]{latency}ms[/bold yellow]"
    return f"[bold red]{latency}ms[/bold red]"

def generate_dashboard(progress_table):
    stats_table = Table(show_header=True, expand=True, border_style="bright_blue")
    stats_table.add_column("Controls", justify="center")
    stats_table.add_column("State", justify="center", width=12)
    stats_table.add_column("UP", justify="center", style="bold green", width=10)
    stats_table.add_column("DOWN", justify="center", style="bold red", width=10)
    
    state_color = "cyan" if scanner_state == "RUNNING" else ("yellow" if scanner_state == "PAUSED" else "red")
    stats_table.add_row(
        "[bold white]\[P][/bold white] Pause  •  [bold white]\[R][/bold white] Resume  •  [bold white]\[Q][/bold white] Stop & Save",
        f"[bold {state_color}]{scanner_state}[/]",
        str(stats["open"]),
        str(stats["dead"])
    )

    hits_table = Table(show_header=True, expand=True, border_style="bright_black")
    hits_table.add_column("Latency", justify="right", width=12)
    hits_table.add_column("Status", justify="left", width=15)
    hits_table.add_column("Label", justify="left", style="white")
    hits_table.add_column("URL", justify="left", style="bright_black")
    
    for lat, stat, lbl, url in recent_hits:
        hits_table.add_row(format_latency(lat), stat, lbl, url)
        
    for _ in range(8 - len(recent_hits)):
        hits_table.add_row("-", "-", "-", "-")

    return Panel(
        Group(
            progress_table,
            Text(""),
            stats_table,
            Text("\nRecent Active Nodes:", style="bold bright_black"),
            hits_table
        ),
        title="[bold blue]🚀 MASTER DNS VPN SCANNER ENTERPRISE[/bold blue]",
        border_style="blue",
        padding=(1, 2)
    )

# ==========================================
# 6. MAIN EXECUTION MENU
# ==========================================
async def main():
    global scanner_state

    os.system('cls' if os.name == 'nt' else 'clear')
    console = Console()
    console.print(Panel("[bold cyan]ENTERPRISE REACHABILITY SCANNER[/bold cyan]\nWelcome to the dashboard setup.", border_style="cyan"))

    input_file = await questionary.text(
        "Enter target list file (e.g., domains.txt):", 
        default="domains.txt"
    ).ask_async()

    if not input_file or not os.path.exists(input_file):
        console.print(f"[red][-] Error: Could not find file '{input_file}'[/red]")
        sys.exit(1)

    c_val = await questionary.text(
        "Enter concurrent connections limit (Default: 80):",
        default="80"
    ).ask_async()
    
    current_max_concurrent = int(c_val) if c_val and c_val.isdigit() else MAX_CONCURRENT

    prioritized_targets = []
    if os.path.exists(LAST_PASSED_FILE):
        try:
            prioritized_targets = parse_input(LAST_PASSED_FILE)
            console.print(f"[green][+] Cache: Loaded {len(prioritized_targets)} prioritized targets.[/green]")
        except Exception:
            pass

    try:
        main_targets = parse_input(input_file)
    except Exception as e:
        console.print(f"[red][-] Could not read {input_file}: {e}[/red]")
        sys.exit(1)

    seen = set()
    TARGETS = []
    for lbl, url in prioritized_targets + main_targets:
        if url not in seen:
            seen.add(url)
            TARGETS.append((lbl, url))

    if not TARGETS:
        console.print("[red][-] No valid targets found to scan.[/red]")
        sys.exit(1)

    stats["total"] = len(TARGETS)
    open_results, dead_results = [], []

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    open_file = f"reachable_{timestamp}.txt"
    full_file = f"full_log_{timestamp}.txt"

    connector = aiohttp.TCPConnector(ssl=False, limit=current_max_concurrent, ttl_dns_cache=300, limit_per_host=2)
    semaphore = asyncio.Semaphore(current_max_concurrent)

    os.system('cls' if os.name == 'nt' else 'clear')

    threading.Thread(target=kb_listener, daemon=True).start()

    progress = Progress(
        "[progress.description]{task.description}",
        BarColumn(bar_width=40),
        "[progress.percentage]{task.percentage:>3.0f}%",
        "•",
        TextColumn("[cyan]{task.completed}/{task.total}[/cyan]"),
        "•",
        TimeElapsedColumn(),
        "•",
        TimeRemainingColumn()
    )
    task_id = progress.add_task("[bold white]Scanning Network...", total=stats["total"])

    async def ui_loop(live_ctx):
        while scanner_state != "STOPPED" and stats["done"] < stats["total"]:
            progress.update(task_id, completed=stats["done"])
            live_ctx.update(generate_dashboard(progress))
            await asyncio.sleep(0.1)

    with Live(generate_dashboard(progress), console=console, refresh_per_second=10, screen=True) as live:
        ui_task = asyncio.create_task(ui_loop(live))

        async with aiohttp.ClientSession(connector=connector, headers=HEADERS) as session:
            tasks = [asyncio.create_task(check_url(session, lbl, url, semaphore)) for lbl, url in TARGETS]

            for coro in asyncio.as_completed(tasks):
                res = await coro
                label, url, status, latency, error = res
                
                if error == "ABORTED":
                    continue 
                
                stats["done"] += 1

                if status is not None:
                    open_results.append((label, url, status, latency))
                    stats["open"] += 1
                    recent_hits.append((latency, status_label(status), label, url))
                else:
                    dead_results.append((label, url, error, latency))
                    stats["dead"] += 1

        scanner_state = "STOPPED"
        await ui_task
        progress.update(task_id, completed=stats["done"])
        live.update(generate_dashboard(progress))

    actual_tested = len(open_results) + len(dead_results)
    if actual_tested == 0:
        console.print("\n[yellow][-] Scan was aborted before any results were collected.[/yellow]")
        sys.exit(0)
    
    open_results.sort(key=lambda x: x[3])   
    
    with open(open_file, "w", encoding="utf-8") as f:
        f.write("Reachability Report — OPEN SITES\n")
        f.write(f"Generated        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total tested     : {actual_tested} / {stats['total']}\n")
        f.write(f"Open (reachable) : {len(open_results)}\n")
        f.write(f"Closed / Dead    : {len(dead_results)}\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"{'#':<4}  {'Latency':>8}  {'HTTP':>5}  {'Label':<40}  URL\n")
        f.write("-" * 80 + "\n")
        for i, (label, url, status, latency) in enumerate(open_results, 1):
            f.write(f"{i:<4}  {latency:>6}ms  {status:>5}  {label:<40}  {url}\n")
        f.write("\n\n" + "=" * 80 + "\n")
        f.write("CLOSED / UNREACHABLE (DNS/TCP/TLS/HTTP Errors)\n")
        f.write("=" * 80 + "\n")
        for label, url, error, latency in sorted(dead_results, key=lambda x: x[0]):
            f.write(f"  {label:<40}  [{error}]\n")

    with open(LAST_PASSED_FILE, "w", encoding="utf-8") as f:
        f.write("# Auto-saved cache of last passed domains\n")
        for label, url, _, _ in open_results:
            f.write(f"{label} | {url}\n")

    all_rows = (
        [(lbl, url, str(st), lat, "OPEN") for lbl, url, st, lat in open_results] +
        [(lbl, url, err or "DEAD", lat, "DEAD") for lbl, url, err, lat in dead_results]
    )
    all_rows.sort(key=lambda x: x[0])
    with open(full_file, "w", encoding="utf-8") as f:
        f.write("Reachability Report — FULL LOG\n")
        f.write(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"{'Tag':<6}  {'Latency':>8}  {'HTTP/Err':<15}  {'Label':<35}  URL\n")
        f.write("-" * 80 + "\n")
        for lbl, url, s, lat, tag in all_rows:
            f.write(f"{tag:<6}  {lat:>6}ms  {s:<15}  {lbl:<35}  {url}\n")

    pct = len(open_results) / actual_tested * 100 if actual_tested else 0
    console.print(f"\n[bold green]DONE[/bold green] — {len(open_results)}/{actual_tested} reachable ({pct:.1f}%)")
    if actual_tested < stats['total']:
        console.print(f"[bold yellow][!] SCAN ABORTED EARLY - Saved {actual_tested} completed tests.[/bold yellow]")
    console.print(f"[cyan][+][/cyan] Cache updated → {LAST_PASSED_FILE}")
    console.print(f"[cyan][+][/cyan] Open results  → {open_file}")
    console.print(f"[cyan][+][/cyan] Full log      → {full_file}\n")


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Force interrupted by user (Ctrl+C).")
        sys.exit(1)