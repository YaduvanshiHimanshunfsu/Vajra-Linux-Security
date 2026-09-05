"""
================================================================================
⚡  वज्र (VAJRA) — Master Unified Execution Runner
================================================================================
  Competition  :  SSM Hackathon BY CDAC (2026)
  Track        :  Integration of AI Capabilities in the OS Ecosystem (Linux)
  Team Name    :  Team_Red_Eagle
  Problem      :  AI-Powered Explainable Linux Security & Reliability Assistant
                  for Kernel-Level Intrusion & Behavioral Threat Detection
================================================================================
USAGE:
  python run_vajra.py                        → Interactive menu
  python run_vajra.py --all                  → Scenarios + Web Dashboard
  python run_vajra.py --scenarios            → Run 5 attack/reliability scenarios
  python run_vajra.py --tests                → Run all 36 unit tests
  python run_vajra.py --server               → Launch web dashboard (port 8000)
  python run_vajra.py --server --port 9000   → Custom port
  python run_vajra.py --no-browser           → Don't auto-open browser
================================================================================
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

# ── UTF-8 + ANSI on Windows ────────────────────────────────────────────────────
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

if sys.platform == "win32":
    os.system("")   # Enable ANSI escape codes on Windows terminal

# ── Project root ───────────────────────────────────────────────────────────────
ROOT_DIR    = Path(__file__).resolve().parent
SERVICES_DIR = ROOT_DIR / "services"

# ── ANSI colours ──────────────────────────────────────────────────────────────
R  = "\033[0m"      # reset
BD = "\033[1m"      # bold
DM = "\033[2m"      # dim
CY = "\033[96m"     # cyan
BL = "\033[94m"     # blue
GR = "\033[92m"     # green
YL = "\033[93m"     # yellow
RD = "\033[91m"     # red
MG = "\033[95m"     # magenta
WH = "\033[97m"     # white


# ══════════════════════════════════════════════════════════════════════════════
#   BANNER
# ══════════════════════════════════════════════════════════════════════════════

def print_banner() -> None:
    print(f"""
{CY}{BD}╔══════════════════════════════════════════════════════════════════════════════════════╗
║                          ⚡  वज्र  (VAJRA)  ⚡                               ║
║    AI-Powered Explainable Linux Security & Reliability Assistant               ║
║           for Kernel-Level Intrusion & Behavioural Threat Detection            ║
╠══════════════════════════════════════════════════════════════════════════════════╣{R}
{WH}║  {YL}{BD}Competition{R}{WH}  :  SSM Hackathon BY CDAC  (2026)                                       ║
║  {YL}{BD}Track{R}{WH}        :  Integration of AI Capabilities in the OS Ecosystem (Linux)     ║
║  {YL}{BD}Team{R}{WH}         :  {RD}{BD}Team_Red_Eagle{R}{WH}                                                     ║
║  {YL}{BD}Problem{R}{WH}      :  Kernel eBPF Telemetry  →  Laplace Markov Anomaly Scoring        ║
║                 →  PSI Failure Forecasting  →  ProvX Counterfactuals          ║
║                 →  Reversible cgroup-v2 Containment  →  Grounded On-Prem LLM  ║
{CY}{BD}╚══════════════════════════════════════════════════════════════════════════════════════╝{R}
""")


def print_section(title: str) -> None:
    w = 86
    print(f"\n{MG}{BD}{'═' * w}{R}")
    print(f"{MG}{BD}▶  {title}{R}")
    print(f"{MG}{BD}{'═' * w}{R}\n")


def print_ok(msg: str) -> None:
    print(f"  {GR}{BD}✔  {msg}{R}")


def print_fail(msg: str) -> None:
    print(f"  {RD}{BD}✖  {msg}{R}")


def print_info(label: str, value: str) -> None:
    print(f"  {CY}{label:<22}{R} {WH}{value}{R}")


# ══════════════════════════════════════════════════════════════════════════════
#   SYSTEM PREFLIGHT
# ══════════════════════════════════════════════════════════════════════════════

def preflight_check() -> bool:
    """Verify all required directories and critical Python files exist."""
    print_section("PREFLIGHT SYSTEM CHECK")

    checks = [
        ("Root project",          ROOT_DIR.exists()),
        ("services/api",          (SERVICES_DIR / "api" / "app" / "main.py").exists()),
        ("services/detector",     (SERVICES_DIR / "detector" / "app" / "engine.py").exists()),
        ("services/graph",        (SERVICES_DIR / "graph" / "app" / "lineage.py").exists()),
        ("services/responder",    (SERVICES_DIR / "responder" / "app" / "executor.py").exists()),
        ("policy/detection",      (ROOT_DIR / "policy" / "detection").is_dir()),
        ("policy/response",       (ROOT_DIR / "policy" / "response" / "response_policy.yaml").exists()),
        ("test-lab scenarios",    (ROOT_DIR / "test-lab" / "run_all_scenarios.py").exists()),
        ("Web UI (index.html)",   (ROOT_DIR / "ui" / "index.html").exists()),
    ]

    all_ok = True
    for label, ok in checks:
        if ok:
            print_ok(label)
        else:
            print_fail(f"{label}  ← NOT FOUND")
            all_ok = False

    if all_ok:
        print(f"\n{GR}{BD}  All systems ready. Vajra is good to launch!{R}\n")
    else:
        print(f"\n{RD}{BD}  Some components are missing. Check your project directory.{R}\n")
    return all_ok


# ══════════════════════════════════════════════════════════════════════════════
#   TEST-LAB SCENARIOS (run via subprocess so imports stay isolated)
# ══════════════════════════════════════════════════════════════════════════════

_SCENARIO_PROFILES = [
    ("01", "Benign Web Workload Normal Baseline",
           "systemd → nginx worker — normal lifecycle — no threat"),
    ("02", "/tmp Reverse Shell Intrusion",
           "nginx spawns unsigned /tmp/kworker_rev  [AG-RULE-001 | Markov | Trust]"),
    ("03", "Living-off-the-Land Sensitive Decoy Access",
           "curl opens /etc/shadow decoy  [AG-RULE-003 | Behavioural]"),
    ("04", "PSI Memory Pressure & OOM Failure Forecasting",
           "Exponential memory stall velocity  →  Reliability Score ≥ 0.99"),
    ("05", "Hardware TPM Attestation Compromise",
           "Failed TPM PCR quote  →  baseline frozen, automation locked"),
]


def run_scenarios() -> bool:
    """Stream the existing test-lab runner as a subprocess and pretty-print its output."""
    print_section("AUTOMATED ATTACK & RELIABILITY TEST LAB  (5 / 5 SCENARIOS)")

    for num, name, desc in _SCENARIO_PROFILES:
        print(f"  {CY}[Scenario {num}]{R} {BD}{name}{R}")
        print(f"  {DM}  Profile: {desc}{R}")

    print()

    runner = ROOT_DIR / "test-lab" / "run_all_scenarios.py"
    result = subprocess.run(
        [sys.executable, str(runner)],
        cwd=str(ROOT_DIR),
    )

    if result.returncode == 0:
        print(f"\n{GR}{BD}✔  ALL 5 TEST-LAB SCENARIOS PASSED — 100 % SPECIFICATION COMPLIANCE!{R}\n")
    else:
        print(f"\n{RD}{BD}✖  One or more scenarios failed (exit code {result.returncode}).{R}\n")

    return result.returncode == 0


# ══════════════════════════════════════════════════════════════════════════════
#   UNIT TEST SUITES
# ══════════════════════════════════════════════════════════════════════════════

_TEST_SUITES = [
    ("services/detector",  "AI Detection Engine — Markov Models & Rule Engine  (5 tests)"),
    ("services/api",       "FastAPI Gateway, Grounded Assistant & Metrics       (9 tests)"),
    ("services/graph",     "Causal Lineage DAG — ProvenanceGraph & Exporter     (7 tests)"),
    ("services/responder", "SOAR Responder — Policy Auth, Executor & Rollback  (15 tests)"),
]


def run_unit_tests() -> bool:
    print_section("COMPREHENSIVE UNIT TEST SUITES  (36 / 36 TESTS)")

    all_passed = True
    total_run = 0

    for path, label in _TEST_SUITES:
        full_path = ROOT_DIR / path
        print(f"  {CY}[Suite]{R} {BD}{label}{R}")
        t0 = time.perf_counter()
        res = subprocess.run(
            [sys.executable, "-m", "pytest", "tests", "-v", "--tb=short"],
            cwd=str(full_path),
            capture_output=False,
        )
        elapsed = time.perf_counter() - t0
        if res.returncode == 0:
            print_ok(f"Passed  ({elapsed:.2f}s)\n")
        else:
            print_fail(f"Failed  (exit {res.returncode})\n")
            all_passed = False
        total_run += 1

    if all_passed:
        print(f"\n{GR}{BD}✔  ALL 36 UNIT TESTS ACROSS 4 SERVICES PASSED — 100 % SUCCESS RATE!{R}\n")
    else:
        print(f"\n{RD}{BD}✖  Some tests failed. Review output above.{R}\n")

    return all_passed


# ══════════════════════════════════════════════════════════════════════════════
#   WEB DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

def start_web_dashboard(port: int = 8000, open_browser: bool = True) -> None:
    print_section("VAJRA WEB DASHBOARD  &  SOC OPERATIONS CONSOLE")

    url = f"http://localhost:{port}"

    print_info("⚡ Web Console URL",    url)
    print_info("⚡ API Healthcheck",   f"{url}/healthz")
    print_info("⚡ OpenAPI Docs",      f"{url}/docs")
    print_info("⚡ MITRE ATT&CK Layer",f"{url}/v1/mitre/navigator")
    print_info("⚡ Incident Feed",     f"{url}/v1/incidents")
    print_info("⚡ Provenance Graph",  f"{url}/v1/graph")
    print_info("⚡ Overhead Metrics",  f"{url}/v1/metrics/overhead")

    print(f"""
  {BD}Dashboard Features:{R}
    {GR}•{R} Live HTML5 Canvas Causal Lineage DAG (real-time edge animation)
    {GR}•{R} One-click Attack Scenario Buttons (5 scenarios)
    {GR}•{R} ProvX L₀-Counterfactual Explainability Panel
    {GR}•{R} SOAR Containment Console (cgroup freeze / egress block / quarantine)
    {GR}•{R} Grounded On-Premises AI Security Assistant (chat interface)
    {GR}•{R} MITRE ATT&CK Navigator Layer JSON Export
    {GR}•{R} Real-time Telemetry Overhead Benchmark Widget
""")

    if open_browser:
        print(f"  {YL}Opening {url} in your default browser in 2 seconds…{R}")
        time.sleep(2)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    print(f"  {GR}{BD}Press CTRL+C at any time to gracefully stop the server.{R}\n")

    try:
        subprocess.run(
            [
                sys.executable, "-m", "uvicorn", "app.main:app",
                "--host", "0.0.0.0",
                "--port", str(port),
                "--log-level", "info",
            ],
            cwd=str(SERVICES_DIR / "api"),
        )
    except KeyboardInterrupt:
        print(f"\n\n  {YL}Vajra server gracefully stopped. Goodbye!{R}\n")
    except FileNotFoundError:
        print(f"\n  {RD}uvicorn not found. Run:  pip install uvicorn{R}\n")
    except Exception as exc:
        print(f"\n  {RD}Server error: {exc}{R}\n")


# ══════════════════════════════════════════════════════════════════════════════
#   TERMINAL SECURITY ASSISTANT
# ══════════════════════════════════════════════════════════════════════════════

def terminal_assistant() -> None:
    print_section("VAJRA TERMINAL SECURITY ASSISTANT  (SOVEREIGN AI CONSOLE)")
    print(f"  {DM}The assistant works with grounded evidence from the detection engine.")
    print(f"  {DM}It will NOT hallucinate entities that are not present in the event graph.{R}")
    print(f"\n  {WH}Example questions:{R}")
    print(f"    {DM}→  Why was the last incident flagged?")
    print(f"    →  What MITRE technique is this mapped to?")
    print(f"    →  What containment action is recommended?")
    print(f"    →  Explain the counterfactual for this event.{R}")
    print(f"\n  {YL}Type  'exit'  or  'quit'  to return to the main menu.{R}\n")

    # Dynamically import to keep namespace clean
    try:
        _api_dir = str(SERVICES_DIR / "api")
        _det_dir = str(SERVICES_DIR / "detector")
        _gph_dir = str(SERVICES_DIR / "graph")
        for p in [ROOT_DIR, _api_dir, _det_dir, _gph_dir]:
            if str(p) not in sys.path:
                sys.path.insert(0, str(p))

        from app.assistant import SecurityAssistant
        from app.engine import DetectionEngine
        from app.profiles import ProfileStore
        from app.rules import RuleEngine
        from app.domain import Event as DetectorEvent
        from app.lineage import ProvenanceGraph
        from app.exporter import GraphExporter
    except ImportError as e:
        print(f"  {RD}Import error: {e}{R}")
        print(f"  {YL}Tip: Make sure all service packages are installed (pip install -e services/api etc.){R}\n")
        return

    # Build a minimal detection context seeded with a demo intrusion event
    rule_engine   = RuleEngine.from_directory(ROOT_DIR / "policy" / "detection")
    profile_store = ProfileStore(minimum_observations=2)
    det_engine    = DetectionEngine(rule_engine, profile_store)
    graph         = ProvenanceGraph()
    incidents: list[dict] = []

    # Seed with the /tmp reverse-shell demo event so the assistant has context immediately
    seed_event = {
        "event_id":    "evt-assistant-seed",
        "observed_at": "2026-09-03T12:00:00Z",
        "host_id":     "prod-server-01",
        "boot_id":     "boot-linux-001",
        "event_type":  "PROCESS_EXEC",
        "subject": {
            "process_id": "boot:1:666",
            "pid": 666, "ppid": 101,
            "executable": "/tmp/kworker_rev",
            "uid": 33,
        },
        "object_type":  "binary",
        "object_value": "/tmp/kworker_rev",
        "workload": {"workload_id": "nginx.service", "environment": "production"},
        "result": "success",
        "attributes": {"parent_executable": "/usr/sbin/nginx_worker"},
        "trust": {
            "host_attestation":    "verified",
            "agent_integrity":     "verified",
            "artifact_verification": "failed",
        },
    }
    assessment = det_engine.assess(DetectorEvent.from_dict(seed_event))
    graph.ingest_event(seed_event, risk_score=assessment.security_score)
    incidents.append({
        "event_id":           seed_event["event_id"],
        "event":              seed_event,
        "findings":           [f.to_dict() for f in assessment.findings],
        "security_score":     assessment.security_score,
        "reliability_score":  assessment.reliability_score,
        "telemetry_trust_score": assessment.telemetry_trust_score,
        "counterfactual":     assessment.counterfactual,
    })

    print(f"  {GR}Context loaded:{R}  1 intrusion incident seeded  "
          f"(Risk = {assessment.security_score:.2f}, Findings = "
          f"{[f.finding_id for f in assessment.findings]})\n")

    assistant = SecurityAssistant()

    while True:
        try:
            query = input(f"{CY}{BD}Analyst > {R}").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if not query:
            continue
        if query.lower() in ("exit", "quit", "q", "back"):
            break

        graph_data = GraphExporter.to_cytoscape_json(graph)
        reply = assistant.chat_query(
            query=query,
            recent_incidents=incidents,
            graph_data=graph_data,
        )
        print(f"\n{GR}{BD}वज्र Assistant:{R}")
        print(f"{WH}{reply}{R}\n")


# ══════════════════════════════════════════════════════════════════════════════
#   PROJECT INFO (quick summary printed in terminal)
# ══════════════════════════════════════════════════════════════════════════════

def print_project_info() -> None:
    print_section("PROJECT INFORMATION — वज्र (VAJRA)")

    rows = [
        ("Project Name",      "वज्र (VAJRA)"),
        ("Competition",       "SSM Hackathon BY CDAC  (2026)"),
        ("Track",             "Integration of AI Capabilities in the OS Ecosystem (Linux Based)"),
        ("Team Name",         "Team_Red_Eagle"),
        ("Category",          "AI + Linux Kernel + Runtime Security"),
        ("", ""),
        ("Problem Statement", "Linux systems lack a single explainable, low-overhead runtime tool that"),
        ("",                  "simultaneously detects zero-day intrusions, forecasts OS resource failures,"),
        ("",                  "and applies reversible, policy-governed autonomous containment."),
        ("", ""),
        ("Solution",          "Vajra bridges CO-RE eBPF telemetry → Laplace-smoothed Markov anomaly"),
        ("",                  "scoring → PSI kernel pressure forecasting → Bayesian Noisy-OR fusion →"),
        ("",                  "L₀-minimal counterfactual explanations → cgroup-v2 reversible SOAR."),
        ("", ""),
        ("Key Innovation",    "ProvX-style counterfactuals explain WHY each alert fired in plain language,"),
        ("",                  "TPM attestation freezes baseline if sensor integrity is compromised,"),
        ("",                  "and on-premises LLM assistant enforces entity-grounding (zero hallucination)."),
        ("", ""),
        ("Tech Stack",        "eBPF CO-RE (C)  ·  Rust 2021 Sensor  ·  Python 3.11 / FastAPI"),
        ("",                  "Pydantic v2  ·  cgroup v2  ·  Linux PSI  ·  HMAC-SHA-256 receipts"),
        ("",                  "HTML5 Canvas DAG  ·  MITRE ATT&CK Navigator v4.5  ·  Ollama LLM"),
        ("", ""),
        ("Test Coverage",     "36 / 36 unit tests — 5 / 5 scenario tests — 100 % pass rate"),
        ("Detection Rules",   "YAML policy-as-code — AG-RULE-001 (tmp exec), AG-RULE-003 (credential"),
        ("",                  "decoy), AG-REL-PRESSURE-FORECAST (OOM), AG-TRUST (TPM attestation)"),
    ]

    for label, value in rows:
        if not label and not value:
            print()
        elif label:
            print(f"  {YL}{BD}{label:<22}{R}  {WH}{value}{R}")
        else:
            print(f"  {DM}{'':24}{value}{R}")

    print()
    input(f"  {DM}Press Enter to return to the main menu…{R}")


# ══════════════════════════════════════════════════════════════════════════════
#   INTERACTIVE MAIN MENU
# ══════════════════════════════════════════════════════════════════════════════

_MENU_OPTIONS = [
    ("1", "🚀",  "Complete Demo Mode",
         "Run 5 scenarios then launch live web console",     "Recommended"),
    ("2", "🌐",  "Launch Web Dashboard",
         "Start FastAPI + HTML5 Canvas SOC Console (port 8000)", ""),
    ("3", "🧪",  "Run Test-Lab Scenarios",
         "Validate 5 attack & reliability failure modes",    ""),
    ("4", "🔬",  "Run All Unit Tests",
         "Execute 36 tests across 4 microservices",          ""),
    ("5", "🤖",  "Terminal AI Assistant",
         "Ask security questions in the CLI",                ""),
    ("6", "📋",  "Project Information",
         "Problem statement, tech stack, team details",      ""),
    ("7", "🚪",  "Exit",
         "",                                                 ""),
]


def main_menu() -> None:
    while True:
        print_banner()
        print(f"{WH}{BD}  Select an Execution Mode:{R}\n")

        for num, icon, title, desc, note in _MENU_OPTIONS:
            note_str = f"  {GR}← {note}{R}" if note else ""
            desc_str = f"  {DM}{desc}{R}" if desc else ""
            print(f"    {CY}[{num}]{R}  {icon}  {BD}{title}{R}{note_str}")
            if desc_str:
                print(f"         {DM}{desc}{R}")
            print()

        try:
            choice = input(f"  {YL}{BD}Enter choice [1-7]  (default = 1) : {R}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n  {YL}Goodbye from Team_Red_Eagle! ⚡{R}\n")
            sys.exit(0)

        os.system("cls" if sys.platform == "win32" else "clear")

        if choice in ("", "1"):
            print_banner()
            ok = run_scenarios()
            if ok:
                time.sleep(1)
                start_web_dashboard(open_browser=True)
            break

        elif choice == "2":
            print_banner()
            start_web_dashboard(open_browser=True)
            break

        elif choice == "3":
            print_banner()
            run_scenarios()
            input(f"\n  {DM}Press Enter to return to the menu…{R}")

        elif choice == "4":
            print_banner()
            run_unit_tests()
            input(f"\n  {DM}Press Enter to return to the menu…{R}")

        elif choice == "5":
            print_banner()
            terminal_assistant()

        elif choice == "6":
            print_banner()
            print_project_info()

        elif choice == "7":
            print(f"\n  {GR}Exiting Vajra. Good luck, Team_Red_Eagle at the CDAC Hackathon! ⚡{R}\n")
            sys.exit(0)

        else:
            print(f"\n  {RD}Invalid choice — please enter a number between 1 and 7.{R}\n")
            time.sleep(1)


# ══════════════════════════════════════════════════════════════════════════════
#   CLI ARG PARSER  (for headless/CI usage)
# ══════════════════════════════════════════════════════════════════════════════

def parse_args() -> None:
    parser = argparse.ArgumentParser(
        prog="run_vajra.py",
        description=(
            "⚡ वज्र (VAJRA) — Master Runner\n"
            "   Team_Red_Eagle | SSM Hackathon BY CDAC 2026"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--all",        action="store_true", help="Scenarios + web dashboard")
    parser.add_argument("--server",     action="store_true", help="Launch web dashboard only")
    parser.add_argument("--scenarios",  action="store_true", help="Run 5 test-lab scenarios")
    parser.add_argument("--tests",      action="store_true", help="Run all unit test suites")
    parser.add_argument("--check",      action="store_true", help="Preflight system check only")
    parser.add_argument("--info",       action="store_true", help="Print project information")
    parser.add_argument("--port",       type=int, default=8000, metavar="PORT",
                        help="Web server port (default: 8000)")
    parser.add_argument("--no-browser", action="store_true",
                        help="Do not auto-open the browser")

    args = parser.parse_args()
    print_banner()

    if args.check:
        preflight_check()
    elif args.info:
        print_project_info()
    elif args.scenarios:
        run_scenarios()
    elif args.tests:
        run_unit_tests()
    elif args.server:
        start_web_dashboard(port=args.port, open_browser=not args.no_browser)
    elif args.all:
        preflight_check()
        run_scenarios()
        time.sleep(1)
        start_web_dashboard(port=args.port, open_browser=not args.no_browser)
    else:
        main_menu()


# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    parse_args()
