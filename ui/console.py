"""AURORA Console — Colored terminal output utilities."""
from __future__ import annotations
import sys

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False
    class _Stub:
        def __getattr__(self, name): return ""
    Fore = Back = Style = _Stub()

def c(color: str, text: str) -> str:
    if not _HAS_COLOR: return text
    colors = {"RED":Fore.RED,"GREEN":Fore.GREEN,"YELLOW":Fore.YELLOW,"CYAN":Fore.CYAN,"MAGENTA":Fore.MAGENTA,"BLUE":Fore.BLUE,"WHITE":Fore.WHITE,"BRIGHT":Style.BRIGHT,"DIM":Style.DIM,"RESET":Style.RESET_ALL}
    return colors.get(color, "") + str(text) + Style.RESET_ALL

def banner():
    print(c("CYAN", """
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║    ░█████╗░██╗░░░██╗██████╗░░█████╗░██████╗░░█████╗░                   ║
║    ██╔══██╗██║░░░██║██╔══██╗██╔══██╗██╔══██╗██╔══██╗                   ║
║    ███████║██║░░░██║██████╔╝██║░░██║██████╔╝███████║                   ║
║    ██╔══██║██║░░░██║██╔══██╗██║░░██║██╔══██╗██╔══██║                   ║
║    ██║░░██║╚██████╔╝██║░░██║╚█████╔╝██║░░██║██║░░██║                   ║
║    ╚═╝░░╚═╝░╚═════╝░╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝                   ║
║                                                                          ║
║    Autonomous Unified Resilience & Organizational Real-time Awareness    ║
║    7 Layers  ·  14 Engines  ·  500+ Tests  ·  Quantum-Safe  ║
╚══════════════════════════════════════════════════════════════════════════╝
"""))

def risk_bar(score: float, width: int = 30) -> str:
    filled = int(score / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    if score >= 80: color = "RED"
    elif score >= 60: color = "YELLOW"
    elif score >= 40: color = "CYAN"
    else: color = "GREEN"
    return c(color, f"[{bar}]") + f" {score:.1f}%"

def risk_verdict(score: float) -> str:
    if score >= 85: return c("RED",     "● CRITICAL  — Autonomous containment activated")
    if score >= 70: return c("RED",     "● HIGH      — Immediate intervention required")
    if score >= 55: return c("YELLOW",  "● ELEVATED  — Enhanced monitoring active")
    if score >= 35: return c("CYAN",    "● MODERATE  — Standard protocols")
    return c("GREEN", "● MINIMAL   — Within normal parameters")

def section(title: str) -> None:
    print(f"\n  {c('BRIGHT', '─'*60)}")
    print(f"  {c('CYAN', title)}")
    print(f"  {c('BRIGHT', '─'*60)}")

def item(label: str, value: str, color: str = "WHITE") -> None:
    print(f"  {c('DIM', label.ljust(28))} {c(color, value)}")

def multiline_item(label: str, value: str, color: str = "WHITE", width: int = 72) -> None:
    """Like item() but wraps long values onto continuation lines."""
    import textwrap
    label_col = c("DIM", label.ljust(28))
    lines = textwrap.wrap(str(value), width=width)
    if not lines:
        print(f"  {label_col}")
        return
    print(f"  {label_col} {c(color, lines[0])}")
    indent = " " * 30  # 2 spaces + 28-char label column
    for line in lines[1:]:
        print(f"  {indent}{c(color, line)}")
