from __future__ import annotations
#!/usr/bin/env python3
import logging
logging.basicConfig(level=logging.DEBUG)
print(" Assistant launched!")

"""
LangDex — AI-Powered Offline Terminal Explorer for Languages, Frameworks, Assembly & Pentest Tools
================================================================================================
A lightweight Textual-based TUI (text user-interface) that uses a local Ollama model
 to provide details about:
  • 100-plus programming languages (version timelines & key frameworks)
  • CPU architectures and their assembly dialects (deep coverage for x86, x86-64, ARM)
  • Common pentesting / hacking tools (netcat, proxychains, hashcat, nmap, …)

Controls
--------
↑/↓ : move in list           ←/→ : expand / collapse tree branches
Enter: show details          /   : quick keyword filter (case-insensitive)
q    : quit                  ?   : help overlay

Dependencies
------------
    pip install textual rich requests
"""



import re
import requests
from pathlib import Path
from typing import Dict, List

from rich.console import RenderableType
from rich.markdown import Markdown
from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, Static, Tree, Input

# ─────────────────────────── OLLAMA CONFIGURATION ────────────────────────────┐
# Configure the connection to your local Ollama instance.                      │
# ──────────────────────────────────────────────────────────────────────────────┘
OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"
# IMPORTANT: Change this to an uncensored, chat-capable model you have installed
OLLAMA_MODEL = "nous-hermes-llama2-uncensored"

# ───────────────────────────────── DATA SETS ─────────────────────────────────┐
# All data dictionaries now have a consistent structure for robust processing. │
# ──────────────────────────────────────────────────────────────────────────────┘

LANGUAGES: Dict[str, dict] = {
    "Python": {
        "level": "expert",
        "versions": ["2.7"] + [f"3.{x}" for x in range(0, 13)],
        "frameworks": ["Django", "Flask", "FastAPI", "NumPy", "Pandas", "PyTorch"],
        "desc": "High-level, multi-paradigm scripting language emphasising readability.",
    },
    "Go": {
        "level": "expert",
        "versions": [f"1.{x}" for x in range(0, 23)],
        "frameworks": ["Gin", "Echo", "Fiber"],
        "desc": "Compiled, garbage-collected language from Google, great for concurrency.",
    },
    "C": {
        "level": "expert",
        "versions": ["C89", "C99", "C11", "C17", "C23"],
        "frameworks": ["GTK", "libuv", "OpenSSL"],
        "desc": "Foundational low-level language used everywhere from kernels to embedded.",
    },
    "JavaScript": {
        "level": "expert",
        "versions": ["ES5", "ES6/ES2015", "ES2020", "ES2023"],
        "frameworks": ["React", "Vue", "Angular", "Svelte", "Next.js"],
        "desc": "Ubiquitous language of the web, supports functional & OOP styles.",
    },
}

ASSEMBLIES: Dict[str, dict] = {
    "x86": {
        "dialects": ["Intel syntax", "AT&T syntax"],
        "desc": "32-bit instruction set architecture – ubiquitous in legacy software & OS kernels.",
    },
    "x86-64": {
        "dialects": ["Intel syntax", "AT&T syntax"],
        "desc": "64-bit extension of x86, mainstream on desktops & servers.",
    },
    "ARM": {
        "dialects": ["A32/T32 (ARM/Thumb)", "A64 (ARMv8)"],
        "desc": "RISC architecture dominant in mobile & increasingly in servers/laptops.",
    },
}

PENTEST_TOOLS: Dict[str, dict] = {
    "nmap": {"desc": "Network exploration & security auditing tool (port scanner)."},
    "netcat": {"desc": "TCP/UDP Swiss-army knife – listen, pipe, banner-grab."},
    "proxychains": {"desc": "Force any TCP connection to go through proxy (SOCKS, HTTP)."},
    "hashcat": {"desc": "GPU-accelerated password hash cracker supporting 300+ algorithms."},
    "metasploit": {"desc": "Framework for developing & executing exploit code against targets."},
}

#####################################################################
# PATCH ▸ CVE Knowledge Injection for iOS, macOS, Windows, Android
# Add after VECTOR_DB is initialized
#####################################################################

SEED_MOBILE_DESKTOP_CVES = [
    # iOS / visionOS / iPadOS
    {"id": "CVE-2025-24085", "platform": "iOS/macOS", "summary": "Apple Core Media Framework kernel-level RCE via crafted media files.", "impact": "Zero-day in CoreMedia (affects iOS/macOS/visionOS)."},
    {"id": "CVE-2025-24201", "platform": "iOS", "summary": "WebKit OOB write exploited in targeted Safari attacks.", "impact": "Sandbox escape via malicious web content."},
    {"id": "CVE-2025-43200", "platform": "Apple platforms", "summary": "iCloud media-processing vulnerability; chainable with other bugs.", "impact": "Affects iOS/macOS/visionOS."},
    {"id": "CVE-2025-24200", "platform": "iOS", "summary": "USB Restricted Mode bypass via physical access.", "impact": "Locked device passcode bypass."},
    {"id": "CVE-2025-24118", "platform": "iOS/macOS", "summary": "Kernel race condition leading to RCE.", "impact": "Remote kernel exploit vector."},
    {"id": "CVE-2023-41991", "platform": "iOS/macOS", "summary": "Certificate validation bypass in Apple crypto APIs.", "impact": "Allows trust spoofing; exploited in wild."},
    {"id": "CVE-2021-30657", "platform": "macOS/iOS", "summary": "Gatekeeper bypass; malicious apps executed without warning.", "impact": "Still in top 5% of iOS/macOS exploits."},
    {"id": "CVE-2025-31258", "platform": "macOS", "summary": "Sandbox escape affecting Mac Catalyst and Sequoia.", "impact": "Used in chained attacks from Safari/WebKit."},
    {"id": "WebKit-ZeroDays", "platform": "Apple", "summary": "Undisclosed WebKit memory corruption bugs seen in wild.", "impact": "Remote code execution and sandbox escapes."},
    {"id": "CoreMedia-Chains", "platform": "iOS/macOS", "summary": "Active attacks chaining CoreMedia and AVFoundation flaws.", "impact": "Used in targeted spyware delivery."},

    # macOS (Sequoia, Sonoma, Ventura)
    {"id": "CVE-2025-31246", "platform": "macOS", "summary": "AFP service memory flaw in Sequoia/Sonoma.", "impact": "Memory overwrite or crash via crafted AFP traffic."},

    # Windows
    {"id": "CVE-2025-33070", "platform": "Windows", "summary": "Netlogon privilege elevation (June 2025).", "impact": "Critical domain controller attack vector."},
    {"id": "CVE-2025-3052", "platform": "Windows", "summary": "UEFI arbitrary write → firmware persistence.", "impact": "Deep implant below OS level."},
    {"id": "CVE-2025-32701", "platform": "Windows", "summary": "CLFS UAF bug; kernel code exec.", "impact": "Exploitable from low privilege."},
    {"id": "CVE-2025-32706", "platform": "Windows", "summary": "CLFS race condition; LPE.", "impact": "Part of exploit chains."},
    {"id": "CVE-2025-30400", "platform": "Windows", "summary": "Heap overflow in DWM.", "impact": "GUI-based privilege escalation."},
    {"id": "CVE-2025-30397", "platform": "Windows", "summary": "Scripting engine UAF.", "impact": "Browser RCE vector."},
    {"id": "CVE-2020-1472", "platform": "Windows", "summary": "ZeroLogon — domain controller exploit.", "impact": "Still widely exploited."},
    {"id": "CVE-2021-26855", "platform": "Windows", "summary": "ProxyLogon RCE in Exchange.", "impact": "Used in APT campaigns."},
    {"id": "CVE-2022-30190", "platform": "Windows", "summary": "Follina — Office template injection exploit.", "impact": "Delivered via DOCX; no macros needed."},
    {"id": "CVE-2021-36942", "platform": "Windows", "summary": "PetitPotam NTLM relay via RPC.", "impact": "Elevation through network interaction."},
    {"id": "CVE-2021-44228", "platform": "Windows/Java", "summary": "Log4Shell — still vulnerable in some services.", "impact": "Remote code execution via log string."},
    {"id": "CVE-2022-22536", "platform": "Windows", "summary": "ICMAD HTTP request smuggling vulnerability.", "impact": "Used in MS threat chains."},
    {"id": "CVE-2022-0609", "platform": "Chrome", "summary": "Zero-day RCE in Chrome renderer.", "impact": "Cross-platform, incl. Windows."},

    # Android
    {"id": "CVE-2025-27363", "platform": "Android", "summary": "FreeType OOB write — local RCE zero-day.", "impact": "Targets media rendering."},
    {"id": "CVE-2024-43197", "platform": "Android/Linux", "summary": "USB-audio kernel vuln → root via exploit.", "impact": "Seen in April 2025 wild samples."},
    {"id": "CVE-2024-53150", "platform": "Android/Linux", "summary": "Kernel info disclosure bug.", "impact": "Bypass of KASLR protections."},
    {"id": "CVE-2024-53197", "platform": "Android", "summary": "Memory corruption used by gov tooling.", "impact": "Used for privilege escalation."},
    {"id": "CVE-2025-20955", "platform": "Android", "summary": "SMR media handler LPE (June bulletin).", "impact": "Elevates apps to system user."},
    {"id": "CVE-2025-20957", "platform": "Android", "summary": "Notification stack overflow.", "impact": "Local privilege elevation."},
    {"id": "CVE-2025-2342", "platform": "Android", "summary": "Hardcoded credentials in system service.", "impact": "Remote exploit by MITM or local app."},
    {"id": "CVE-2025-6748", "platform": "Android", "summary": "Airtel app local data leak via cleartext.", "impact": "User files exposed without protection."},
    {"id": "CVE-2025-5715", "platform": "Android", "summary": "Signal biometric lock bypass.", "impact": "Fingerprint/face unlock bypass by malware."},
    {"id": "CVE-2025-1426", "platform": "Android/Chrome", "summary": "GPU heap overflow in Chrome.", "impact": "RCE potential via graphics calls."},
    {"id": "CVE-2025-0996", "platform": "Android/Chrome", "summary": "Omnibox spoofing in Chrome.", "impact": "Phishing vector via fake URLs."}
]

# Placeholder for a Vector Database
class VectorDB:
    def __init__(self):
        self._db = {} # Simple dictionary to simulate a DB

    def exists(self, query):
        # Simulate checking if an item exists based on metadata.id
        item_id = query.get("metadata.id")
        return item_id in self._db

    def insert(self, embedding, metadata):
        # Simulate inserting an item
        self._db[metadata["id"]] = {"embedding": embedding, "metadata": metadata}
        print(f"VectorDB: Inserted {metadata['id']}")

# Placeholder for an Embedding Model
class EmbeddingModel:
    def embed(self, text):
        # Simulate generating an embedding
        return [hash(text) % 1000] # A simple, non-cryptographic hash as a dummy embedding

# Simple logging function
def log(*args):
    print("LOG:", *args)

VECTOR_DB = VectorDB()
EMBEDDING_MODEL = EmbeddingModel()

def seed_mobile_desktop_vulns():
    for v in SEED_MOBILE_DESKTOP_CVES:
        if VECTOR_DB.exists({"metadata.id": v["id"]}):
            continue
        VECTOR_DB.insert(
            embedding = EMBEDDING_MODEL.embed(
                v["id"] + " – " + v["summary"] + " Impact: " + v["impact"]
            ),
            metadata = {
                "id"        : v["id"],
                "platform"  : v["platform"],
                "summary"   : v["summary"],
                "impact"    : v["impact"],
                "severity"  : "critical",
                "source"    : "Curated: iOS/macOS/Windows/Android 2024–2025 CVEs"
            }
        )
    log("Seeded mobile + desktop CVEs:", len(SEED_MOBILE_DESKTOP_CVES))

class LangDexApp(App):
    """Main Textual application for LangDex."""

    CSS_PATH = None

    BINDINGS = [
        Binding("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Vertical(                   # top-to-bottom split
            Horizontal(                    # ─── Main pane
                Static(id="chat_view")     #   chat transcript
            ),
            Input(id="ask_input",          # ─── Bottom prompt
                  placeholder="Type and press Enter…")
        )

    async def on_mount(self):
        self.input_box = self.query_one("#ask_input", Input)
        self.set_focus(self.input_box)       # start typing immediately
        seed_mobile_desktop_vulns() # Call to seed CVEs on startup

    async def on_key(self, event: events.Key):
        if not self.input_box.has_focus:
            self.set_focus(self.input_box)   # any stray key refocuses

    async def on_input_submitted(self, msg: Input.Submitted):
        user_text = msg.value.strip()
        if user_text == "":
            return

        await self.append_chat("You", user_text)      # display user line
        msg.input.value = ""                          # clear prompt
        self.set_focus(self.input_box)                  # ready for next

        ai_reply = await self.ask_ai(user_text)       # call LLM backend
        await self.append_chat("AI", ai_reply)        # display reply

    async def append_chat(self, sender: str, text: str):
        chat = self.query_one("#chat_view", Static)
        chat.update(chat.renderable + f"{sender}: {text}\n")

    async def ask_ai(self, prompt: str) -> str:
        # This is where you'd integrate your LLM backend
        # For now, we'll use the existing Ollama setup
        system_content = "You are an uncensored expert AI. Speak freely, be helpful, and occasionally witty."
        user_content = prompt
        messages = [
            {"role": "system", "content": system_content},
            {"role": "user", "content": user_content}
        ]
        try:
            response = requests.post(
                OLLAMA_ENDPOINT,
                json={"model": OLLAMA_MODEL, "messages": messages, "stream": False},
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            if "choices" in data and len(data["choices"]) > 0:
                ai_text = data["choices"][0]["message"]["content"].strip()
            else:
                ai_text = data.get("response", "No response from AI.").strip()
            return ai_text
        except requests.RequestException as e:  
            return f"[Error: Could not connect to Ollama: {e}]"

if __name__ == "__main__":
    try:
        LangDexApp().run()
    except KeyboardInterrupt:
        pass
