"""Static analysis of install-time scripts.

Install hooks are the sharpest edge in the supply chain: `npm install` runs
`postinstall` and `pip install` runs `setup.py` before anyone has reviewed a
line of the code. Both the `event-stream` and `ua-parser-js` compromises
executed through this path.

Only text that registries expose in metadata is analysed here — npm `scripts`
entries and equivalents. Downloading and unpacking every tarball to scan its
source is deliberately out of scope; see the README threat model for why, and
for what that costs in coverage.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum


class Behaviour(StrEnum):
    NETWORK_FETCH = "network_fetch"
    PIPE_TO_SHELL = "pipe_to_shell"
    ENCODED_PAYLOAD = "encoded_payload"
    DYNAMIC_EVAL = "dynamic_eval"
    ENVIRONMENT_ACCESS = "environment_access"
    CREDENTIAL_PATH = "credential_path"
    EXFILTRATION_TARGET = "exfiltration_target"
    PROCESS_SPAWN = "process_spawn"
    OBFUSCATION = "obfuscation"
    FILESYSTEM_WRITE = "filesystem_write"


@dataclass(frozen=True, slots=True)
class Detection:
    behaviour: Behaviour
    #: 0.0-1.0 contribution to the overall suspicion score.
    weight: float
    description: str
    excerpt: str = ""


@dataclass(slots=True)
class ScriptAnalysis:
    detections: list[Detection] = field(default_factory=list)

    @property
    def score(self) -> float:
        """Combined suspicion, saturating rather than summing past 1.0."""
        score = 0.0
        for detection in sorted(self.detections, key=lambda d: -d.weight):
            score += detection.weight * (1.0 - score)
        return round(min(1.0, score), 3)

    @property
    def behaviours(self) -> set[Behaviour]:
        return {d.behaviour for d in self.detections}

    def __bool__(self) -> bool:
        return bool(self.detections)


# --------------------------------------------------------------------------
# Pattern table
# --------------------------------------------------------------------------

_PATTERNS: list[tuple[Behaviour, str, float, str]] = [
    # -- fetching remote content ------------------------------------------
    (Behaviour.NETWORK_FETCH, r"\b(?:curl|wget)\b", 0.45, "Invokes curl/wget"),
    (Behaviour.NETWORK_FETCH, r"\bnc\s+-[a-z]*e", 0.7, "Netcat with command execution"),
    (Behaviour.NETWORK_FETCH, r"/dev/tcp/", 0.7, "Raw TCP socket via /dev/tcp"),
    (Behaviour.NETWORK_FETCH, r"\b(?:https?://)\d{1,3}(?:\.\d{1,3}){3}", 0.6,
     "Contacts a bare IP address rather than a hostname"),
    (Behaviour.NETWORK_FETCH, r"\b(?:urllib|requests\.(?:get|post)|http\.client|axios|node-fetch)\b",
     0.35, "Makes an HTTP request"),
    (Behaviour.NETWORK_FETCH, r"\bInvoke-WebRequest\b|\bDownloadString\b", 0.6,
     "PowerShell remote download"),

    # -- executing what was fetched ----------------------------------------
    (Behaviour.PIPE_TO_SHELL, r"(?:curl|wget)[^|;&\n]*(?<!\|)\|(?!\|)\s*(?:ba|z|k|d)?sh\b", 0.95,
     "Downloads a script and pipes it straight into a shell"),
    (Behaviour.PIPE_TO_SHELL, r"(?<!\|)\|(?!\|)\s*(?:python|node|ruby|perl)\b", 0.8,
     "Pipes downloaded content into an interpreter"),
    (Behaviour.PIPE_TO_SHELL, r"(?<!\|)\|(?!\|)\s*(?:ba|z|k|d)?sh\b", 0.8,
     "Pipes command output directly into a shell"),
    (Behaviour.PIPE_TO_SHELL, r"\bIEX\b|\bInvoke-Expression\b", 0.85,
     "PowerShell Invoke-Expression on remote content"),

    # -- obfuscated payloads -----------------------------------------------
    (Behaviour.ENCODED_PAYLOAD, r"\bbase64\s+(?:-d|--decode|-D)\b", 0.75,
     "Decodes a base64 payload"),
    (Behaviour.ENCODED_PAYLOAD, r"\batob\s*\(", 0.7, "JavaScript base64 decode"),
    (Behaviour.ENCODED_PAYLOAD, r"Buffer\.from\s*\([^)]*['\"]base64['\"]", 0.7,
     "Node base64 buffer decode"),
    (Behaviour.ENCODED_PAYLOAD, r"\bb64decode\b|\bbase64\.b64decode\b", 0.75,
     "Python base64 decode"),
    (Behaviour.ENCODED_PAYLOAD, r"String\.fromCharCode\s*\(", 0.6,
     "Builds a string from character codes"),
    (Behaviour.ENCODED_PAYLOAD, r"(?:\\x[0-9a-fA-F]{2}){8,}", 0.65,
     "Long run of hex escapes"),

    # -- dynamic execution --------------------------------------------------
    (Behaviour.DYNAMIC_EVAL, r"\b(?:python\d?|node|ruby|perl)\s+-(?:e|c)\b", 0.4,
     "Runs inline source through an interpreter rather than a checked-in script"),
    (Behaviour.DYNAMIC_EVAL, r"\beval\s*\(", 0.7, "Calls eval()"),
    (Behaviour.DYNAMIC_EVAL, r"\bnew\s+Function\s*\(", 0.7, "Constructs a function from a string"),
    (Behaviour.DYNAMIC_EVAL, r"\bexec\s*\(|\bexecSync\s*\(", 0.55, "Executes a command string"),
    (Behaviour.DYNAMIC_EVAL, r"\bos\.system\b|\bsubprocess\.(?:call|run|Popen|check_output)\b",
     0.5, "Spawns a subprocess from Python"),
    (Behaviour.PROCESS_SPAWN, r"\bchild_process\b|\bspawnSync?\b", 0.5,
     "Spawns a child process from Node"),

    # -- reading secrets ----------------------------------------------------
    (Behaviour.ENVIRONMENT_ACCESS, r"\bprocess\.env\b|\bos\.environ\b|\bENV\[", 0.3,
     "Reads environment variables"),
    (Behaviour.CREDENTIAL_PATH, r"\.ssh/|id_rsa|\.aws/credentials|\.npmrc|\.pypirc|"
     r"\.netrc|\.docker/config|kube/config", 0.85,
     "References a credential file path"),
    (Behaviour.CREDENTIAL_PATH, r"\bAWS_SECRET|\bGITHUB_TOKEN\b|\bNPM_TOKEN\b|"
     r"\bSECRET_KEY\b|\bPRIVATE_KEY\b", 0.7,
     "References a well-known secret environment variable"),

    # -- where the data goes ------------------------------------------------
    (Behaviour.EXFILTRATION_TARGET,
     r"\b(?:webhook\.site|requestbin|pipedream\.net|ngrok\.io|ngrok-free\.app|"
     r"pastebin\.com|transfer\.sh|termbin\.com|file\.io|0x0\.st)\b", 0.9,
     "Contacts a known drop/paste service"),
    (Behaviour.EXFILTRATION_TARGET,
     r"\b(?:burpcollaborator\.net|oastify\.com|interact\.sh|dnslog\.cn|"
     r"canarytokens\.com|\.oast\.)\b", 0.9,
     "Contacts an out-of-band interaction domain used for exfiltration"),
    (Behaviour.EXFILTRATION_TARGET, r"discord(?:app)?\.com/api/webhooks", 0.9,
     "Posts to a Discord webhook"),
    (Behaviour.EXFILTRATION_TARGET, r"\bt\.me/|api\.telegram\.org", 0.8,
     "Contacts Telegram's API"),

    # -- persistence / tampering -------------------------------------------
    (Behaviour.FILESYSTEM_WRITE, r"\bcrontab\b|/etc/cron|LaunchAgents|\.bashrc|\.zshrc|\.profile",
     0.8, "Writes to a shell startup or scheduler location"),
    (Behaviour.FILESYSTEM_WRITE, r"\bchmod\s+\+x\b", 0.4, "Marks a file executable"),
    (Behaviour.FILESYSTEM_WRITE, r"\brm\s+-rf\b", 0.5, "Recursively deletes files"),
]

_COMPILED = [
    (behaviour, re.compile(pattern, re.IGNORECASE), weight, description)
    for behaviour, pattern, weight, description in _PATTERNS
]

#: Install hooks that are overwhelmingly benign on their own.
_BENIGN_SCRIPTS = re.compile(
    r"^\s*(?:node-gyp\s+rebuild|prebuild-install\b[\w\s.=-]*|husky(?:\s+install)?|"
    r"patch-package|opencollective\b[\w\s.=-]*|is-ci\b[\w\s.=-]*|"
    r"node\s+scripts/postinstall\.js|exit\s+0|true)\s*$",
    re.IGNORECASE,
)

#: Shell metacharacters that allow chaining, piping or substitution. A script
#: containing any of these is never waved through by the benign allowlist,
#: however innocent its opening command looks — `echo x | base64 -d | sh`
#: starts with a harmless `echo`.
_SHELL_METACHARACTERS = re.compile(r"[|;&`>]|\$\(")


def _is_benign(source: str) -> bool:
    """Whether a script can be dismissed without pattern analysis."""
    stripped = source.strip()
    if _SHELL_METACHARACTERS.search(stripped):
        return False
    return bool(_BENIGN_SCRIPTS.match(stripped))


def analyse_script(source: str) -> ScriptAnalysis:
    """Analyse one script body for attacker-shaped behaviour."""
    analysis = ScriptAnalysis()
    if not source or not source.strip():
        return analysis
    if _is_benign(source):
        return analysis

    seen: set[Behaviour] = set()
    for behaviour, pattern, weight, description in _COMPILED:
        match = pattern.search(source)
        if not match:
            continue
        # Count each behaviour once, keeping the strongest match.
        if behaviour in seen:
            continue
        seen.add(behaviour)
        analysis.detections.append(
            Detection(behaviour, weight, description, _excerpt(source, match))
        )

    # Obfuscation is judged on an embedded blob, not on entropy alone.
    #
    # Entropy was originally the trigger here, and it was wrong: it was tuned
    # against one-line npm install hooks, but a CI `run:` block is a full
    # multi-line shell script whose ordinary mix of paths, flags and case runs
    # at 5.0-5.5 bits. Scanning pytorch/pytorch produced 89 findings on that
    # basis alone, every one of them a normal build step. What actually
    # distinguishes an encoded payload is a long unbroken token; entropy only
    # says how it is encoded, so it now strengthens that finding rather than
    # standing on its own.
    if (blob := _find_blob(source)) is not None:
        entropy = shannon_entropy(blob)
        analysis.detections.append(
            Detection(
                Behaviour.OBFUSCATION,
                0.6 if entropy > 4.5 else 0.4,
                f"Contains a {len(blob)}-character unbroken token "
                f"({entropy:.1f} bits of entropy), typical of an embedded payload",
                excerpt=blob[:60] + ("..." if len(blob) > 60 else ""),
            )
        )
    return analysis


def analyse_scripts(scripts: dict[str, str]) -> dict[str, ScriptAnalysis]:
    """Analyse a mapping of hook name -> script body, keeping only hits."""
    results: dict[str, ScriptAnalysis] = {}
    for hook, source in (scripts or {}).items():
        analysis = analyse_script(str(source))
        if analysis:
            results[hook] = analysis
    return results


def combined_score(analyses: dict[str, ScriptAnalysis]) -> float:
    """Overall suspicion across every hook, saturating at 1.0."""
    score = 0.0
    for analysis in sorted(analyses.values(), key=lambda a: -a.score):
        score += analysis.score * (1.0 - score)
    return round(min(1.0, score), 3)


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character. Minified/encoded blobs run high."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


#: A long unbroken run of base64/hex-safe characters. Real shell scripts break
#: on whitespace and punctuation long before this; encoded payloads do not.
_BLOB = re.compile(r"[A-Za-z0-9+/=_-]{120,}")


def _find_blob(text: str) -> str | None:
    match = _BLOB.search(text)
    return match.group(0) if match else None


def _excerpt(source: str, match: re.Match) -> str:
    start = max(0, match.start() - 30)
    end = min(len(source), match.end() + 30)
    snippet = source[start:end].replace("\n", " ").strip()
    return ("..." if start else "") + snippet + ("..." if end < len(source) else "")
