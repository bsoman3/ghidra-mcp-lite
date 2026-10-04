---
node: high-level-design
---

# Decision: How the server works with the Ghidra GUI

## Context

The server runs Ghidra inside its own Python process through pyghidra and keeps its binaries in a Ghidra project on disk. Analysts also want to look at that work in the Ghidra GUI: see the agent's renames, comments, and types appear, and point the agent at whatever they are looking at. A local Ghidra project can be open in only one process at a time: Ghidra locks it, and a second open fails with `LockException: Unable to lock project!` (observed with Ghidra 12.1.4). So the server and a separately started GUI cannot share a project, and some integration design is needed. Getting it wrong either leaves the GUI useless for watching agent work, or lets two writers corrupt or silently undo each other's edits.

## Decision Elements

**Gates**

- *Inherited — one implementation, in Python on pyghidra* (HLD Approach). Each tool is implemented once, in the Python process that runs Ghidra. An option that needs a second implementation of the tools in another language is eliminated.

**Weighted criteria**

- **Live visibility** (major). An edit made by a tool appears in the analyst's GUI without restarting, re-opening, or synchronizing anything.
- **Correctness under concurrent use** (major; tenets *Reliability over footprint*, *Explicit over silent*). The analyst, Ghidra's own analysis, and the tools all change the same program. No writer may silently undo another's edit, and a tool must never report success for an edit that did not stick.
- **Analyst control** (moderate). The analyst's unsaved work, undo history, and analysis runs are not overridden by the agent.
- **Headless unchanged** (moderate). Headless use — the default, and the only option on a remote VM — keeps its behavior and simplicity.
- **Operational burden** (moderate). Extra servers, accounts, or processes the analyst must run.
- **Cost to build and maintain** (moderate).
- **Testability** (minor). Whether the integration can be exercised automatically.
- **Collaboration and history** (minor). Several analysts working on one project; a record of every agent edit.

## Options in the Domain

### A. Headless only, with a documented hand-off

**Description.** The server stays headless. The analyst and the server take turns with the project: stop the server, open the `.gpr` in the GUI, close it, restart the server. A copy of the project directory can be opened in the GUI as a read-only snapshot at any time.

**Analysis.**
- *One implementation*: **passes** — no new code.
- *Live visibility*: **weak** — nothing is live; every look requires stopping the server.
- *Correctness*: **strong** — there is only ever one writer.
- *Analyst control*: **strong** — the analyst and the agent never act at the same time.
- *Headless unchanged*: **strong**.
- *Operational burden*: **partial** — no extra processes, but a manual stop/start for every look.
- *Cost*: **strong** — documentation only.
- *Testability*: **strong** — nothing new to test.
- *Collaboration and history*: **weak**.

**Summary.** Zero cost and zero risk, at the price of any live integration.

### B. Host the server inside the GUI's process

**Description.** A `--gui` mode starts the full Ghidra GUI inside the server's own Python process (pyghidra can launch Ghidra's GUI in-process) with the server's project open, and serves MCP over HTTP alongside it. The server works on the GUI's open project and on the same in-memory programs CodeBrowser shows, so there is no second project open and no lock conflict. Analysis is delegated to Ghidra's own analysis manager, writes run on the GUI's Swing thread as their own transactions, and GUI-only tools (current function, current address, navigation) become possible. Headless mode is unchanged.

**Demonstration.** In a 12.1.4 spike, a rename made from the server's thread appeared immediately in CodeBrowser's listing, call sites, and decompiler pane; the GUI and the server held the identical `Program` object; Ghidra's analysis manager ran analysis in CodeBrowser's background task and reported its end; and an MCP tool called over HTTP returned the GUI's current address.

**Analysis.**
- *One implementation*: **passes** — the same Python tools run in both modes.
- *Live visibility*: **strong** — the GUI and the tools share one in-memory program, so edits appear immediately.
- *Correctness*: **partial** — Ghidra merges overlapping transactions on one program and aborts all of them if any aborts. Running each write on the Swing thread, only when no other transaction is open, avoids overlap with the analyst's edits and with analysis; a background task starting a transaction during a write's few milliseconds remains possible. Ghidra's analysis manager reports only cancellation, not analyzer failures.
- *Analyst control*: **strong** — edits are applied without saving and appear in the undo history; analysis is Ghidra's own.
- *Headless unchanged*: **strong** — GUI behavior sits behind a host seam used only with `--gui`.
- *Operational burden*: **strong** — one command starts both.
- *Cost*: **partial** — a new GUI host component, a project/program seam in program lifecycle, a write hook, and GUI-only tools.
- *Testability*: **partial** — the logic is testable with fakes; the GUI itself needs an on-demand smoke suite that launches a real GUI with isolated settings.
- *Collaboration and history*: **weak** — one analyst, one process.

**Summary.** Live, single-process integration at the cost of a second hosting mode and Swing-thread discipline.

### C. Share a Ghidra Server repository

**Description.** The project lives in a Ghidra Server repository. The GUI and the server each connect as clients, check binaries out, edit, and check them in; the analyst updates to see the agent's versions. Exclusive checkouts serialize editing; non-exclusive ones rely on Ghidra's merge on check-in.

**Analysis.**
- *One implementation*: **passes**.
- *Live visibility*: **weak** — changes appear only after a check-in and an update.
- *Correctness*: **partial** — exclusive checkouts are safe but let only one side edit; concurrent edits need merges that cannot be resolved reliably without a person.
- *Analyst control*: **partial** — checkouts and versions are explicit, but exclusive checkouts block the analyst while the agent holds one.
- *Headless unchanged*: **partial** — headless use must also learn shared projects, checkouts, and credentials.
- *Operational burden*: **weak** — a Ghidra Server to install and administer, with accounts and authentication.
- *Cost*: **partial** — shared-project handling and a check-in policy (per write floods the history; batched loses granularity).
- *Testability*: **partial** — needs a Ghidra Server in tests.
- *Collaboration and history*: **strong** — multi-user, versioned, every agent edit recorded.

**Summary.** Real collaboration and history, at the price of liveness and a server to run.

### D. A Java plugin in CodeBrowser behind a Python bridge

**Description.** The tools are implemented as a Java Ghidra extension that runs an HTTP server inside CodeBrowser; the Python MCP server becomes a bridge that forwards calls to it. A separate headless backend serves the same API without the GUI. This is the shape of other Ghidra MCP servers built around the GUI.

**Analysis.**
- *One implementation*: **eliminated** — the tools exist in Java for the GUI and in Python (or a second Java backend) for headless use.
- *Live visibility*: **strong** — the plugin runs inside the GUI.
- *Correctness*: **strong** — native plugin code uses Ghidra's own command and threading idioms.
- *Analyst control*: **strong**.
- *Headless unchanged*: **weak** — headless becomes a second backend or a bridge target.
- *Operational burden*: **partial** — install an extension, start its server from the GUI, run the bridge.
- *Cost*: **weak** — a reimplementation of every tool and a permanent second codebase.
- *Testability*: **partial** — Ghidra's Java GUI test framework, separate from the Python suite.
- *Collaboration and history*: **weak**.

**Summary.** The most native GUI integration, as a different product.

## Selection

**B — host the server inside the GUI's process.** It is the only option that passes the one-implementation gate and is strong on live visibility, the reason the decision exists. It keeps headless use unchanged and needs no extra infrastructure. Its correctness weakness is narrowed to a documented residual risk by the write rule: run each write on the Swing thread as its own transaction, only when no other transaction is open, and otherwise answer `retry_later` (tenet *Explicit over silent*). The missing analyzer-failure signal is documented as a blind spot rather than papered over (same tenet). A is the fallback if GUI hosting proves unworkable on a platform; C remains the route if multi-analyst collaboration or an edit history becomes a goal; D is a different product.

**Commits the project to:** a second, opt-in hosting mode with its own component (`gui-host`); a project/program seam in program lifecycle with headless and GUI implementations; a write hook in write-back; HTTP only in GUI mode (pyghidra's GUI launcher takes over standard output); GUI-only tools registered only in GUI mode; apply-without-saving in GUI mode; and an on-demand GUI smoke suite.

**Forecloses, in GUI mode:** stdio transport, following the analyst between projects, and multi-analyst use.
