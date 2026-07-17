# Horse Plinko Cyber Challenge — Blue Team Hardening

Initial-hardening scripts for the [Horse Plinko Cyber Challenge](https://plinko.horse), a beginner-oriented cyber defense competition run at UCF. One script per box, covering Season 2 (Fall 2024) and Season 3 (Fall 2025).

```bash
sudo bash s3-fall-2025/antenna.sh
```

- [The problem](#the-problem)
- [Scoring traps](#scoring-traps)
- [Layout](#layout)
- [The boxes](#the-boxes)
- [Usage](#usage)
- [What these do that most hardening scripts don't](#what-these-do-that-most-hardening-scripts-dont)
- [Runbook](#runbook)
- [Design notes](#design-notes)
- [Caveats](#caveats)

---

## The problem

Most "hardening script" repos are a pile of `echo >> sshd_config`. That's not what this is, because in a defense competition **hardening and scoring are in direct tension.**

Your score is 65% service uptime. Uptime is measured by a robot that logs into your boxes as `hkeating`/`jmoney` and checks that things work. Which means the scoring engine looks *exactly like an attacker* — same protocols, same credentials, same source network. Every reflexive lockdown is a self-inflicted outage.

The design principle throughout: **leave the front door open exactly as wide as the check requires, and bolt every other door shut.** Anonymous FTP stays enabled — but read-only, chrooted, no upload, files immutable, hashed, and self-healing. That's the whole repo in one sentence.

## Scoring traps

| The reflex | What it actually does |
|---|---|
| `PasswordAuthentication no` | Zeroes the SSH check. The engine authenticates with a password. |
| Disable anonymous FTP | Zeroes the FTP check. The check **is** an anonymous login. Both seasons. |
| `bind-address = 127.0.0.1` | Zeroes MySQL. In S3 it also kills the storefront that reads from it. |
| `fDenyTSConnections = 1` | Zeroes RDP on sails (S2), depot + foreman (S3). |
| `setenforce 0` | Throws away the thing stopping the webshell you haven't found yet. |
| Swap Apache → nginx | Rule 3 violation. Scored service software is mandated. |
| Delete the weird wiki page | Both HTTP checks read page **content**, not just a `200`. |

### Content checks vs. liveness checks

DNS, HTTP, and FTP verify **content**. The daemon can be perfectly healthy while the check is red:

- DNS record edited to point elsewhere → `named` is up, check is red
- Page defaced or product deleted → `200 OK`, check is red
- Memo file modified → login succeeds, hash mismatch, check is red

`systemctl status` will lie to you here. Monitor content, not ports.

### The dependency chains

Two boxes back score checks they don't own. This is the highest-value thing on this page.

```
S2:   sails HTTP  ──reads──>  mast MySQL (my_wiki)
S3:   storkfront HTTP  ──reads──>  foreman MySQL (horsepress)
```

Locking MySQL to localhost costs you **two** checks, not one. And when the web check goes red, confirm the DB box is reachable on 3306 *before* touching the web server — most people burn twenty minutes on Apache first.

### Password Change Requests

Rotating the scoring user's password without a PCR is an immediate outage. **Order matters:**

1. `scoreboard.plinko.horse` → PCRs tab → select `<box>.credlist`
2. Enter `username,password` — no space around the comma
3. **Then** change it on the box

The scripts skip the scoring user during bulk rotation and stop to remind you.

### Things that are safe to do

Not everything is a trap. These are free: rotate every non-scoring password (do it first), delete all `authorized_keys`, `PermitRootLogin no`, firewall everything except scored ports, remove anonymous/test MySQL users, keep SELinux enforcing, disable SMBv1 / RemoteRegistry / Spooler / WinRM, kill the WordPress file editor, block PHP execution in `wp-content/uploads/`, disable BIND zone transfers and dynamic updates, turn on audit logging.

### Account lockout is double-edged

`lockoutthreshold` protects against brute force. It also lets Red Team lock out **the scoring account** by failing logins on purpose — check goes red, they never got in. No clean answer. Reasonable middle ground: threshold 10, 15-minute window, and watch Event ID 4740 / `faillock` so you notice.

## Layout

```
.
├── s2-fall-2024/           Season 2 — Plinko Sauce
│   ├── lib/                shared library (sourced, not run)
│   ├── sonar.sh
│   ├── helm.ps1
│   ├── sails.ps1
│   ├── mast.sh
│   └── cargo.sh
│
└── s3-fall-2025/           Season 3 — 7G™ towers
    ├── lib/
    ├── generator.sh
    ├── antenna.sh
    ├── storkfront.sh
    ├── depot.ps1
    └── foreman.ps1
```

## The boxes

### Season 2 — Fall 2024

Scoring user `hkeating` · default creds `plinktern:HPCCrulez!`

| Script | Box | IP | OS | Scored |
|---|---|---|---|---|
| `sonar.sh` | sonar | `172.16.t.5` | Linux | — (out of Red Team scope) |
| `helm.ps1` | helm | `172.16.t.10` | Windows | SSH, DNS |
| `sails.ps1` | sails | `172.16.t.20` | Windows | RDP, HTTP (MediaWiki/Apache) |
| `mast.sh` | mast | `172.16.t.30` | Linux | SSH, MySQL (`my_wiki`) |
| `cargo.sh` | cargo | `172.16.t.40` | Linux | SSH, FTP (vsftpd, anonymous) |

- `sails` is a Windows box running **Apache**, not IIS. Surprises people.
- Wiki accounts `PlinkoMaster:plinkosauce` and `Dr.Ravy:plinkularity` are published. Rotate them. Do **not** delete Dr. Ravy's page — the HTTP check reads its content.
- `LocalSettings.php` holds mast's DB password in cleartext.

### Season 3 — Fall 2025

Scoring user `jmoney` · default creds `plinktern:IHPLRulez!`

| Script | Box | IP | OS | Scored |
|---|---|---|---|---|
| `generator.sh` | generator | `172.16.t.5` | Linux Mint 22 | — (out of Red Team scope) |
| `antenna.sh` | antenna | `172.16.t.10` | Debian 12 | SSH, DNS (BIND) |
| `storkfront.sh` | storkfront | `172.16.t.20` | AlmaLinux 9 | SSH, HTTP (WooCommerce) |
| `depot.ps1` | depot | `172.16.t.30` | Server 2012 R2 | RDP, FTP (IIS, `/memos`) |
| `foreman.ps1` | foreman | `172.16.t.40` | Server 2022 | RDP, MySQL (`horsepress`) |

- `depot` is PowerShell 4.0 — no `Get-LocalUser`, patchy `*-NetFirewall*`. `lib/common-windows.ps1` probes and falls back to `net.exe`/`netsh`.
- `storkfront` is AlmaLinux: `dnf`, `firewalld`, `httpd`, SELinux enforcing. Needs `setsebool -P httpd_can_network_connect_db 1` or WordPress can't reach foreman.
- WooCommerce admin `plinktern:IHPLRulez!` is published. Rotate it. Don't delete products — the HTTP check reads product info.
- **Packet inconsistency:** the MySQL walkthrough says to log into *depot*, but Scored Services and the scoreboard screenshot both put MySQL on *foreman*. These scripts follow foreman. Verify day one; ask White Team if it differs.

## Usage

Keep `lib/` next to the box script — it's sourced by relative path.

```bash
# Linux
sudo bash s3-fall-2025/storkfront.sh

# Windows, elevated
powershell -ExecutionPolicy Bypass -File .\s3-fall-2025\depot.ps1
```

Each script prompts for your team number and for passwords. Nothing is hardcoded and nothing is committed.

## What these do that most hardening scripts don't

**Simulate the score check before you leave the box.** Every script ends by performing the check the engine performs — anonymous FTP fetch, `nslookup` of the scored record, `jmoney` SELECT on `horsepress` — and prints PASS/FAIL. You find out during the setup window, not from a red square at minute 12.

**Self-heal the content checks.** DNS and FTP get a known-good copy, a hash, and a one-minute timer that restores drift.

**Back up before touching anything.** A restore is 30 seconds. A box revert is a 20-minute uptime penalty.

**Use the free box.** `sonar`/`generator` are out of Red Team scope by rule — so they get a backup vault and two watchers (`hpcc-watch` for reachability, `hpcc-integrity` for content diffing) that Red Team structurally cannot kill.

**Audit instead of delete** where a false positive would cost more than a miss: sudoers, local admins, cron, SUID, IFEO debuggers, sticky-keys hijacks, webshell heuristics. The script prints; you decide.

**Survive Server 2012 R2.** One Windows library, both boxes, honest about the mess.

## Runbook

### Before the round

Clone this before you're on competition wifi. Confirm you can SSH and RDP from your machine. Read the current packet — box names and scored services change every season. Decide who owns which box now, not at 10:01.

### First 15 minutes

**1. Rotate every password (0–2 min).** Before scripts, before firewalls, before anything. `plinktern:IHPLRulez!` is published in the packet; Red Team read the same PDF and is already typing it.

```bash
for u in $(awk -F: '$3>=1000 && $1!="nobody" {print $1}' /etc/passwd); do
  echo "$u:<newpass>" | chpasswd
done
```

Skip the scoring user unless you've filed the PCR first.

**2. Stand up the free box (2–4 min).** It's the only thing on the board Red Team cannot touch.

```bash
sudo bash s3-fall-2025/generator.sh
tmux new -d -s watch     "hpcc-watch <team>"
tmux new -d -s integrity "hpcc-integrity <team>"
```

**3. Run the box scripts in parallel (4–12 min).** One person per box. Each ends with a score-check simulation — **do not walk away from a FAIL.**

**4. Get backups off-box (12–15 min).**

```bash
scp -r /root/hpcc-backup-* plinktern@172.16.<t>.5:/opt/hpcc-vault/<box>/
```

**5. Confirm all green, then start injects.** They're 35% and allow partial credit. Submitting anything beats nothing; late is 50%, which also beats nothing.

### During the round

Triage order when a check goes red: is it a dependency (web red → check the DB box first) → is the service running → has the content changed → restore from backup before considering a revert.

When you find Red Team on a box: remove the implant, block the C2. Do **not** attack the C2, scan them, or touch another team's environment. Instant DQ.

Log off sessions you don't recognize. `query user` / `logoff <id>`, or `who` + `pkill -u`.

### Recovery one-liners

```bash
# DNS zone reverted
chattr -i /etc/bind/db.team<t>.plinko.horse
cp /root/zone.known-good /etc/bind/db.team<t>.plinko.horse
systemctl reload named

# Scored FTP file gone (S2)
chattr -i /var/ftp/ImaHorse.jpg 2>/dev/null
cp -a /root/ftp-backup/ImaHorse.jpg /var/ftp/
chattr +i /var/ftp/ImaHorse.jpg

# WordPress defaced
tar xzf /root/hpcc-backup-*/webroot.tar.gz -C /

# Database wrecked
mysql -u root -p < /root/db-backups/all-databases.sql

# You locked yourself out with chattr
chattr -i <file>   # this is always the answer
```

```powershell
# FTP memos modified (S3)
Copy-Item C:\HPCC-Backup\ftp-memos\* <ftproot>\memos\ -Force

# Firewalled yourself out — use the OpenStack console, then:
netsh advfirewall set allprofiles state off
```

### Things people forget

The OpenStack console always works — it's a virtual monitor and keyboard, it doesn't need the network. Ask Black Team; helping you is their job and rule 7 says you're not penalized for reporting problems. Ask White Team on rules ambiguity. Breaks are hands-off for everyone, Red Team included — eat. Rule 9 is real: failing to have fun is a disqualifiable offense.

## Design notes

**Drop-in configs, not `echo >>`.** Appending isn't idempotent, and sshd takes the *first* occurrence of most directives — so appending to a config that already sets the key silently does nothing. You get a script that looks like it worked and didn't. So: a drop-in at `/etc/ssh/sshd_config.d/99-hpcc.conf` plus an `Include` if the base config lacks one. vsftpd is the inverse — it takes the *last* occurrence — which is arguably worse, because appending *does* work and you end up with a config that contradicts itself three times. That one gets rewritten whole from a known-good template.

**`chattr +i` last, and documented.** It's genuinely good against an attacker with a shell, and equally good against *you* at minute 47 when you can't figure out why `sed` isn't sticking. So it's the last step in every script, and every script prints the `chattr -i` incantation. The DNS self-heal timer has the same edge: it will revert your *legitimate* zone edit within 60 seconds unless you also update `/root/zone.sha256`. Called out in the script's closing output. Real footgun; the alternative is worse.

**Simulate the check, don't assume.** The highest-value 20 lines here. Hardening scripts fail silently by nature — you don't learn that `PasswordAuthentication no` killed your SSH check until the scoreboard tells you, and by then you've lost eight minutes at 65% weight. It's not a perfect simulation: `127.0.0.1` isn't the engine's source address, so it won't catch a too-narrow firewall rule. It catches config errors, which are the common case.

**Audit, don't auto-remediate.** A false positive costs a scored service; a false negative costs a shell you were probably losing anyway. Asymmetric. The webshell grep (`eval(`, `base64_decode(`) hits legitimate WordPress core constantly — auto-deleting takes down HTTP to remove a file that was never malicious. Human in the loop, on a 6-hour clock, is the right call.

**SELinux stays on.** The universal instinct is `setenforce 0` the moment anything misbehaves. On a box whose whole job is serving PHP, SELinux is doing more anti-webshell work than anything else installed. The actual fix is one boolean.

**Firewall by source address, not by binding.** `bind-address = 127.0.0.1` is the textbook step and it takes down two checks. Bind to `0.0.0.0`, restrict by source. Same exposure, without lying to the application about what interface it's on. Same logic for grants: `'jmoney'@'172.16.t.%'`, not `'jmoney'@'%'` — the engine gets in, Red Team's own infrastructure doesn't, even holding the password.

**Prompts, not hardcoded secrets.** The reference scripts this grew from had a literal password in a `passwd` pipeline. Replaced with `read -rsp` throughout, so the repo can be public without a rotation scramble. Consequence: the scripts are interactive and can't run unattended. For a competition where a human watches every box anyway, correct trade.

**What I'd do differently.** Identify the scoring engine's source IP during the round and narrow the subnet rules to that host. Central logging to the safe box (right now each box logs locally, which is exactly where an attacker with root edits them). Golden-image diffing instead of heuristic webshell hunting — pull a clean WordPress of the matching version and `diff -r`; vastly better signal, needs prep. And test against the live images: these are written from the packets, which is why path discovery (`$WEBROOT`, `my.ini`, IIS site names) is best-effort probing with manual fallbacks.

## Caveats

These target specific competition environments from specific years. Box names, IPs, and scored services change every season — the packet says so in a footnote, twice. **Read the current packet before running any of this.** The reasoning above ages better than the code does.

Not a general-purpose hardening baseline. Several choices here — leaving anonymous FTP enabled, keeping password SSH — are correct *for a scored competition* and wrong for production.

Credentials appearing in these scripts (`plinktern:IHPLRulez!`, `hkeating:hkeating`) are published in the public onboarding packets. That's precisely why rotating them in the first two minutes matters more than everything else here combined.

The packets themselves aren't redistributed here; get them from [plinko.horse](https://plinko.horse). HPCC3 rule 5 explicitly permits publicly available free scripts and notes that team-authored scripts don't need to be public. This one is, for whoever's next.

## License

MIT — see [LICENSE](LICENSE).
