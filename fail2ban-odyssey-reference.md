# fail2ban + Odyssey — Reference

How to set up fail2ban, connect it to Odyssey, and run it during manual red teaming.

> Replace `https://odyssey.example.com`, `CHANGE_ME`, and the IPs below with your real values.

---

## 1. Install

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install -y fail2ban curl

# RHEL / Rocky / Alma
sudo dnf install -y epel-release && sudo dnf install -y fail2ban curl

sudo systemctl enable --now fail2ban
```

Never edit `jail.conf` — put your settings in `jail.local` (it overrides `jail.conf` and survives upgrades).

---

## 2. File layout

| Path | Purpose |
|---|---|
| `/etc/fail2ban/jail.local` | Your jails and defaults |
| `/etc/fail2ban/action.d/odyssey.conf` | Custom action that reports to Odyssey |
| `/etc/fail2ban/filter.d/*.conf` | Regex filters that detect failures |
| `/var/log/fail2ban.log` | fail2ban's own log (bans/unbans) |

---

## 3. `/etc/fail2ban/jail.local`

```ini
[DEFAULT]
# IPs that are NEVER banned. Add red-team IPs here only if you do NOT
# want to test the blocking (see section 7).
ignoreip = 127.0.0.1/8 ::1

bantime  = 1h
findtime = 10m
maxretry = 5

# Repeat offenders get longer bans each time
bantime.increment = true
bantime.maxtime   = 1w

backend   = systemd
banaction = nftables-multiport     # use iptables-multiport on older systems

# Ban at the firewall AND report to Odyssey
action = %(action_)s
         odyssey

[sshd]
enabled  = true
port     = ssh                      # change if SSH runs on a custom port, e.g. 2222
maxretry = 3

[nginx-http-auth]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log

[nginx-botsearch]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/access.log

[recidive]
# Bans IPs that keep getting banned by other jails
enabled  = true
logpath  = /var/log/fail2ban.log
bantime  = 1w
findtime = 1d
maxretry = 5
```

---

## 4. Odyssey integration — push (fail2ban → Odyssey)

`/etc/fail2ban/action.d/odyssey.conf`

```ini
[Definition]
actionstart =
actionstop  =
actioncheck =

actionban   = curl -s -m 5 -X POST "<odyssey_url>/api/fail2ban" \
                -H "Content-Type: application/json" \
                -H "Authorization: Bearer <odyssey_token>" \
                -d '{"event":"ban","ip":"<ip>","jail":"<name>","failures":<failures>,"time":<time>,"host":"<fq-hostname>"}'

actionunban = curl -s -m 5 -X POST "<odyssey_url>/api/fail2ban" \
                -H "Content-Type: application/json" \
                -H "Authorization: Bearer <odyssey_token>" \
                -d '{"event":"unban","ip":"<ip>","jail":"<name>","host":"<fq-hostname>"}'

[Init]
odyssey_url   = https://odyssey.example.com
odyssey_token = CHANGE_ME
```

Payload Odyssey receives on a ban:

```json
{
  "event": "ban",
  "ip": "203.0.113.45",
  "jail": "sshd",
  "failures": 3,
  "time": 1761990000,
  "host": "web01.example.com"
}
```

Notes:
- `-m 5` stops a slow Odyssey from blocking fail2ban.
- Lock down permissions since the file holds a token: `sudo chmod 600 /etc/fail2ban/action.d/odyssey.conf`
- If Odyssey has no API yet, test with a webhook catcher first (e.g. a local `nc -l 8080`).

---

## 5. Odyssey integration — pull (Odyssey → fail2ban)

Use this if Odyssey runs on the same host (or over SSH) and you'd rather it fetch data.

**Read the log**

```bash
grep -E "Ban|Unban" /var/log/fail2ban.log
# 2026-11-01 12:00:01,234 fail2ban.actions [1234]: NOTICE  [sshd] Ban 203.0.113.45
```

Regex to parse a line:

```
^(?P<ts>\S+ \S+) fail2ban\.actions\s+\[\d+\]: NOTICE\s+\[(?P<jail>[^\]]+)\] (?P<event>Ban|Unban) (?P<ip>\S+)
```

**Query live state**

```bash
sudo fail2ban-client status                 # list jails
sudo fail2ban-client status sshd            # counts + banned IPs for one jail
sudo fail2ban-client banned                 # all banned IPs (fail2ban >= 0.11)
```

**Control from Odyssey**

```bash
sudo fail2ban-client set sshd banip   203.0.113.45
sudo fail2ban-client set sshd unbanip 203.0.113.45
sudo fail2ban-client unban --all
```

---

## 6. Apply and verify

```bash
sudo fail2ban-client -t                     # test config syntax
sudo systemctl restart fail2ban
sudo fail2ban-client status sshd

# Trigger the Odyssey action without a real attack
sudo fail2ban-client set sshd banip 198.51.100.1
sudo fail2ban-client set sshd unbanip 198.51.100.1

# Watch it live
sudo tail -f /var/log/fail2ban.log
```

Check a filter against a log before trusting it:

```bash
sudo fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf
```

---

## 7. Manual red teaming checklist

**Decide the goal first**

| Goal | Setting |
|---|---|
| Test that detection + blocking works | Do **not** whitelist tester IPs. Each ban = evidence, logged in Odyssey. |
| Test the app itself without being blocked | Add tester IPs to `ignoreip`, restart fail2ban. |

**Before the engagement**
- [ ] Written authorization / scope covering the target hosts
- [ ] Record tester source IPs
- [ ] Console or out-of-band access available (in case you ban yourself)
- [ ] Odyssey receiving test ban/unban events (section 6)

**During**
- Note the time of each attack attempt so you can match it to Odyssey events.
- Useful checks: how many tries before a ban (`maxretry`), whether bans escalate (`bantime.increment`), whether `recidive` catches repeat offenders, whether rotating IPs bypasses it (fail2ban is per-IP).

**If you lock yourself out**

```bash
sudo fail2ban-client unban <your-ip>
# or, last resort
sudo systemctl stop fail2ban
```

**After**
- [ ] Remove temporary `ignoreip` entries
- [ ] `sudo fail2ban-client unban --all` if test bans should be cleared
- [ ] Export Odyssey events for the report

---

## 8. Quick troubleshooting

| Symptom | Check |
|---|---|
| Nothing gets banned | `fail2ban-regex` on the log; correct `logpath` / `backend`? |
| Bans happen but Odyssey gets nothing | Run the `curl` from `odyssey.conf` by hand; check URL/token; `grep odyssey /var/log/fail2ban.log` for errors |
| fail2ban won't start | `sudo fail2ban-client -t`, then `journalctl -u fail2ban -n 50` |
| Banned IP can still connect | `sudo nft list ruleset` (or `iptables -L -n`) — is the right `banaction` / `port` set? |
