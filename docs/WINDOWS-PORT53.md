# Windows: freeing UDP/TCP port 53

Windows itself may listen on :53, so `monitor.exe` fails with
`Only one usage of each socket address...`. Culprits:

| Service | Display name | Why it takes 53 |
| --- | --- | --- |
| `Dnscache` | DNS Client | runs a local resolver (Win10+ sometimes binds :53) |
| `SharedAccess` | Internet Connection Sharing | ICS shares a connection incl. DNS proxy |
| `RasMan` / RRAS | Remote Access | RRAS forwarding can bind 53 |

## Find what is actually listening (PowerShell, admin)

```
netstat -ano | findstr ":53 "
```
Note the PID(s) in the last column, then map to process:
```
tasklist /svc /fi "PID eq 4"
```

## Option A: disable the DNS cache (most common)

```
sc.exe config dnscache start= disabled
net stop dnscache
```
`monitor.exe` then binds fine. The host keeps name resolution working
(it will use the router's DNS through the underlying resolution path).

## Option B: disable ICS (SharedAccess)

```
sc.exe config SharedAccess start= disabled
net stop SharedAccess
```
Do this only if you really do not use Internet Connection Sharing.

## Option C: don't fight, move the port

Set `dns_listen: 0.0.0.0:5300` and add a router DHCP/DNS-forward rule, or a
Windows port-proxy:
```
netsh interface portproxy add v4tov4 listenport=53 listenaddress=0.0.0.0 connectport=5300 connectaddress=127.0.0.1
```

## Restore everything back

```
sc.exe config dnscache start= auto
net start dnscache
sc.exe config SharedAccess start= demand
netsh interface portproxy reset
```

## After unlocking

Verify locally:
```
nslookup example.com 127.0.0.1
```
`Server: UnKnown` in the answer is normal (no PTR for 127.0.0.1); the record
must appear on the Live feed.