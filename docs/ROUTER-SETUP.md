# Router setup (hand out monitor DNS)

Goal: router DHCP gives all clients the monitor host IP as the DNS server.
Everything else on the router stays as-is.

Replace `192.168.1.5` with the actual static IP of the monitor host, and
reserve that IP by MAC binding in DHCP first.

## Generic IGD (Ростелеком / Sagemcom / Sercomm)

1. WAN → Индивидуальные значения DHCP/IPv4 → DNS-серверы: `192.168.1.5`.
   On Rostelecom units the page is «Настройки интерфейсов LAN / DHCP».
2. Reboot собранного устройства Wi-Fi чтобы клиент взял новый DNS.
3. Some IGD firmwares hand out their own IP as DNS regardless; then instead:
   forward port 53 to the host, or use «Индивидуальные» DNS in the LAN
   section (works on most Sercomm builds).

## OpenWRT

`/etc/config/dhcp`:
```
config dhcp 'lan'
    ...existing...
    list dhcp_option '6,192.168.1.5'
    list dhcp_option '3,192.168.1.1'
```
Apply: `/etc/init.d/dnsmasq restart`.
To *prevent clients from bypassing the resolver* lock down outbound:
```
# /etc/firewall user config:
config rule
    option name 'Block-DoT'
    option src 'lan'
    option dest 'wan'
    option dest_port '853'
    option proto 'tcp udp'
    option target 'REJECT'
```

## MikroTik (RouterOS)

```
/ip dhcp-server network set [find] dns-server=192.168.1.5
# optional: prevent resolver bypass
/ip firewall filter add chain=forward protocol=tcp dst-port=853 action=drop comment="no direct DoT"
```

## Keenetic

- «Мои сети и Wi-Fi» → Сегменты → (LAN) → Настройки TCP/IP →
  «DNS-сервер 1»: `192.168.1.5`.
- Keenetic knows «Интернет-фильтры»; local policy enforcement is done by the
  monitor itself (NXDOMAIN for DoH endpoints), no router filter needed.

## If the router cannot hand out custom DNS

1. Move the listener: `dns_listen: 0.0.0.0:5300` on the monitor host and add
   any DHCP option/брanded «DNS forwarding» the router does support;
2. Or use a static DNS per device (Tablets/PC: Wi-Fi → modify network →
   static DNS) — works for a handful of devices;
3. Or block external resolvers at the Wi-Fi guest segment and let DHCP stay
   ОС-managed (insecure fallback, not recommended).