# Palisade

> DNS-over-HTTPS tunnel for Linux — protect your DNS queries from manipulation.

Palisade is a Linux adaptation of [Jigsaw-Code/Intra](https://github.com/Jigsaw-Code/Intra), an Android app by Google's Jigsaw team that encrypts DNS lookups using DNS-over-HTTPS (DoH).

## How It Works

Palisade creates a TUN device and uses nftables to transparently redirect all DNS (port 53) traffic through a local lwIP stack. DNS queries are intercepted and forwarded to a DoH server (Cloudflare by default) over HTTPS, preventing your ISP or network from snooping on or manipulating your DNS requests.

```
Apps → port 53 → [nftables redirect] → TUN → lwIP → DoH (HTTPS)
```

## Features

- **Transparent interception** — no system DNS config changes needed
- **Web UI** — start/stop, server picker, latency chart, query log
- **Server probe** — test 6 DoH providers, find the fastest
- **systemd service** — run as a daemon with auto-start
- **No UI mode** — `--no-web` for headless deployments

## Quick Start

```bash
# Run directly
sudo ./palisade
# Open http://127.0.0.1:8453

# Install as service
sudo ./install.sh
sudo systemctl enable --now palisade

# CLI options
./palisade -h
```

## Support

<a href="https://trakteer.id/ahmad435" target="_blank">
  <img src="https://cdn.trakteer.id/images/mix/coffee.png" alt="Traktir Kopi di Trakteer" />
</a>

## License

Palisade is a fork of [Jigsaw-Code/Intra](https://github.com/Jigsaw-Code/Intra) and is licensed under **Apache 2.0**.

Core DNS-over-HTTPS engine (`internal/doh/`), tunnel logic (`internal/intra/`), and logging adapted from the original Intra project © Jigsaw Operations LLC.
