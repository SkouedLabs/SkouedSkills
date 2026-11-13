#!/usr/bin/python3 -I
"""Refresh the nftables blocklist sets from threat feeds and local lists.

Installed as /usr/local/sbin/nft-blocklist-update, run by nft-blocklist-update.service.
A feed that fails to download, parses to too few entries or shrinks abnormally keeps its
previous cached content. All sets are replaced in a single nft transaction.

Usage: nft-blocklist-update [--config PATH] [--cache-only]
"""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

NFT = "/usr/sbin/nft"
TABLE_FILE = "/etc/nft-blocklist/blocklist.nft"
TOKEN = re.compile(r"[0-9A-Fa-f:.]+(?:/\d{1,3})?")


def log(message):
    print(message, file=sys.stderr)


def parse_network(text):
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def parse_lines(lines):
    """Extract one network per line from plain, netset, Spamhaus legacy or JSON-lines formats."""
    networks = []
    for raw in lines:
        line = re.split(r"[#;]", raw, maxsplit=1)[0].strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                value = json.loads(line).get("cidr")
            except (ValueError, AttributeError):
                continue
            network = parse_network(value) if isinstance(value, str) else None
        else:
            network = next((n for n in map(parse_network, TOKEN.findall(line)) if n), None)
        if network is not None:
            networks.append(network)
    return networks


def is_blockable(network, config):
    if (network.is_private or network.is_loopback or network.is_link_local
            or network.is_multicast or network.is_reserved or network.is_unspecified):
        return False
    min_prefix = config["min_prefix_v4"] if network.version == 4 else config["min_prefix_v6"]
    return network.prefixlen >= min_prefix


def download(url, config):
    if not url.startswith("https://"):
        raise ValueError("feed URL must use https")
    request = urllib.request.Request(url, headers={"User-Agent": "nft-blocklist-update"})
    with urllib.request.urlopen(request, timeout=config["timeout_seconds"]) as response:
        data = response.read(config["max_download_bytes"] + 1)
    if len(data) > config["max_download_bytes"]:
        raise ValueError("feed exceeds max_download_bytes")
    return data.decode("utf-8", errors="replace").splitlines()


def read_cache(path):
    if not path.exists():
        return []
    return parse_lines(path.read_text(encoding="utf-8").splitlines())


def write_atomic(path, text):
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False, encoding="utf-8") as tmp:
        tmp.write(text)
    os.replace(tmp.name, path)


def write_cache(path, networks):
    write_atomic(path, "\n".join(str(n) for n in networks) + "\n")


def refresh_feed(feed, config, cache_dir):
    cache = cache_dir / (feed["name"] + ".list")
    previous = read_cache(cache)
    try:
        fetched = [n for n in parse_lines(download(feed["url"], config)) if is_blockable(n, config)]
    except Exception as error:  # any failure keeps the cached feed
        log("{}: download failed ({}), keeping {} cached entries".format(feed["name"], error, len(previous)))
        return previous
    if len(fetched) < feed.get("min_entries", 1):
        log("{}: only {} entries, keeping cache".format(feed["name"], len(fetched)))
        return previous
    if previous and len(fetched) < len(previous) * (1 - config["max_shrink_ratio"]):
        log("{}: shrank from {} to {} entries, keeping cache".format(feed["name"], len(previous), len(fetched)))
        return previous
    write_cache(cache, fetched)
    log("{}: {} entries".format(feed["name"], len(fetched)))
    return fetched


def read_list(path):
    file = Path(path)
    return parse_lines(file.read_text(encoding="utf-8").splitlines()) if file.exists() else []


def by_family(networks):
    v4 = ipaddress.collapse_addresses(n for n in networks if n.version == 4)
    v6 = ipaddress.collapse_addresses(n for n in networks if n.version == 6)
    return list(v4), list(v6)


def set_commands(name, networks):
    commands = ["flush set inet blocklist {}".format(name)]
    if networks:
        commands.append("add element inet blocklist {} {{ {} }}".format(name, ", ".join(map(str, networks))))
    return commands


def ensure_table():
    listed = subprocess.run([NFT, "list", "table", "inet", "blocklist"], capture_output=True)
    if listed.returncode != 0:
        subprocess.run([NFT, "-f", TABLE_FILE], check=True)


def apply(commands, cache_dir):
    script = cache_dir / "elements.nft"
    write_atomic(script, "\n".join(commands) + "\n")
    subprocess.run([NFT, "-c", "-f", str(script)], check=True)
    subprocess.run([NFT, "-f", str(script)], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default="/etc/nft-blocklist/config.json")
    parser.add_argument("--cache-only", action="store_true", help="apply cached feeds without downloading")
    args = parser.parse_args()

    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    cache_dir = Path(config["cache_dir"])
    cache_dir.mkdir(mode=0o750, parents=True, exist_ok=True)

    feed_networks = []
    for feed in config["feeds"]:
        if not feed.get("enabled", False):
            continue
        if args.cache_only:
            feed_networks += read_cache(cache_dir / (feed["name"] + ".list"))
        else:
            feed_networks += refresh_feed(feed, config, cache_dir)

    allow4, allow6 = by_family(read_list(config["allow_file"]))
    manual4, manual6 = by_family(n for n in read_list(config["manual_file"]) if is_blockable(n, config))
    feed4, feed6 = by_family(feed_networks)

    commands = []
    for name, networks in (("allow4", allow4), ("allow6", allow6), ("manual4", manual4),
                           ("manual6", manual6), ("feed4", feed4), ("feed6", feed6)):
        commands += set_commands(name, networks)

    ensure_table()
    apply(commands, cache_dir)
    log("applied: allow={} manual={} feed={}".format(
        len(allow4) + len(allow6), len(manual4) + len(manual6), len(feed4) + len(feed6)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
