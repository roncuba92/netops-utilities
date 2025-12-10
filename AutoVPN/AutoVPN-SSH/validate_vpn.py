from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict

from netmiko import ConnectHandler

from vpn_templates import DEFAULT_CONFIG_PATH, load_config


def _is_ping_success(output: str) -> bool:
    text = output.lower()
    loss_match = re.search(r"(\d+)%\s*packet loss", text)
    if loss_match:
        return int(loss_match.group(1)) < 100
    recv_match = re.search(r"(\d+)\s+packets?\s+received", text)
    if recv_match:
        return int(recv_match.group(1)) > 0
    if "100% packet loss" in text or "0 packets received" in text or "0 packet received" in text:
        return False
    if "bytes from" in text or "icmp_seq" in text:
        return True
    return False


def ping_from_fortigate(host: str, username: str, password: str, source_ip: str, target_ip: str) -> Dict[str, str]:
    device = {
        "device_type": "fortinet",
        "host": host,
        "username": username,
        "password": password,
        "fast_cli": False,
    }
    with ConnectHandler(**device) as conn:
        outputs = []
        outputs.append(conn.send_command(f"execute ping-options source {source_ip}"))
        outputs.append(conn.send_command("execute ping-options repeat-count 3"))
        outputs.append(conn.send_command(f"execute ping {target_ip}"))
        outputs.append(conn.send_command("execute ping-options source 0.0.0.0"))
    combined = "\n".join(outputs)
    return {"ok": str(_is_ping_success(combined)).lower(), "output": combined}


def ping_from_paloalto(host: str, username: str, password: str, source_ip: str, target_ip: str) -> Dict[str, str]:
    device = {
        "device_type": "paloalto_panos",
        "host": host,
        "username": username,
        "password": password,
        "fast_cli": False,
    }
    with ConnectHandler(**device) as conn:
        output = conn.send_command_timing(f"ping count 3 source {source_ip} host {target_ip}", delay_factor=2)
    return {"ok": str(_is_ping_success(output)).lower(), "output": output}


def status_from_fortigate(host: str, username: str, password: str, tunnel_name: str) -> Dict[str, str]:
    device = {
        "device_type": "fortinet",
        "host": host,
        "username": username,
        "password": password,
        "fast_cli": False,
    }
    with ConnectHandler(**device) as conn:
        output = conn.send_command("get vpn ipsec tunnel summary")
    text = output.lower()
    ok = tunnel_name.lower() in text and ("up" in text or "established" in text or "connected" in text)
    return {"ok": str(ok).lower(), "output": output}


def status_from_paloalto(host: str, username: str, password: str, tunnel_name: str) -> Dict[str, str]:
    device = {
        "device_type": "paloalto_panos",
        "host": host,
        "username": username,
        "password": password,
        "fast_cli": False,
    }
    with ConnectHandler(**device) as conn:
        ike_out = conn.send_command(f"show vpn ike-sa gateway {tunnel_name}", expect_string=r"[#>]", delay_factor=2)
        ipsec_out = conn.send_command(f"show vpn ipsec-sa tunnel {tunnel_name}", expect_string=r"[#>]", delay_factor=2)
    text = (ike_out + "\n" + ipsec_out).lower()
    ike_ok = "established" in text or "active" in text
    ipsec_ok = "mature" in text or "tunnel" in text or "child sa" in text
    ok = ike_ok or ipsec_ok
    return {"ok": str(ok).lower(), "output": ike_out + "\n" + ipsec_out}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prueba conectividad entre subredes atravesando el túnel IPSec usando SSH.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Ruta a vpn_config.json.")
    parser.add_argument("--fortigate-host", required=True, help="IP/hostname de FortiGate.")
    parser.add_argument("--fortigate-user", required=True, help="Usuario de FortiGate.")
    parser.add_argument("--fortigate-password", required=True, help="Contraseña de FortiGate.")
    parser.add_argument("--paloalto-host", required=True, help="IP/hostname de Palo Alto.")
    parser.add_argument("--paloalto-user", required=True, help="Usuario de Palo Alto.")
    parser.add_argument("--paloalto-password", required=True, help="Contraseña de Palo Alto.")
    parser.add_argument("--target-from-fgt", help="IP destino a la que FortiGate hará ping (por defecto, la IP de túnel de Palo Alto).")
    parser.add_argument("--target-from-pa", help="IP destino a la que Palo Alto hará ping (por defecto, la IP de túnel de FortiGate).")
    parser.add_argument("--skip-ping", action="store_true", help="Omite los pings y solo consulta el estado de los túneles.")
    parser.add_argument("--verbose", action="store_true", help="Incluye la salida completa de los comandos (por defecto solo ok/fail).")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    cfg = load_config(args.config)

    target_from_fgt = args.target_from_fgt or cfg.paloalto_tunnel_ip
    target_from_pa = args.target_from_pa or cfg.fortigate_tunnel_ip

    try:
        fgt_status = status_from_fortigate(
            host=args.fortigate_host,
            username=args.fortigate_user,
            password=args.fortigate_password,
            tunnel_name=cfg.name,
        )
    except Exception as exc:  # pylint: disable=broad-except
        fgt_status = {"ok": "false", "output": f"Error estado FortiGate: {exc}"}

    try:
        pa_status = status_from_paloalto(
            host=args.paloalto_host,
            username=args.paloalto_user,
            password=args.paloalto_password,
            tunnel_name=cfg.name,
        )
    except Exception as exc:  # pylint: disable=broad-except
        pa_status = {"ok": "false", "output": f"Error estado Palo Alto: {exc}"}

    # Pings opcionales
    if args.skip_ping:
        fgt_ping = {"ok": "unknown", "output": "ping omitido"}
        pa_ping = {"ok": "unknown", "output": "ping omitido"}
    else:
        try:
            fgt_ping = ping_from_fortigate(
                host=args.fortigate_host,
                username=args.fortigate_user,
                password=args.fortigate_password,
                source_ip=cfg.fortigate_tunnel_ip,
                target_ip=target_from_fgt,
            )
        except Exception as exc:  # pylint: disable=broad-except
            fgt_ping = {"ok": "false", "output": f"Error ping FortiGate: {exc}"}

        try:
            pa_ping = ping_from_paloalto(
                host=args.paloalto_host,
                username=args.paloalto_user,
                password=args.paloalto_password,
                source_ip=cfg.paloalto_tunnel_ip,
                target_ip=target_from_pa,
            )
        except Exception as exc:  # pylint: disable=broad-except
            pa_ping = {"ok": "false", "output": f"Error ping Palo Alto: {exc}"}

    summary = {
        "overall_ok": None,
        "fortigate": {
            "target": target_from_fgt,
            "ping_ok": fgt_ping.get("ok"),
            "status_ok": fgt_status.get("ok"),
            "ok": str(fgt_ping.get("ok") == "true" or fgt_status.get("ok") == "true").lower(),
        },
        "paloalto": {
            "target": target_from_pa,
            "ping_ok": pa_ping.get("ok"),
            "status_ok": pa_status.get("ok"),
            "ok": str(pa_ping.get("ok") == "true" or pa_status.get("ok") == "true").lower(),
        },
    }
    summary["overall_ok"] = str(summary["fortigate"]["ok"] == "true" and summary["paloalto"]["ok"] == "true").lower()

    if args.verbose:
        summary["fortigate"]["ping_output"] = fgt_ping.get("output")
        summary["fortigate"]["status_output"] = fgt_status.get("output")
        summary["paloalto"]["ping_output"] = pa_ping.get("output")
        summary["paloalto"]["status_output"] = pa_status.get("output")

    print(json.dumps(summary, indent=2))
    if summary["overall_ok"] != "true":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
