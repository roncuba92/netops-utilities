from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Tuple

import requests
from netmiko import ConnectHandler
from requests import RequestException
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = BASE_DIR / "vpn_config.json"

disable_warnings(InsecureRequestWarning)


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handler:
        data = json.load(handler)
    if not isinstance(data, dict):
        raise ValueError("El archivo de configuración debe contener un objeto JSON.")
    return data


def check_fortigate(
    host: str, token: str, tunnel_name: str, vdom: str = "root", verify_ssl: bool = False
) -> Tuple[bool, str]:
    """
    Consulta el monitor de SAs IPsec en FortiGate.
    """
    base = host.rstrip("/")
    url = f"{base}/api/v2/monitor/vpn/ipsec/sa"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"vdom": vdom}
    try:
        response = requests.get(url, headers=headers, params=params, verify=verify_ssl, timeout=10)
        response.raise_for_status()
        payload = response.json()
    except RequestException as exc:
        return False, f"Error HTTP FortiGate: {exc}"
    except ValueError:
        return False, "No se pudo parsear la respuesta JSON de FortiGate."

    results = payload.get("results") or payload.get("data") or []
    for entry in results:
        name = entry.get("name") or entry.get("tunnel")
        status = str(entry.get("status", "")).lower()
        if tunnel_name == name:
            return status in {"up", "active"}, f"Respuesta FortiGate: {entry}"
    return False, f"No se encontró el túnel {tunnel_name} en la respuesta de FortiGate."


def check_paloalto(
    host: str, username: str, password: str, tunnel_name: str, ssh_port: int = 22
) -> Tuple[bool, str]:
    """
    Ejecuta comandos de estado en Palo Alto usando Netmiko.
    """
    device = {
        "device_type": "paloalto_panos",
        "host": host,
        "username": username,
        "password": password,
        "port": ssh_port,
        "fast_cli": False,
    }
    try:
        with ConnectHandler(**device) as conn:
            ike_out = conn.send_command(f"show vpn ike-sa gateway {tunnel_name}")
            ipsec_out = conn.send_command(f"show vpn ipsec-sa tunnel {tunnel_name}")
    except Exception as exc:  # pylint: disable=broad-except
        return False, f"Error al conectar o ejecutar comandos en Palo Alto: {exc}"

    ike_ok = "active" in ike_out.lower() or "established" in ike_out.lower()
    ipsec_ok = "active" in ipsec_out.lower() or "established" in ipsec_out.lower()
    if ike_ok and ipsec_ok:
        return True, "IKE e IPSec activos según CLI de Palo Alto."
    return False, f"IKE_OK={ike_ok}, IPSEC_OK={ipsec_ok}. CLI IKE: {ike_out} | CLI IPSec: {ipsec_out}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Valida estado del túnel IPSec en FortiGate y Palo Alto.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Ruta a vpn_config.json.")
    parser.add_argument("--fortigate-host", required=True, help="URL base hacia FortiGate (ej. https://198.51.100.10).")
    parser.add_argument("--fortigate-token", required=True, help="Token API de FortiGate.")
    parser.add_argument("--fortigate-vdom", default="root", help="VDOM de FortiGate.")
    parser.add_argument("--paloalto-host", required=True, help="IP/hostname de Palo Alto para SSH.")
    parser.add_argument("--paloalto-user", required=True, help="Usuario de Palo Alto.")
    parser.add_argument("--paloalto-password", required=True, help="Contraseña de Palo Alto.")
    parser.add_argument("--paloalto-port", type=int, default=22, help="Puerto SSH de Palo Alto.")
    parser.add_argument("--verify-ssl", action="store_true", help="Verifica certificados TLS en FortiGate.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    cfg = _load_json(args.config)
    tunnel_name = cfg.get("name", "ipsec-tunnel")

    fg_ok, fg_msg = check_fortigate(
        host=args.fortigate_host,
        token=args.fortigate_token,
        tunnel_name=tunnel_name,
        vdom=args.fortigate_vdom,
        verify_ssl=args.verify_ssl,
    )
    pa_ok, pa_msg = check_paloalto(
        host=args.paloalto_host,
        username=args.paloalto_user,
        password=args.paloalto_password,
        tunnel_name=tunnel_name,
        ssh_port=args.paloalto_port,
    )

    summary = {
        "tunnel": tunnel_name,
        "fortigate": {"up": fg_ok, "detail": fg_msg},
        "paloalto": {"up": pa_ok, "detail": pa_msg},
        "overall_up": fg_ok and pa_ok,
    }
    print(json.dumps(summary, indent=2))
    if not (fg_ok and pa_ok):
        sys.exit(1)


if __name__ == "__main__":
    main()
