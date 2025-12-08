from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import requests
from netmiko import ConnectHandler
from requests import RequestException
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "outputs"
FGT_PAYLOAD_PATH = OUTPUT_DIR / "fortigate_payload.json"
PA_COMMANDS_PATH = OUTPUT_DIR / "paloalto_commands.txt"

disable_warnings(InsecureRequestWarning)


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handler:
        data = json.load(handler)
    if not isinstance(data, dict):
        raise ValueError("El archivo JSON debe contener un objeto.")
    return data


def deploy_fortigate(host: str, token: str, payload_file: Path, verify_ssl: bool) -> None:
    base = host.rstrip("/")
    headers = {"Authorization": f"Bearer {token}"}
    data = load_json(payload_file)
    for name, entry in data.items():
        endpoint = entry.get("endpoint")
        if not endpoint:
            print(f"[FortiGate][{name}] endpoint no encontrado", file=sys.stderr)
            continue
        url = f"{base}{endpoint}"
        items: List[Dict[str, Any]] = []
        if "payloads" in entry and isinstance(entry["payloads"], list):
            items = entry["payloads"]
        elif "payload" in entry and isinstance(entry["payload"], dict):
            items = [entry["payload"]]
        else:
            print(f"[FortiGate][{name}] no hay payload/payloads válidos", file=sys.stderr)
            continue
        for idx, payload in enumerate(items, start=1):
            tag = f"{name}[{idx}]" if len(items) > 1 else name
            try:
                resp = requests.post(url, headers=headers, json=payload, verify=verify_ssl, timeout=15)
                resp.raise_for_status()
                print(f"[FortiGate][{tag}] OK {resp.status_code}")
            except RequestException as exc:
                detail = resp.text if "resp" in locals() else str(exc)
                print(f"[FortiGate][{tag}] ERROR: {detail}", file=sys.stderr)


def deploy_paloalto(host: str, username: str, password: str, commands_file: Path) -> None:
    commands = [line.strip() for line in commands_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not commands:
        print("[PaloAlto] No hay comandos en el archivo", file=sys.stderr)
        return
    device = {
        "device_type": "paloalto_panos",
        "host": host,
        "username": username,
        "password": password,
        "fast_cli": False,
    }
    try:
        with ConnectHandler(**device) as conn:
            output = conn.send_config_set(commands)
            print("[PaloAlto] Config output:")
            print(output)
            commit_out = conn.send_command("commit", expect_string=r"#")
            print("[PaloAlto] Commit output:")
            print(commit_out)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"[PaloAlto] ERROR: {exc}", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Aplica configuraciones generadas en FortiGate y Palo Alto.")
    parser.add_argument("--fortigate-host", required=True, help="URL base de FortiGate (ej. https://198.51.100.10)")
    parser.add_argument("--fortigate-token", required=True, help="Token API de FortiGate")
    parser.add_argument("--paloalto-host", required=True, help="Hostname/IP de Palo Alto")
    parser.add_argument("--paloalto-user", required=True, help="Usuario de Palo Alto")
    parser.add_argument("--paloalto-password", required=True, help="Contraseña de Palo Alto")
    parser.add_argument("--verify-ssl", action="store_true", help="Verifica certificados TLS en FortiGate")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    deploy_fortigate(args.fortigate_host, args.fortigate_token, FGT_PAYLOAD_PATH, args.verify_ssl)
    deploy_paloalto(args.paloalto_host, args.paloalto_user, args.paloalto_password, PA_COMMANDS_PATH)


if __name__ == "__main__":
    main()
