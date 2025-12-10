from __future__ import annotations

import argparse
from pathlib import Path
from typing import List

from netmiko import ConnectHandler

from vpn_templates import (
    DEFAULT_CONFIG_PATH,
    build_fortigate_cli,
    build_paloalto_cli,
    load_config,
)


def _push_commands(host: str, username: str, password: str, device_type: str, commands: List[str]) -> str:
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "fast_cli": False,
    }
    with ConnectHandler(**device) as conn:
        output = conn.send_config_set(commands)
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Aplica la configuración IPSec vía SSH/Netmiko en FortiGate y Palo Alto.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Ruta al vpn_config.json.")
    parser.add_argument("--fortigate-host", required=True, help="IP/hostname de FortiGate.")
    parser.add_argument("--fortigate-user", required=True, help="Usuario de FortiGate.")
    parser.add_argument("--fortigate-password", required=True, help="Contraseña de FortiGate.")
    parser.add_argument("--paloalto-host", required=True, help="IP/hostname de Palo Alto.")
    parser.add_argument("--paloalto-user", required=True, help="Usuario de Palo Alto.")
    parser.add_argument("--paloalto-password", required=True, help="Contraseña de Palo Alto.")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent / "outputs", help="Dónde guardar los comandos generados.")
    parser.add_argument("--dry-run", action="store_true", help="Solo genera archivos en outputs, no aplica en los dispositivos.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    cfg = load_config(args.config)
    fgt_commands = build_fortigate_cli(cfg)
    pa_commands = build_paloalto_cli(cfg)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "fortigate_cli.txt").write_text("\n".join(fgt_commands) + "\n", encoding="utf-8")
    (args.output_dir / "paloalto_cli.txt").write_text("\n".join(pa_commands) + "\n", encoding="utf-8")

    if args.dry_run:
        print(f"[DRY-RUN] Comandos escritos en {args.output_dir}, no se aplicó nada.")
        return

    try:
        print("[FortiGate] Aplicando configuración por SSH...")
        fgt_out = _push_commands(
            host=args.fortigate_host,
            username=args.fortigate_user,
            password=args.fortigate_password,
            device_type="fortinet",
            commands=fgt_commands,
        )
        print(fgt_out)
    except Exception as exc:  # pylint: disable=broad-except
        raise SystemExit(f"Error aplicando en FortiGate: {exc}") from exc

    try:
        print("[Palo Alto] Aplicando configuración por SSH...")
        pa_out = _push_commands(
            host=args.paloalto_host,
            username=args.paloalto_user,
            password=args.paloalto_password,
            device_type="paloalto_panos",
            commands=pa_commands,
        )
        print(pa_out)
    except Exception as exc:  # pylint: disable=broad-except
        raise SystemExit(f"Error aplicando en Palo Alto: {exc}") from exc

    print("Configuración aplicada en ambos dispositivos.")


if __name__ == "__main__":
    main()
