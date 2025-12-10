from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from netmiko import ConnectHandler

from vpn_api_templates import (
    DEFAULT_CONFIG_PATH,
    BASE_DIR,
    VPNConfig,
    build_fortigate_payloads,
    build_paloalto_cli,
    load_config,
    render_plan,
)


class FortiAPIError(RuntimeError):
    """Excepción para respuestas no exitosas de la API FortiGate."""


def _forti_request(
    session: requests.Session,
    host: str,
    method: str,
    path: str,
    vdom: str,
    payload: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
    verify: bool = False,
) -> Dict[str, Any]:
    url = f"https://{host}/api/v2/{path}"
    final_params = dict(params or {})
    final_params.setdefault("vdom", vdom)
    response = session.request(method, url, params=final_params, json=payload, timeout=15, verify=verify)
    try:
        data = response.json()
    except ValueError as exc:
        raise FortiAPIError(f"Respuesta sin JSON ({response.status_code}): {response.text}") from exc
    if data.get("status") != "success":
        raise FortiAPIError(f"{method} {path} falló: {data}")
    return data


def _forti_upsert_simple(
    session: requests.Session,
    host: str,
    base_path: str,
    name: str,
    payload: Dict[str, Any],
    vdom: str,
    verify: bool,
) -> None:
    try:
        _forti_request(session, host, "PUT", f"cmdb/{base_path}/{name}", vdom=vdom, payload=payload, verify=verify)
    except Exception:
        _forti_request(session, host, "POST", f"cmdb/{base_path}", vdom=vdom, payload=payload, verify=verify)


def _forti_find_first(
    session: requests.Session,
    host: str,
    base_path: str,
    filter_expr: str,
    vdom: str,
    verify: bool,
) -> Optional[Dict[str, Any]]:
    data = _forti_request(
        session, host, "GET", f"cmdb/{base_path}", vdom=vdom, params={"filter": filter_expr}, verify=verify
    )
    results = data.get("results") or []
    if not results:
        return None
    return results[0]


def _forti_upsert_policy(
    session: requests.Session,
    host: str,
    payload: Dict[str, Any],
    name: str,
    vdom: str,
    verify: bool,
) -> None:
    existing = _forti_find_first(session, host, "firewall/policy", filter_expr=f"name=={name}", vdom=vdom, verify=verify)
    if existing:
        mkey = existing.get("policyid") or existing.get("q_origin_key")
        _forti_request(
            session, host, "PUT", f"cmdb/firewall/policy/{mkey}", vdom=vdom, payload=payload, verify=verify
        )
    else:
        _forti_request(session, host, "POST", "cmdb/firewall/policy", vdom=vdom, payload=payload, verify=verify)


def _forti_upsert_route(
    session: requests.Session,
    host: str,
    payload: Dict[str, Any],
    vdom: str,
    verify: bool,
) -> None:
    dst = payload["dst"]
    existing = _forti_find_first(session, host, "router/static", filter_expr=f"dst=={dst}", vdom=vdom, verify=verify)
    if existing:
        mkey = existing.get("seq-num") or existing.get("q_origin_key")
        _forti_request(
            session, host, "PUT", f"cmdb/router/static/{mkey}", vdom=vdom, payload=payload, verify=verify
        )
    else:
        _forti_request(session, host, "POST", "cmdb/router/static", vdom=vdom, payload=payload, verify=verify)


def apply_fortigate_api(cfg: VPNConfig, host: str, token: str, vdom: str, verify: bool = False) -> None:
    payloads = build_fortigate_payloads(cfg)
    with requests.Session() as session:
        session.headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        _forti_upsert_simple(session, host, "vpn.ipsec/phase1-interface", cfg.name, payloads["phase1"], vdom, verify)
        for p2 in payloads["phase2"]:
            _forti_upsert_simple(session, host, "vpn.ipsec/phase2-interface", p2["name"], p2, vdom, verify)
        _forti_upsert_simple(session, host, "system/interface", cfg.name, payloads["interface"], vdom, verify)
        for addr in payloads["addresses"]:
            _forti_upsert_simple(session, host, "firewall/address", addr["name"], addr, vdom, verify)
        for grp in payloads["addrgrps"]:
            _forti_upsert_simple(session, host, "firewall/addrgrp", grp["name"], grp, vdom, verify)
        for pol in payloads["policies"]:
            _forti_upsert_policy(session, host, pol, pol["name"], vdom, verify)
        for route in payloads["routes"]:
            _forti_upsert_route(session, host, route, vdom, verify)


def _push_paloalto(host: str, username: str, password: str, commands: List[str]) -> str:
    device = {
        "device_type": "paloalto_panos",
        "host": host,
        "username": username,
        "password": password,
        "fast_cli": False,
    }
    with ConnectHandler(**device) as conn:
        output = conn.send_config_set(commands)
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Aplica la configuración IPSec: FortiGate vía API REST y Palo Alto vía SSH/Netmiko."
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Ruta al vpn_config.json.")
    parser.add_argument("--fortigate-host", required=True, help="IP/hostname de FortiGate (API).")
    parser.add_argument("--fortigate-token", required=True, help="Token de API Bearer para FortiGate.")
    parser.add_argument("--fortigate-vdom", default="root", help="VDOM a usar (por defecto root).")
    parser.add_argument(
        "--fortigate-verify",
        action="store_true",
        help="Verifica el certificado SSL del FortiGate (por defecto se desactiva).",
    )
    parser.add_argument("--paloalto-host", required=True, help="IP/hostname de Palo Alto.")
    parser.add_argument("--paloalto-user", required=True, help="Usuario de Palo Alto.")
    parser.add_argument("--paloalto-password", required=True, help="Contraseña de Palo Alto.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=BASE_DIR / "outputs",
        help="Dónde guardar los payloads/artefactos generados.",
    )
    parser.add_argument("--skip-paloalto", action="store_true", help="No aplica cambios en Palo Alto, solo FortiGate.")
    parser.add_argument("--dry-run", action="store_true", help="Solo genera artefactos, no aplica en dispositivos.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    cfg = load_config(args.config)
    forti_payloads = build_fortigate_payloads(cfg)
    pa_commands = build_paloalto_cli(cfg)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "fortigate_payloads.json").write_text(json.dumps(forti_payloads, indent=2), encoding="utf-8")
    (args.output_dir / "paloalto_cli.txt").write_text("\n".join(pa_commands) + "\n", encoding="utf-8")
    (args.output_dir / "plan.md").write_text(render_plan(cfg), encoding="utf-8")

    if args.dry_run:
        print(f"[DRY-RUN] Artefactos escritos en {args.output_dir}, no se aplicó nada.")
        return

    try:
        print("[FortiGate API] Aplicando payloads...")
        apply_fortigate_api(
            cfg=cfg,
            host=args.fortigate_host,
            token=args.fortigate_token,
            vdom=args.fortigate_vdom,
            verify=args.fortigate_verify,
        )
        print("[FortiGate API] OK.")
    except Exception as exc:  # pylint: disable=broad-except
        raise SystemExit(f"Error aplicando en FortiGate API: {exc}") from exc

    if args.skip_paloalto:
        print("[Palo Alto] Saltado por bandera --skip-paloalto.")
        return

    try:
        print("[Palo Alto SSH] Aplicando configuración y commit...")
        pa_out = _push_paloalto(
            host=args.paloalto_host,
            username=args.paloalto_user,
            password=args.paloalto_password,
            commands=pa_commands,
        )
        print(pa_out)
    except Exception as exc:  # pylint: disable=broad-except
        raise SystemExit(f"Error aplicando en Palo Alto: {exc}") from exc

    print("Configuración aplicada en FortiGate (API) y Palo Alto (SSH).")


if __name__ == "__main__":
    main()
