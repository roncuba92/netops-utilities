from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
import xml.etree.ElementTree as ET

from vpn_api_templates import (
    DEFAULT_CONFIG_PATH,
    BASE_DIR,
    VPNConfig,
    build_fortigate_payloads,
    build_paloalto_api_payloads,
    load_config,
)


class FortiAPIError(RuntimeError):
    """Excepción para respuestas no exitosas de la API FortiGate."""


class PaloAPIError(RuntimeError):
    """Excepción para respuestas no exitosas de la API de Palo Alto."""


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
        session.trust_env = False  # evita proxies del entorno que bloqueen acceso directo
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


def _pa_request(
    session: requests.Session,
    host: str,
    key: str,
    params: Dict[str, Any],
    verify: bool,
    timeout: float,
) -> ET.Element:
    url = f"https://{host}/api/"
    merged = dict(params)
    merged["key"] = key
    response = session.post(url, params=merged, timeout=timeout, verify=verify)
    try:
        root = ET.fromstring(response.text)
    except ET.ParseError as exc:
        raise PaloAPIError(f"Respuesta no válida: {response.text}") from exc
    if root.attrib.get("status") != "success":
        raise PaloAPIError(response.text)
    return root


def _pa_set(
    session: requests.Session,
    host: str,
    key: str,
    xpath: str,
    element: str,
    verify: bool,
    timeout: float,
) -> None:
    _pa_request(session, host, key, {"type": "config", "action": "set", "xpath": xpath, "element": element}, verify, timeout)


def _pa_edit(
    session: requests.Session,
    host: str,
    key: str,
    xpath: str,
    element: str,
    verify: bool,
    timeout: float,
) -> None:
    _pa_request(session, host, key, {"type": "config", "action": "edit", "xpath": xpath, "element": element}, verify, timeout)


def _pa_commit(session: requests.Session, host: str, key: str, verify: bool, timeout: float) -> None:
    _pa_request(session, host, key, {"type": "commit", "cmd": "<commit></commit>"}, verify, timeout)


def _pa_delete(session: requests.Session, host: str, key: str, xpath: str, verify: bool, timeout: float) -> None:
    _pa_request(session, host, key, {"type": "config", "action": "delete", "xpath": xpath}, verify, timeout)


def apply_paloalto_api(
    cfg: VPNConfig,
    host: str,
    api_key: str,
    vsys: str = "vsys1",
    device: str = "localhost.localdomain",
    verify: bool = False,
    timeout: float = 60.0,
) -> None:
    payloads = build_paloalto_api_payloads(cfg, vsys=vsys, device=device)

    with requests.Session() as session:
        session.trust_env = False  # evita proxies del entorno
        session.headers.update({"Content-Type": "application/xml"})
        # Perfiles/objetos base
        _pa_set(session, host, api_key, payloads["mgmt_profile"]["xpath"], payloads["mgmt_profile"]["element"], verify, timeout)
        _pa_set(session, host, api_key, payloads["tunnel_unit"]["xpath"], payloads["tunnel_unit"]["element"], verify, timeout)
        _pa_set(session, host, api_key, payloads["ike_profile"]["xpath"], payloads["ike_profile"]["element"], verify, timeout)

        # Limpieza previa para evitar restos inválidos
        _pa_delete(
            session,
            host,
            api_key,
            xpath=payloads["ipsec_profile"]["xpath"] + f"/entry[@name='{cfg.name}-ipsec']",
            verify=verify,
            timeout=timeout,
        )
        _pa_delete(
            session,
            host,
            api_key,
            xpath=payloads["ike_gateway"]["xpath"] + f"/entry[@name='{cfg.name}']",
            verify=verify,
            timeout=timeout,
        )
        _pa_delete(
            session,
            host,
            api_key,
            xpath=payloads["ipsec_tunnel"]["xpath"] + f"/entry[@name='{cfg.name}']",
            verify=verify,
            timeout=timeout,
        )
        # Perfiles crypto y gateway
        _pa_set(session, host, api_key, payloads["ipsec_profile"]["xpath"], payloads["ipsec_profile"]["element"], verify, timeout)
        _pa_set(session, host, api_key, payloads["ike_gateway"]["xpath"], payloads["ike_gateway"]["element"], verify, timeout)
        _pa_set(session, host, api_key, payloads["ipsec_tunnel"]["xpath"], payloads["ipsec_tunnel"]["element"], verify, timeout)

        # Anexos VR/zona
        _pa_set(session, host, api_key, payloads["vr_interface"]["xpath"], payloads["vr_interface"]["element"], verify, timeout)
        _pa_set(session, host, api_key, payloads["zone"]["xpath"], payloads["zone"]["element"], verify, timeout)

        # Objetos de direcciones
        for addr in payloads["addresses"]:
            _pa_set(session, host, api_key, addr["xpath"], addr["element"], verify, timeout)

        # Proxy IDs
        for proxy in payloads["proxy_ids"]:
            _pa_set(session, host, api_key, proxy["xpath"], proxy["element"], verify, timeout)

        # Rutas
        for route in payloads["static_routes"]:
            _pa_set(session, host, api_key, route["xpath"], route["element"], verify, timeout)

        # Reglas de seguridad
        for rule in payloads["security_rules"]:
            _pa_set(session, host, api_key, rule["xpath"], rule["element"], verify, timeout)

        _pa_commit(session, host, api_key, verify, timeout * 2)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Aplica la configuración IPSec: FortiGate vía API REST y Palo Alto vía API REST."
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
    parser.add_argument("--paloalto-host", required=True, help="IP/hostname de Palo Alto (API).")
    parser.add_argument("--paloalto-api-key", required=True, help="API key de Palo Alto (XML API).")
    parser.add_argument("--paloalto-vsys", default="vsys1", help="VSYS a usar (default vsys1).")
    parser.add_argument("--paloalto-timeout", type=float, default=60.0, help="Timeout en segundos para llamadas API Palo (commit usa 2x).")
    parser.add_argument(
        "--paloalto-verify",
        action="store_true",
        help="Verifica el certificado SSL del Palo Alto (por defecto desactivado).",
    )
    parser.add_argument("--paloalto-device", default="localhost.localdomain", help="Nombre lógico del dispositivo (default).")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=BASE_DIR / "outputs",
        help="Dónde guardar los payloads/archivos de configuración generados.",
    )
    parser.add_argument("--skip-paloalto", action="store_true", help="No aplica cambios en Palo Alto, solo FortiGate.")
    parser.add_argument("--dry-run", action="store_true", help="Solo genera archivos de configuración, no aplica en dispositivos.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    cfg = load_config(args.config)
    forti_payloads = build_fortigate_payloads(cfg)
    pa_payloads = build_paloalto_api_payloads(cfg, vsys=args.paloalto_vsys, device=args.paloalto_device)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "fortigate_payloads.json").write_text(json.dumps(forti_payloads, indent=2), encoding="utf-8")
    (args.output_dir / "paloalto_payloads.json").write_text(json.dumps(pa_payloads, indent=2), encoding="utf-8")

    if args.dry_run:
        print(f"[DRY-RUN] Archivos de configuración escritos en {args.output_dir}, no se aplicó nada.")
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
        print("[Palo Alto API] Aplicando configuración y commit...")
        apply_paloalto_api(
            cfg=cfg,
            host=args.paloalto_host,
            api_key=args.paloalto_api_key,
            vsys=args.paloalto_vsys,
            device=args.paloalto_device,
            verify=args.paloalto_verify,
            timeout=args.paloalto_timeout,
        )
        print("[Palo Alto API] OK.")
    except Exception as exc:  # pylint: disable=broad-except
        raise SystemExit(f"Error aplicando en Palo Alto API: {exc}") from exc

    print("Configuración aplicada en FortiGate (API) y Palo Alto (API).")


if __name__ == "__main__":
    main()
