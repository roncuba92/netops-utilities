from __future__ import annotations

import argparse
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests

from vpn_api_templates import DEFAULT_CONFIG_PATH, load_config


def _is_ping_success(output: str) -> bool:
    text = output.lower()
    loss_match = re.search(r"(\d+)%\s*packet loss", text)
    if loss_match and int(loss_match.group(1)) == 100:
        return False
    if "0 packets received" in text or "0 packet received" in text or "100% packet loss" in text:
        return False
    if "bytes from" in text or "icmp_seq" in text:
        return True
    recv_match = re.search(r"\b(\d+)\s+packets?\s+received\b", text)
    if recv_match and int(recv_match.group(1)) > 0:
        return True
    return "success" in text and "fail" not in text


def _extract_state_flags(element: ET.Element) -> Tuple[bool, str]:
    text = ET.tostring(element, encoding="unicode", method="text").lower()
    positives = {"up", "active", "established", "ok", "success", "ready", "mature"}
    negatives = {"down", "inactive", "failed", "init"}
    state_tokens = set()
    for tag in ("state", "status", "result", "stat"):
        for node in element.findall(f".//{tag}"):
            if node.text:
                state_tokens.update(str(node.text).lower().split())
    positive_hit = bool(positives & state_tokens) or any(word in text for word in positives)
    negative_hit = bool(negatives & state_tokens) or any(word in text for word in negatives)
    return positive_hit and not negative_hit, text.strip()


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
        raise RuntimeError(f"[Palo Alto] Respuesta no válida: {response.text}") from exc
    if root.attrib.get("status") != "success":
        raise RuntimeError(f"[Palo Alto] Respuesta de error: {response.text}")
    return root


def check_paloalto_api(
    host: str,
    api_key: str,
    tunnel_name: str,
    source_ip: str,
    target_ip: str,
    verify: bool,
    timeout: float,
    do_ping: bool,
) -> Dict[str, Any]:
    with requests.Session() as session:
        session.trust_env = False
        session.headers.update({"Content-Type": "application/xml"})

        ike_cmd = f"<show><vpn><ike-sa><gateway>{tunnel_name}</gateway></ike-sa></vpn></show>"
        ipsec_cmd = f"<show><vpn><ipsec-sa><tunnel>{tunnel_name}</tunnel></ipsec-sa></vpn></show>"
        ike_root = _pa_request(session, host, api_key, {"type": "op", "cmd": ike_cmd}, verify, timeout)
        ipsec_root = _pa_request(session, host, api_key, {"type": "op", "cmd": ipsec_cmd}, verify, timeout)
        ike_up, ike_text = _extract_state_flags(ike_root)
        ipsec_up, ipsec_text = _extract_state_flags(ipsec_root)

        ping_ok: Optional[bool] = None
        ping_output = ""
        if do_ping:
            ping_cmd = (
                f"<ping><count>3</count><source>{source_ip}</source><host>{target_ip}</host></ping>"
            )
            ping_root = _pa_request(session, host, api_key, {"type": "op", "cmd": ping_cmd}, verify, timeout)
            ping_output = ET.tostring(ping_root, encoding="unicode", method="text")
            ping_ok = _is_ping_success(ping_output)

        ok = ike_up and ipsec_up and (ping_ok is not False)
        details = {
            "ike_state": ike_text,
            "ipsec_state": ipsec_text,
            "ping_output": ping_output if do_ping else "ping omitido",
        }
        return {"ok": ok, "ike_up": ike_up, "ipsec_up": ipsec_up, "ping_ok": ping_ok, "details": details}


def check_fortigate_api(
    host: str,
    token: str,
    tunnel_name: str,
    vdom: str,
    verify: bool,
    timeout: float,
    target_ip: Optional[str],
    do_ping: bool,
) -> Dict[str, Any]:
    with requests.Session() as session:
        session.trust_env = False
        session.headers.update({"Authorization": f"Bearer {token}"})
        status_url = f"https://{host}/api/v2/monitor/vpn/ipsec"
        resp = session.get(status_url, params={"vdom": vdom}, timeout=timeout, verify=verify)
        data = resp.json()
        results = data.get("results") or []
        entries = [item for item in results if str(item.get("name", "")).lower() == tunnel_name.lower()] or results
        state_text = ""
        state_ok = False
        for item in entries:
            state_fields = " ".join(
                str(item.get(key, "")).lower() for key in ("status", "stat", "state", "result", "connection")
            )
            name = item.get("name") or item.get("phase1name") or item.get("id")
            state_text += f"{name}: {state_fields}\n"
            if any(word in state_fields for word in ("up", "connected", "established", "active", "ok", "success")):
                state_ok = True

        ping_ok: Optional[bool] = None
        ping_output = ""
        if do_ping and target_ip:
            # Endpoint de utilitario: devuelve la salida del ping que ejecuta el Forti.
            ping_url = f"https://{host}/api/v2/monitor/system/execute/ping"
            ping_resp = session.get(
                ping_url,
                params={"vdom": vdom, "host": target_ip},
                timeout=timeout,
                verify=verify,
            )
            try:
                ping_json = ping_resp.json()
                ping_output = " ".join(ping_json.get("results") or [])
            except ValueError:
                ping_output = ping_resp.text
            ping_ok = _is_ping_success(ping_output)

        ok = state_ok and (ping_ok is not False)
        return {
            "ok": ok,
            "state_ok": state_ok,
            "ping_ok": ping_ok,
            "details": {"state": state_text.strip(), "ping_output": ping_output or "ping omitido"},
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Valida el estado del túnel IPSec vía API (Palo Alto y opcional FortiGate).")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Ruta a vpn_config.json.")
    parser.add_argument("--paloalto-host", required=True, help="IP/hostname del Palo Alto (API XML).")
    parser.add_argument("--paloalto-api-key", required=True, help="API key de Palo Alto.")
    parser.add_argument("--paloalto-verify", action="store_true", help="Verifica el certificado SSL del Palo Alto.")
    parser.add_argument("--paloalto-timeout", type=float, default=30.0, help="Timeout en segundos para la API de Palo Alto.")
    parser.add_argument("--skip-ping", action="store_true", help="Omite el ping desde Palo Alto/FortiGate.")
    parser.add_argument("--fortigate-host", help="IP/hostname del FortiGate (API REST).")
    parser.add_argument("--fortigate-token", help="Token Bearer del FortiGate.")
    parser.add_argument("--fortigate-vdom", default="root", help="VDOM objetivo (default root).")
    parser.add_argument("--fortigate-verify", action="store_true", help="Verifica el certificado SSL del FortiGate.")
    parser.add_argument("--fortigate-timeout", type=float, default=15.0, help="Timeout en segundos para la API de FortiGate.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    cfg = load_config(args.config)

    palo = check_paloalto_api(
        host=args.paloalto_host,
        api_key=args.paloalto_api_key,
        tunnel_name=cfg.name,
        source_ip=cfg.paloalto_tunnel_ip,
        target_ip=cfg.fortigate_tunnel_ip,
        verify=args.paloalto_verify,
        timeout=args.paloalto_timeout,
        do_ping=not args.skip_ping,
    )

    forti = None
    if args.fortigate_host and args.fortigate_token:
        forti = check_fortigate_api(
            host=args.fortigate_host,
            token=args.fortigate_token,
            tunnel_name=cfg.name,
            vdom=args.fortigate_vdom,
            verify=args.fortigate_verify,
            timeout=args.fortigate_timeout,
            target_ip=cfg.paloalto_tunnel_ip,
            do_ping=not args.skip_ping,
        )

    overall_up = palo["ok"] and (forti["ok"] if forti else True)

    print(f"Palo Alto - IKE:{'UP' if palo['ike_up'] else 'DOWN'} IPSec:{'UP' if palo['ipsec_up'] else 'DOWN'} Ping:{_human_ping(palo['ping_ok'])}")
    if forti:
        print(f"FortiGate - Estado:{'UP' if forti['state_ok'] else 'DOWN'} Ping:{_human_ping(forti['ping_ok'])}")
    print(f"VPN STATUS: {'UP' if overall_up else 'DOWN'}")

    if not overall_up:
        # Mostrar detalles compactos para diagnóstico rápido.
        print("--- detalles ---")
        print(f"Palo Alto IKE/IPSec: {palo['details']['ike_state']} | {palo['details']['ipsec_state']}")
        print(f"Palo Alto ping: {palo['details']['ping_output']}")
        if forti:
            print(f"Forti estado: {forti['details']['state']}")
            print(f"Forti ping: {forti['details']['ping_output']}")
        raise SystemExit(1)


def _human_ping(value: Optional[bool]) -> str:
    if value is None:
        return "SKIPPED"
    return "OK" if value else "FAIL"


if __name__ == "__main__":
    main()
