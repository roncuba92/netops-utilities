"""
Generador de plan y ejemplos de automatización para un túnel IPSec
entre FortiGate y Palo Alto. Ejecuta:

    python vpn.py --output VPN_PLAN.md

El script valida parámetros básicos, produce payloads de ejemplo para
las APIs REST y genera un documento Markdown con el plan de trabajo,
pasos, consideraciones y comandos de validación.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import List, Dict, Any

def _parse_subnets(values: List[str]) -> List[str]:
    """Normaliza una lista de subredes eliminando blancos y duplicados."""
    uniq = []
    for value in values:
        cleaned = value.strip()
        if cleaned and cleaned not in uniq:
            uniq.append(cleaned)
    return uniq

@dataclass
class VPNParams:
    name: str = "fgt-pa-ipsec"
    fortigate_wan_ip: str = "198.51.100.10"
    paloalto_wan_ip: str = "198.51.100.20"
    tunnel_cidr: str = "169.255.1.0/30"
    fortigate_tunnel_ip: str = "169.255.1.1"
    paloalto_tunnel_ip: str = "169.255.1.2"
    fortigate_local_subnets: List[str] = field(default_factory=lambda: ["10.10.0.0/24"])
    paloalto_local_subnets: List[str] = field(default_factory=lambda: ["10.20.0.0/24"])
    pre_shared_key: str = "ChangeMe123!"
    ike_version: str = "ikev2"
    dpd_interval: int = 10
    dpd_retry: int = 3
    phase1_encryption: str = "aes256"
    phase1_integrity: str = "sha256"
    phase1_dh_group: str = "14"
    phase2_encryption: str = "aes256"
    phase2_integrity: str = "sha256"
    phase2_pfs_group: str = "14"
    phase1_lifetime: int = 28800
    phase2_lifetime: int = 3600

    def validate(self) -> None:
        ip_address(self.fortigate_wan_ip)
        ip_address(self.paloalto_wan_ip)
        tunnel_net = ip_network(self.tunnel_cidr, strict=False)
        if ip_address(self.fortigate_tunnel_ip) not in tunnel_net:
            raise ValueError(f"La IP de FortiGate ({self.fortigate_tunnel_ip}) debe pertenecer a {tunnel_net}")
        if ip_address(self.paloalto_tunnel_ip) not in tunnel_net:
            raise ValueError(f"La IP de Palo Alto ({self.paloalto_tunnel_ip}) debe pertenecer a {tunnel_net}")
        for subnet in self.fortigate_local_subnets + self.paloalto_local_subnets:
            ip_network(subnet, strict=False)
        if self.ike_version.lower() not in {"ikev1", "ikev2"}:
            raise ValueError("ike_version debe ser ikev1 o ikev2")
        if self.dpd_interval <= 0 or self.dpd_retry <= 0:
            raise ValueError("dpd_interval y dpd_retry deben ser mayores que cero")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "fortigate_wan_ip": self.fortigate_wan_ip,
            "paloalto_wan_ip": self.paloalto_wan_ip,
            "tunnel_cidr": self.tunnel_cidr,
            "fortigate_tunnel_ip": self.fortigate_tunnel_ip,
            "paloalto_tunnel_ip": self.paloalto_tunnel_ip,
            "fortigate_local_subnets": self.fortigate_local_subnets,
            "paloalto_local_subnets": self.paloalto_local_subnets,
            "pre_shared_key": self.pre_shared_key,
            "ike_version": self.ike_version,
            "dpd_interval": self.dpd_interval,
            "dpd_retry": self.dpd_retry,
            "phase1_encryption": self.phase1_encryption,
            "phase1_integrity": self.phase1_integrity,
            "phase1_dh_group": self.phase1_dh_group,
            "phase2_encryption": self.phase2_encryption,
            "phase2_integrity": self.phase2_integrity,
            "phase2_pfs_group": self.phase2_pfs_group,
            "phase1_lifetime": self.phase1_lifetime,
            "phase2_lifetime": self.phase2_lifetime,
        }


def fortigate_payloads(params: VPNParams) -> Dict[str, Dict[str, Any]]:
    proposal = f"{params.phase1_encryption}-{params.phase1_integrity}"
    return {
        "phase1-interface": {
            "endpoint": "/api/v2/cmdb/vpn.ipsec/phase1-interface",
            "payload": {
                "name": params.name,
                "type": "static",
                "interface": "port1",
                "local-gw": params.fortigate_wan_ip,
                "remote-gw": params.paloalto_wan_ip,
                "psksecret": params.pre_shared_key,
                "ike-version": 2 if params.ike_version.lower() == "ikev2" else 1,
                "proposal": proposal,
                "dpd": "on-idle",
                "dpd-retryinterval": params.dpd_interval,
                "dhgrp": params.phase1_dh_group,
                "keylife": params.phase1_lifetime,
            },
        },
        "phase2-interface": {
            "endpoint": "/api/v2/cmdb/vpn.ipsec/phase2-interface",
            "payload": {
                "phase1name": params.name,
                "name": f"{params.name}-p2",
                "proposal": f"{params.phase2_encryption}-{params.phase2_integrity}",
                "pfs": "enable",
                "dhgrp": params.phase2_pfs_group,
                "keylifeseconds": params.phase2_lifetime,
                "src-subnet": params.fortigate_local_subnets[0],
                "dst-subnet": params.paloalto_local_subnets[0],
            },
        },
        "static-route": {
            "endpoint": "/api/v2/cmdb/router/static",
            "payload": {
                "dst": params.paloalto_local_subnets[0],
                "gateway": params.paloalto_tunnel_ip,
                "device": params.name,
                "distance": 10,
            },
        },
        "policy": {
            "endpoint": "/api/v2/cmdb/firewall/policy",
            "payload": {
                "name": f"to-{params.name}",
                "srcintf": [{"name": "internal"}],
                "dstintf": [{"name": params.name}],
                "srcaddr": [{"name": "all"}],
                "dstaddr": [{"name": "all"}],
                "action": "ipsec",
                "schedule": "always",
                "service": [{"name": "ALL"}],
                "logtraffic": "all",
                "ippool": "disable",
                "nat": "disable",
            },
        },
    }


def paloalto_commands(params: VPNParams) -> List[str]:
    ike_profile = f"{params.name}-ike"
    ipsec_profile = f"{params.name}-ipsec"
    tunnel_iface = "tunnel.10"
    return [
        f"set network ike crypto-profiles ike-crypto-profiles {ike_profile} encryption {params.phase1_encryption}",
        f"set network ike crypto-profiles ike-crypto-profiles {ike_profile} hash {params.phase1_integrity}",
        f"set network ike crypto-profiles ike-crypto-profiles {ike_profile} dh-group group{params.phase1_dh_group}",
        f"set network ike crypto-profiles ike-crypto-profiles {ike_profile} lifetime {params.phase1_lifetime}",
        f"set network ike gateway {params.name} authentication pre-shared-key key '{params.pre_shared_key}'",
        f"set network ike gateway {params.name} local-address ip {params.paloalto_wan_ip}",
        f"set network ike gateway {params.name} peer-address ip {params.fortigate_wan_ip}",
        f"set network ike gateway {params.name} protocol {params.ike_version}",
        f"set network ike gateway {params.name} ike-crypto-profile {ike_profile}",
        f"set network tunnel ipsec-crypto-profiles ipsec-crypto-profiles {ipsec_profile} esp encryption {params.phase2_encryption}",
        f"set network tunnel ipsec-crypto-profiles ipsec-crypto-profiles {ipsec_profile} esp authentication {params.phase2_integrity}",
        f"set network tunnel ipsec-crypto-profiles ipsec-crypto-profiles {ipsec_profile} dh-group group{params.phase2_pfs_group}",
        f"set network tunnel ipsec-crypto-profiles ipsec-crypto-profiles {ipsec_profile} lifetime {params.phase2_lifetime}",
        f"set network tunnel ipsec {params.name} auto-key ike-gateway {params.name}",
        f"set network tunnel ipsec {params.name} auto-key ipsec-crypto-profile {ipsec_profile}",
        f"set network tunnel ipsec {params.name} tunnel-interface {tunnel_iface}",
        f"set network interface tunnel units {tunnel_iface} ip {params.paloalto_tunnel_ip}/{ip_network(params.tunnel_cidr).prefixlen}",
        f"set network interface tunnel units {tunnel_iface} comment 'VPN a FortiGate {params.name}'",
        f"set network virtual-router default interface {tunnel_iface}",
        f"set network virtual-router default routing-table ip static-route to-fortigate destination {params.fortigate_local_subnets[0]} nexthop ip-address {params.fortigate_tunnel_ip}",
        f"set network zone vpn-network network layer3 {tunnel_iface}",
        f"set rulebase security rules allow-ipsec from vpn-network to vpn-network source {params.paloalto_local_subnets[0]} destination {params.fortigate_local_subnets[0]} application any service application-default action allow",
    ]


def render_plan(params: VPNParams) -> str:
    fortigate = fortigate_payloads(params)
    paloalto = paloalto_commands(params)
    fgt_api = "\n".join(f"- {name}: {data['endpoint']}" for name, data in fortigate.items())
    paloalto_cmds = "\n".join(paloalto)
    fortigate_json = json.dumps(fortigate, indent=2)

    lines = [
        "# Plan de Automatización VPN IPSec (FortiGate ↔ Palo Alto)",
        "",
        "## Definición de Parámetros (ejemplo)",
        f"- Nombre del túnel: {params.name}",
        f"- IP WAN FortiGate: {params.fortigate_wan_ip}",
        f"- IP WAN Palo Alto: {params.paloalto_wan_ip}",
        f"- Red de túnel: {params.tunnel_cidr} (FGT {params.fortigate_tunnel_ip}, PA {params.paloalto_tunnel_ip})",
        f"- Subredes locales FortiGate: {', '.join(params.fortigate_local_subnets)}",
        f"- Subredes locales Palo Alto: {', '.join(params.paloalto_local_subnets)}",
        f"- Pre-shared key: **{params.pre_shared_key}**",
        f"- IKE: {params.phase1_encryption}/{params.phase1_integrity} DH{params.phase1_dh_group} vida {params.phase1_lifetime}s ({params.ike_version.upper()})",
        f"- IPSec: {params.phase2_encryption}/{params.phase2_integrity} PFS{params.phase2_pfs_group} vida {params.phase2_lifetime}s",
        f"- DPD: cada {params.dpd_interval}s, reintentos {params.dpd_retry}",
        "",
        "## Herramientas/APIs sugeridas",
        "- FortiGate REST (`/api/v2`): crear phase1-interface, phase2-interface, rutas y políticas; soporta token API y HTTPS.",
        "- Palo Alto REST/XML API (`type=config&action=set` o REST v10+): carga en candidate-config y requiere `commit`.",
        "- SSH como respaldo para ambos (bibliotecas Netmiko/Paramiko) para dispositivos sin API habilitada.",
        "- Control de versiones: guardar payloads/plantillas en Git y parametrizar con variables de entorno (psk, IPs, interfaces).",
        "",
        "## Pasos de Automatización (alto nivel)",
        "1) Validar parámetros de entrada (IPs válidas, subred de túnel /30, PSK no vacía).",
        f"2) FortiGate: crear Phase1 con peer {params.paloalto_wan_ip}, PSK y propuestas; habilitar DPD/NAT-T.",
        f"3) FortiGate: crear Phase2 con selectores {params.fortigate_local_subnets[0]} → {params.paloalto_local_subnets[0]}, PFS y lifetime.",
        f"4) FortiGate: asignar IP {params.fortigate_tunnel_ip} al interfaz del túnel, ruta estática hacia {params.paloalto_local_subnets[0]} y política de firewall (sin NAT).",
        f"5) Palo Alto: definir perfiles IKE/IPSec, gateway remoto {params.fortigate_wan_ip}, túnel {params.name}, interfaz {params.tunnel_cidr} IP {params.paloalto_tunnel_ip}.",
        f"6) Palo Alto: agregar el túnel al virtual-router, crear ruta a {params.fortigate_local_subnets[0]} vía {params.fortigate_tunnel_ip}, y regla de seguridad permitiendo el tráfico.",
        "7) Publicar/commit: `execute vpn tunnel up` o `diagnose vpn ike restart` en FGT si se requiere; `commit` en Palo Alto.",
        "8) Validar SAs e intercambio de tráfico (pings entre subredes, trazas y monitoreo de logs).",
        "",
        "## Consideraciones Específicas",
        "- Habilitar NAT-T/keepalive si alguno de los extremos está detrás de NAT.",
        "- Sincronizar hora/NTP para evitar fallas de autenticación por drift de reloj.",
        "- Alinear propuesta IKE/ESP y lifetimes en ambos extremos; cualquier discrepancia levanta fase1 pero no fase2.",
        "- Zones: en Palo Alto, colocar el `tunnel.10` en zona dedicada (p. ej. `vpn-network`) y ajustar políticas desde/hacia esa zona.",
        "- Seguridad: rotar PSK y guardar secretos fuera del repo (variables de entorno o vault).",
        "- Observabilidad: habilitar logs de tráfico y eventos de VPN en ambos dispositivos.",
        "",
        "## Validación y Alertas",
        "- FortiGate: `get vpn ipsec tunnel summary`, `diagnose vpn ike gateway list`, `diagnose debug application ike -1`.",
        f"- Palo Alto: `show vpn ike-sa`, `show vpn ipsec-sa`, `test vpn ipsec-sa tunnel {params.name}`.",
        f"- Probar tráfico real: ping desde {params.fortigate_local_subnets[0].split('/')[0]} hacia {params.paloalto_local_subnets[0].split('/')[0]} y viceversa.",
        "- Alertas: suscribir syslog/SNMP/REST a un sistema externo; disparar alarma si SA baja o si hay renegociaciones frecuentes.",
        "",
        "## Endpoints/Payloads de ejemplo (FortiGate REST)",
        fgt_api,
        "",
        "### Payloads",
        "```json",
        fortigate_json,
        "```",
        "",
        "## Comandos set para Palo Alto (cargar en candidate-config y luego `commit`)",
        "```bash",
        paloalto_cmds,
        "```",
    ]
    return "\n".join(lines).strip()

def build_plan(output: Path, params: VPNParams) -> None:
    params.validate()
    markdown = render_plan(params)
    output.write_text(markdown + "\n", encoding="utf-8")
    print(f"Plan generado en {output}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Genera un plan y ejemplos de payloads para un túnel IPSec FortiGate ↔ Palo Alto.",
    )
    parser.add_argument("--output", default="VPN_PLAN.md", help="Ruta del archivo Markdown de salida.")
    parser.add_argument("--config", help="Ruta a un archivo JSON con parámetros (sobre los valores por defecto).")
    parser.add_argument("--name", help="Nombre del túnel/objetos.")
    parser.add_argument("--fgt-wan", help="IP WAN de FortiGate.")
    parser.add_argument("--pa-wan", help="IP WAN de Palo Alto.")
    parser.add_argument("--tunnel-cidr", help="Red /30 para el túnel.")
    parser.add_argument("--fgt-tunnel-ip", help="IP del lado FortiGate dentro del túnel.")
    parser.add_argument("--pa-tunnel-ip", help="IP del lado Palo Alto dentro del túnel.")
    parser.add_argument("--fgt-local", nargs="+", help="Subred(es) local(es) de FortiGate.")
    parser.add_argument("--pa-local", nargs="+", help="Subred(es) local(es) de Palo Alto.")
    parser.add_argument("--psk", help="Pre-shared key.")
    parser.add_argument("--ike-version", choices=["ikev1", "ikev2"], help="Versión IKE.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    params_dict = VPNParams().as_dict()

    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            raise FileNotFoundError(f"No se encontró el archivo de configuración: {config_path}")
        with config_path.open("r", encoding="utf-8") as archivo_config:
            contenido = json.load(archivo_config)
        if not isinstance(contenido, dict):
            raise ValueError("El archivo de configuración debe ser un JSON con un objeto de parámetros.")
        params_dict.update(contenido)

    if args.name:
        params_dict["name"] = args.name
    if args.fgt_wan:
        params_dict["fortigate_wan_ip"] = args.fgt_wan
    if args.pa_wan:
        params_dict["paloalto_wan_ip"] = args.pa_wan
    if args.tunnel_cidr:
        params_dict["tunnel_cidr"] = args.tunnel_cidr
    if args.fgt_tunnel_ip:
        params_dict["fortigate_tunnel_ip"] = args.fgt_tunnel_ip
    if args.pa_tunnel_ip:
        params_dict["paloalto_tunnel_ip"] = args.pa_tunnel_ip
    if args.fgt_local:
        params_dict["fortigate_local_subnets"] = _parse_subnets(args.fgt_local)
    if args.pa_local:
        params_dict["paloalto_local_subnets"] = _parse_subnets(args.pa_local)
    if args.psk:
        params_dict["pre_shared_key"] = args.psk
    if args.ike_version:
        params_dict["ike_version"] = args.ike_version

    params = VPNParams(**params_dict)
    build_plan(Path(args.output), params)


if __name__ == "__main__":
    main()
