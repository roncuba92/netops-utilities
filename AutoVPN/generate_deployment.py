from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field, fields
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Dict, List, Tuple

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = BASE_DIR / "vpn_config.json"
DEFAULT_OUTPUT_DIR = BASE_DIR / "outputs"


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handler:
        data = json.load(handler)
    if not isinstance(data, dict):
        raise ValueError("El archivo de configuración debe contener un objeto JSON.")
    return data

def _normalize_config(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Acepta nombres heredados (phase1_encryption/phase1_integrity, etc.)
    y devuelve solo las claves que entiende VPNConfig.
    """
    data = dict(raw)
    if "fortigate_policy_services" in data and isinstance(data["fortigate_policy_services"], str):
        data["fortigate_policy_services"] = [svc.strip() for svc in data["fortigate_policy_services"].split(",") if svc.strip()]
    if "fortigate_policy_srcintf" in data and isinstance(data["fortigate_policy_srcintf"], str):
        data["fortigate_policy_srcintf"] = [iface.strip() for iface in data["fortigate_policy_srcintf"].split(",") if iface.strip()]
    if "fortigate_policy_dstintf" in data and isinstance(data["fortigate_policy_dstintf"], str):
        data["fortigate_policy_dstintf"] = [iface.strip() for iface in data["fortigate_policy_dstintf"].split(",") if iface.strip()]
    if "fortigate_policies" in data and isinstance(data["fortigate_policies"], dict):
        data["fortigate_policies"] = [data["fortigate_policies"]]
    if "paloalto_policies" in data and isinstance(data["paloalto_policies"], dict):
        data["paloalto_policies"] = [data["paloalto_policies"]]
    if "phase1_proposal" not in data:
        enc = data.pop("phase1_encryption", None)
        integ = data.pop("phase1_integrity", None)
        if enc and integ:
            data["phase1_proposal"] = f"{enc}-{integ}"
    if "phase2_proposal" not in data:
        enc2 = data.pop("phase2_encryption", None)
        integ2 = data.pop("phase2_integrity", None)
        if enc2 and integ2:
            data["phase2_proposal"] = f"{enc2}-{integ2}"
    if "phase1_dh" not in data and "phase1_dh_group" in data:
        data["phase1_dh"] = str(data.pop("phase1_dh_group"))
    if "phase2_pfs" not in data and "phase2_pfs_group" in data:
        data["phase2_pfs"] = str(data.pop("phase2_pfs_group"))

    valid_fields = {field.name for field in fields(VPNConfig)}
    return {k: v for k, v in data.items() if k in valid_fields}

def _split_proposal(proposal: str) -> Tuple[str, str]:
    """
    Devuelve (encryption, integrity) a partir de cadenas tipo aes256-sha256.
    Si no se puede dividir, asume sha256 como integridad.
    """
    parts = [item.strip() for item in proposal.split("-") if item.strip()]
    if len(parts) >= 2:
        return parts[0], parts[1]
    return proposal.strip(), "sha256"

@dataclass
class VPNConfig:
    name: str
    fortigate_wan_ip: str
    paloalto_wan_ip: str
    tunnel_cidr: str
    fortigate_tunnel_ip: str
    paloalto_tunnel_ip: str
    fortigate_local_subnets: List[str]
    paloalto_local_subnets: List[str]
    pre_shared_key: str
    ike_version: str = "ikev2"
    phase1_proposal: str = "aes256-sha256"
    phase1_dh: str = "14"
    phase2_proposal: str | None = None
    phase2_pfs: str = "14"
    dpd_interval: int = 10
    dpd_retry: int = 3
    phase1_lifetime: int = 28800
    phase2_lifetime: int = 3600
    fortigate_interface: str = "port1"
    paloalto_tunnel_unit: str = "tunnel.10"
    paloalto_zone: str = "vpn-network"
    paloalto_virtual_router: str = "default"
    fortigate_policy_srcintf: List[str] = field(default_factory=lambda: ["internal"])
    fortigate_policy_dstintf: List[str] | None = None
    fortigate_policy_services: List[str] = field(default_factory=lambda: ["PING", "HTTPS", "SSH"])
    fortigate_policies: List[Dict[str, Any]] = field(default_factory=list)
    paloalto_policies: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.phase2_proposal:
            self.phase2_proposal = self.phase1_proposal
        self.fortigate_local_subnets = self._normalize_subnets(self.fortigate_local_subnets)
        self.paloalto_local_subnets = self._normalize_subnets(self.paloalto_local_subnets)
        self.fortigate_policy_srcintf = self._normalize_list(self.fortigate_policy_srcintf)
        if self.fortigate_policy_dstintf is None:
            self.fortigate_policy_dstintf = [self.name]
        else:
            self.fortigate_policy_dstintf = self._normalize_list(self.fortigate_policy_dstintf)
        self.fortigate_policy_services = self._normalize_list(self.fortigate_policy_services)
        self.fortigate_policies = self._normalize_policy_list(
            self.fortigate_policies,
            base_name=f"to-{self.name}",
            default_src_subnets=self.fortigate_local_subnets,
            default_dst_subnets=self.paloalto_local_subnets,
            default_srcintf=self.fortigate_policy_srcintf,
            default_dstintf=self.fortigate_policy_dstintf,
            default_services=self.fortigate_policy_services,
        )
        self.paloalto_policies = self._normalize_policy_list(
            self.paloalto_policies,
            base_name=f"allow-{self.name}",
            default_src_subnets=self.paloalto_local_subnets,
            default_dst_subnets=self.fortigate_local_subnets,
            default_srcintf=[self.paloalto_zone],
            default_dstintf=[self.paloalto_zone],
            default_services=["application-default"],
        )

    @staticmethod
    def _normalize_subnets(subnets: List[str]) -> List[str]:
        uniq: List[str] = []
        for subnet in subnets:
            cleaned = subnet.strip()
            if cleaned and cleaned not in uniq:
                uniq.append(cleaned)
        return uniq

    @staticmethod
    def _normalize_list(values: List[str] | str) -> List[str]:
        if isinstance(values, str):
            items = [values]
        else:
            items = values
        uniq: List[str] = []
        for value in items:
            cleaned = str(value).strip()
            if cleaned and cleaned not in uniq:
                uniq.append(cleaned)
        return uniq

    @staticmethod
    def _normalize_policy_list(
        policies: List[Dict[str, Any]] | Dict[str, Any],
        base_name: str,
        default_src_subnets: List[str],
        default_dst_subnets: List[str],
        default_srcintf: List[str],
        default_dstintf: List[str],
        default_services: List[str],
    ) -> List[Dict[str, Any]]:
        if isinstance(policies, dict):
            policy_list = [policies]
        else:
            policy_list = list(policies)
        if not policy_list:
            policy_list = [
                {
                    "src_subnets": default_src_subnets,
                    "dst_subnets": default_dst_subnets,
                    "srcintf": default_srcintf,
                    "dstintf": default_dstintf,
                    "services": default_services,
                }
            ]

        normalized: List[Dict[str, Any]] = []
        for idx, pol in enumerate(policy_list, start=1):
            data = dict(pol)
            data.setdefault("name", f"{base_name}-{idx}")
            data["src_subnets"] = VPNConfig._normalize_subnets(
                data.get("src_subnets", default_src_subnets)
            )
            data["dst_subnets"] = VPNConfig._normalize_subnets(
                data.get("dst_subnets", default_dst_subnets)
            )
            data["srcintf"] = VPNConfig._normalize_list(data.get("srcintf", default_srcintf))
            data["dstintf"] = VPNConfig._normalize_list(data.get("dstintf", default_dstintf))
            data["services"] = VPNConfig._normalize_list(data.get("services", default_services))
            normalized.append(data)
        return normalized

    def validate(self) -> None:
        ip_address(self.fortigate_wan_ip)
        ip_address(self.paloalto_wan_ip)
        tunnel = ip_network(self.tunnel_cidr, strict=False)
        if ip_address(self.fortigate_tunnel_ip) not in tunnel:
            raise ValueError("La IP de FortiGate del tunel no pertenece a la red declarada.")
        if ip_address(self.paloalto_tunnel_ip) not in tunnel:
            raise ValueError("La IP de Palo Alto del tunel no pertenece a la red declarada.")
        if not self.fortigate_local_subnets or not self.paloalto_local_subnets:
            raise ValueError("Se requiere al menos una subred local por lado.")
        for subnet in self.fortigate_local_subnets + self.paloalto_local_subnets:
            ip_network(subnet, strict=False)
        if self.ike_version.lower() not in {"ikev1", "ikev2"}:
            raise ValueError("ike_version debe ser ikev1 o ikev2.")
        if self.dpd_interval <= 0 or self.dpd_retry <= 0:
            raise ValueError("Los valores de DPD deben ser mayores a cero.")

def build_fortigate_payload(cfg: VPNConfig) -> Dict[str, Any]:
    tunnel_net = ip_network(cfg.tunnel_cidr, strict=False)
    mask = str(tunnel_net.netmask)
    ike_version = 2 if cfg.ike_version.lower() == "ikev2" else 1
    selectors = [
        (src, dst) for src in cfg.fortigate_local_subnets for dst in cfg.paloalto_local_subnets
    ]
    phase2_payloads = []
    for idx, (src, dst) in enumerate(selectors, start=1):
        phase2_payloads.append(
            {
                "phase1name": cfg.name,
                "name": f"{cfg.name}-p2-{idx}" if len(selectors) > 1 else f"{cfg.name}-p2",
                "proposal": cfg.phase2_proposal,
                "pfs": "enable",
                "dhgrp": cfg.phase2_pfs,
                "keylifeseconds": cfg.phase2_lifetime,
                "src-subnet": src,
                "dst-subnet": dst,
            }
        )

    static_routes = []
    for idx, subnet in enumerate(cfg.paloalto_local_subnets, start=1):
        static_routes.append(
            {
                "dst": subnet,
                "gateway": cfg.paloalto_tunnel_ip,
                "device": cfg.name,
                "distance": 10,
                "name": f"to-pa-{idx}" if len(cfg.paloalto_local_subnets) > 1 else f"to-pa",
            }
        )

    fgt_subnets = list(cfg.fortigate_local_subnets)
    pa_subnets = list(cfg.paloalto_local_subnets)

    def _classify_and_add(subnet: str, ifaces: List[str]) -> None:
        if subnet in fgt_subnets or subnet in pa_subnets:
            return
        if cfg.name in ifaces:
            pa_subnets.append(subnet)
        else:
            fgt_subnets.append(subnet)

    for pol in cfg.fortigate_policies:
        for subnet in pol.get("src_subnets", []):
            _classify_and_add(subnet, pol.get("srcintf", []))
        for subnet in pol.get("dst_subnets", []):
            _classify_and_add(subnet, pol.get("dstintf", []))

    fgt_addresses = []
    fgt_addr_map: Dict[str, str] = {}
    for idx, subnet in enumerate(fgt_subnets, start=1):
        name = f"{cfg.name}-fgt-{idx}"
        fgt_addr_map[subnet] = name
        fgt_addresses.append(
            {
                "name": name,
                "subnet": subnet,
                "type": "ipmask",
                "comment": "Subred local FortiGate para tunel",
            }
        )
    pa_addresses = []
    pa_addr_map: Dict[str, str] = {}
    for idx, subnet in enumerate(pa_subnets, start=1):
        name = f"{cfg.name}-pa-{idx}"
        pa_addr_map[subnet] = name
        pa_addresses.append(
            {
                "name": name,
                "subnet": subnet,
                "type": "ipmask",
                "comment": "Subred remota Palo Alto para tunel",
            }
        )
    address_groups = [
        {
            "name": f"grp-{cfg.name}-fgt-local",
            "member": [{"name": addr["name"]} for addr in fgt_addresses],
            "comment": "Agrupa subredes locales FortiGate",
        },
        {
            "name": f"grp-{cfg.name}-pa-remote",
            "member": [{"name": addr["name"]} for addr in pa_addresses],
            "comment": "Agrupa subredes remotas Palo Alto",
        },
    ]

    policy_payloads = []
    group_local = f"grp-{cfg.name}-fgt-local"
    group_remote = f"grp-{cfg.name}-pa-remote"
    for pol in cfg.fortigate_policies:
        src_group = group_local if all(sub in fgt_subnets for sub in pol["src_subnets"]) else group_remote
        dst_group = group_remote if all(sub in pa_subnets for sub in pol["dst_subnets"]) else group_local
        policy_payloads.append(
            {
                "name": pol["name"],
                "srcintf": [{"name": iface} for iface in pol["srcintf"]],
                "dstintf": [{"name": iface} for iface in pol["dstintf"]],
                "srcaddr": [{"name": src_group}],
                "dstaddr": [{"name": dst_group}],
                "action": "ipsec",
                "schedule": "always",
                "service": [{"name": svc} for svc in pol["services"]],
                "logtraffic": "all",
                "nat": "disable",
            }
        )

    return {
        "phase1-interface": {
            "endpoint": "/api/v2/cmdb/vpn.ipsec/phase1-interface",
            "payload": {
                "name": cfg.name,
                "type": "static",
                "interface": cfg.fortigate_interface,
                "local-gw": cfg.fortigate_wan_ip,
                "remote-gw": cfg.paloalto_wan_ip,
                "psksecret": cfg.pre_shared_key,
                "ike-version": ike_version,
                "proposal": cfg.phase1_proposal,
                "dpd": "on-idle",
                "dpd-retryinterval": cfg.dpd_interval,
                "dhgrp": cfg.phase1_dh,
                "keylife": cfg.phase1_lifetime,
                "nattraversal": "enable",
            },
        },
        "phase2-interface": {
            "endpoint": "/api/v2/cmdb/vpn.ipsec/phase2-interface",
            "payloads": phase2_payloads,
        },
        "firewall-address": {
            "endpoint": "/api/v2/cmdb/firewall/address",
            "payloads": fgt_addresses + pa_addresses,
        },
        "firewall-addrgrp": {
            "endpoint": "/api/v2/cmdb/firewall/addrgrp",
            "payloads": address_groups,
        },
        "system-interface": {
            "endpoint": "/api/v2/cmdb/system/interface",
            "payload": {
                "name": cfg.name,
                "type": "tunnel",
                "ip": f"{cfg.fortigate_tunnel_ip} {mask}",
                "remote-ip": cfg.paloalto_tunnel_ip,
                "interface": cfg.fortigate_interface,
                "alias": f"VPN {cfg.name}",
            },
        },
        "static-route": {
            "endpoint": "/api/v2/cmdb/router/static",
            "payloads": static_routes,
        },
        "policy": {
            "endpoint": "/api/v2/cmdb/firewall/policy",
            "payloads": policy_payloads,
        },
    }

def build_paloalto_commands(cfg: VPNConfig) -> List[str]:
    ike_enc, ike_int = _split_proposal(cfg.phase1_proposal)
    esp_enc, esp_int = _split_proposal(cfg.phase2_proposal or cfg.phase1_proposal)
    prefix = ip_network(cfg.tunnel_cidr, strict=False).prefixlen
    ike_profile = f"{cfg.name}-ike"
    ipsec_profile = f"{cfg.name}-ipsec"
    cmds = [
        f"set network ike crypto-profiles ike-crypto-profiles {ike_profile} encryption {ike_enc}",
        f"set network ike crypto-profiles ike-crypto-profiles {ike_profile} hash {ike_int}",
        f"set network ike crypto-profiles ike-crypto-profiles {ike_profile} dh-group group{cfg.phase1_dh}",
        f"set network ike crypto-profiles ike-crypto-profiles {ike_profile} lifetime {cfg.phase1_lifetime}",
        f"set network ike gateway {cfg.name} authentication pre-shared-key key '{cfg.pre_shared_key}'",
        f"set network ike gateway {cfg.name} local-address ip {cfg.paloalto_wan_ip}",
        f"set network ike gateway {cfg.name} peer-address ip {cfg.fortigate_wan_ip}",
        f"set network ike gateway {cfg.name} protocol {cfg.ike_version.lower()}",
        f"set network ike gateway {cfg.name} ike-crypto-profile {ike_profile}",
        f"set network ike gateway {cfg.name} dead-peer-detection interval {cfg.dpd_interval} retry {cfg.dpd_retry}",
        f"set network tunnel ipsec-crypto-profiles ipsec-crypto-profiles {ipsec_profile} esp encryption {esp_enc}",
        f"set network tunnel ipsec-crypto-profiles ipsec-crypto-profiles {ipsec_profile} esp authentication {esp_int}",
        f"set network tunnel ipsec-crypto-profiles ipsec-crypto-profiles {ipsec_profile} dh-group group{cfg.phase2_pfs}",
        f"set network tunnel ipsec-crypto-profiles ipsec-crypto-profiles {ipsec_profile} lifetime {cfg.phase2_lifetime}",
        f"set network tunnel ipsec {cfg.name} auto-key ike-gateway {cfg.name}",
        f"set network tunnel ipsec {cfg.name} auto-key ipsec-crypto-profile {ipsec_profile}",
        f"set network tunnel ipsec {cfg.name} tunnel-interface {cfg.paloalto_tunnel_unit}",
        f"set network interface tunnel units {cfg.paloalto_tunnel_unit} ip {cfg.paloalto_tunnel_ip}/{prefix}",
        f"set network interface tunnel units {cfg.paloalto_tunnel_unit} comment 'VPN a FortiGate {cfg.name}'",
        f"set network virtual-router {cfg.paloalto_virtual_router} interface {cfg.paloalto_tunnel_unit}",
        f"set network zone {cfg.paloalto_zone} network layer3 {cfg.paloalto_tunnel_unit}",
    ]

    for idx, subnet in enumerate(cfg.fortigate_local_subnets, start=1):
        route_name = f"to-{cfg.name}-{idx}" if len(cfg.fortigate_local_subnets) > 1 else f"to-{cfg.name}"
        cmds.append(
            f"set network virtual-router {cfg.paloalto_virtual_router} routing-table ip static-route {route_name} destination {subnet} nexthop ip-address {cfg.fortigate_tunnel_ip}"
        )

    for pol in cfg.paloalto_policies:
        sources = " ".join(pol["src_subnets"])
        destinations = " ".join(pol["dst_subnets"])
        from_zones = " ".join(pol.get("srcintf", [cfg.paloalto_zone])) if pol.get("srcintf") else " ".join([cfg.paloalto_zone])
        to_zones = " ".join(pol.get("dstintf", [cfg.paloalto_zone])) if pol.get("dstintf") else " ".join([cfg.paloalto_zone])
        services = " ".join(pol["services"])
        cmds.append(
            f"set rulebase security rules {pol['name']} from {from_zones} to {to_zones} source {sources} destination {destinations} application any service {services} action allow"
        )
    selectors = [(pa, fgt) for fgt in cfg.fortigate_local_subnets for pa in cfg.paloalto_local_subnets]
    for idx, (pa_subnet, fgt_subnet) in enumerate(selectors, start=1):
        proxy_name = f"{cfg.name}-p2-{idx}" if len(selectors) > 1 else f"{cfg.name}-p2"
        cmds.append(
            f"set network tunnel ipsec {cfg.name} auto-key proxy-id {proxy_name} local {pa_subnet} remote {fgt_subnet} protocol any"
        )
    cmds.append("commit")
    return cmds

def render_markdown(cfg: VPNConfig, fortigate_payload: Dict[str, Any], paloalto_cmds: List[str]) -> str:

    fg_payload_json = json.dumps(fortigate_payload, indent=2)
    paloalto_block = "\n".join(paloalto_cmds)
    endpoints_list = "\n".join(
        f"- {name}: {data['endpoint']}" for name, data in fortigate_payload.items()
    )
    selectors = [
        (src, dst) for src in cfg.fortigate_local_subnets for dst in cfg.paloalto_local_subnets
    ]
    selector_desc = f"{selectors[0][0]} → {selectors[0][1]}"
    if len(selectors) > 1:
        selector_desc += f" (+{len(selectors) - 1} selectores adicionales)"
    pa_route_desc = cfg.paloalto_local_subnets[0]
    if len(cfg.paloalto_local_subnets) > 1:
        pa_route_desc += f" (+{len(cfg.paloalto_local_subnets) - 1} rutas)"
    fgt_route_desc = cfg.fortigate_local_subnets[0]
    if len(cfg.fortigate_local_subnets) > 1:
        fgt_route_desc += f" (+{len(cfg.fortigate_local_subnets) - 1} rutas)"
    consideraciones = "\n".join(
        [
            "- Habilitar NAT-T/keepalive si alguno de los extremos está detrás de NAT.",
            "- Sincronizar hora/NTP para evitar fallas de autenticación por drift de reloj.",
            "- Alinear propuesta IKE/ESP y lifetimes en ambos extremos; cualquier discrepancia levanta fase1 pero no fase2.",
            "- MTU/MSS: ajustar MSS en borde si hay fragmentación; considerar ip-frag en Palo Alto.",
            "- DPD/keepalive: balancear intervalos para evitar falsos positivos en enlaces inestables.",
            "- Zones: en Palo Alto, colocar el `tunnel` en zona dedicada y ajustar políticas desde/hacia esa zona.",
            "- Rutas y zonas: validar que las rutas a subredes remotas usan el tunel y que las políticas permiten ambos sentidos.",
            "- Seguridad: rotar PSK y guardar secretos fuera del repo (variables de entorno o vault).",
            "- Observabilidad: habilitar logs de tráfico y eventos de VPN en ambos dispositivos.",
            "- FortiGate: usar objetos/grupos por subred y grupo de servicios para limitar el alcance del tunel.",
        ]
    )
    pasos = "\n".join(
        [
            "1) Validar parámetros de entrada (IPs válidas, subred de tunel /30, PSK no vacía).",
            f"2) FortiGate: crear Phase1 con peer {cfg.paloalto_wan_ip}, PSK y propuestas; habilitar DPD/NAT-T.",
            f"3) FortiGate: crear Phase2 con selectores {selector_desc}, PFS y lifetime.",
            f"4) FortiGate: asignar IP {cfg.fortigate_tunnel_ip} al interfaz del tunel, rutas estáticas hacia {pa_route_desc} y política de firewall (sin NAT) usando objetos/grupos y servicios permitidos.",
            f"5) Palo Alto: definir perfiles IKE/IPSec, gateway remoto {cfg.fortigate_wan_ip}, tunel {cfg.name}, interfaz {cfg.tunnel_cidr} IP {cfg.paloalto_tunnel_ip}.",
            f"6) Palo Alto: agregar el tunel al virtual-router, crear rutas a {fgt_route_desc} vía {cfg.fortigate_tunnel_ip}, y regla de seguridad permitiendo el tráfico.",
            "7) Publicar/commit: `execute vpn tunnel up` o `diagnose vpn ike restart` en FGT si se requiere; `commit` en Palo Alto.",
            "8) Validar SAs e intercambio de tráfico (pings entre subredes, trazas y monitoreo de logs).",
        ]
    )
    validacion = "\n".join(
        [
            "- FortiGate: `get vpn ipsec tunnel summary`, `diagnose vpn ike gateway list`, `diagnose debug application ike -1`.",
            f"- Palo Alto: `show vpn ike-sa`, `show vpn ipsec-sa`, `test vpn ipsec-sa tunnel {cfg.name}`.",
            f"- Probar tráfico real: ping desde {cfg.fortigate_local_subnets[0].split('/')[0]} hacia {cfg.paloalto_local_subnets[0].split('/')[0]} y viceversa.",
            "- Alertas: suscribir syslog/SNMP/REST a un sistema externo; disparar alarma si SA baja o si hay renegociaciones frecuentes.",
        ]
    )
    why_split = (
        "Se generan archivos separados para aislar configuración (payloads/comandos reutilizables), "
        "documentación (trazabilidad/auditoría) y validación (scripts), reduciendo riesgo de errores "
        "al aplicar cambios y permitiendo versionar cada artefacto por separado."
    )
    fgt_policy_names = ", ".join(pol["name"] for pol in cfg.fortigate_policies) or "N/A"
    pa_policy_names = ", ".join(pol["name"] for pol in cfg.paloalto_policies) or "N/A"
    params_lines = "\n".join(
        [
            f"- Nombre del tunel: {cfg.name}",
            f"- IP WAN FortiGate: {cfg.fortigate_wan_ip}",
            f"- IP WAN Palo Alto: {cfg.paloalto_wan_ip}",
            f"- Red de tunel: {cfg.tunnel_cidr} (FGT {cfg.fortigate_tunnel_ip}, PA {cfg.paloalto_tunnel_ip})",
            f"- Subredes locales FortiGate: {', '.join(cfg.fortigate_local_subnets)}",
            f"- Subredes locales Palo Alto: {', '.join(cfg.paloalto_local_subnets)}",
            f"- Pre-shared key: **{cfg.pre_shared_key}**",
            f"- IKE: {cfg.phase1_proposal} DH{cfg.phase1_dh} lifetime {cfg.phase1_lifetime}s ({cfg.ike_version.upper()})",
            f"- IPSec: {cfg.phase2_proposal} PFS{cfg.phase2_pfs} lifetime {cfg.phase2_lifetime}s",
            f"- DPD: cada {cfg.dpd_interval}s, reintentos {cfg.dpd_retry}",
        ]
    )
    lines = [
        "# Plan de Automatización VPN IPSec (FortiGate ↔ Palo Alto)",
        "",
        "## Definición de Parámetros",
        params_lines,
        "",
        "## Herramientas/APIs sugeridas",
        "- FortiGate REST (`/api/v2`): crear phase1-interface, phase2-interface, rutas y políticas; soporta token API y HTTPS.",
        "- Palo Alto REST/XML API (`type=config&action=set` o REST v10+): carga en candidate-config y requiere `commit`.",
        "- SSH como respaldo para ambos (bibliotecas Netmiko/Paramiko) para dispositivos sin API habilitada.",
        "- Control de versiones: guardar payloads/plantillas en Git y parametrizar con variables de entorno (psk, IPs, interfaces).",
        "",
        "## Pasos de Automatización (alto nivel)",
        pasos,
        "",
        "## Consideraciones y Desafíos",
        consideraciones,
        "",
        "## Validación y Alertas",
        validacion,
        "",
        "## Artefactos generados (opcional en Git)",
        "- `outputs/fortigate_payload.json`: payload listo para `/api/v2/cmdb/...` (ver archivo, no se embebe aquí).",
        "- `outputs/paloalto_commands.txt`: comandos `set` para candidate-config (ver archivo).",
        "- `outputs/VPN_PLAN.md`: este plan.",
        "- `deploy_vpn.py`: aplica payloads/comandos en los equipos (FortiGate REST, Palo Alto SSH).",
        "",
        f"Separación de Configuración y Documentación: {why_split}",
    ]
    return "\n".join(lines).strip() + "\n"

def write_outputs(cfg: VPNConfig, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    fortigate_payload = build_fortigate_payload(cfg)
    paloalto_cmds = build_paloalto_commands(cfg)
    markdown = render_markdown(cfg, fortigate_payload, paloalto_cmds)
    (output_dir / "VPN_PLAN.md").write_text(markdown, encoding="utf-8")
    (output_dir / "fortigate_payload.json").write_text(
        json.dumps(fortigate_payload, indent=2), encoding="utf-8"
    )
    (output_dir / "paloalto_commands.txt").write_text("\n".join(paloalto_cmds) + "\n", encoding="utf-8")

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Genera artefactos de despliegue IPSec (FortiGate ↔ Palo Alto).")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Ruta al vpn_config.json de entrada.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR, help="Directorio para las salidas.")
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    raw_cfg = _load_json(args.config)
    cfg_data = _normalize_config(raw_cfg)
    try:
        cfg = VPNConfig(**cfg_data)
        cfg.validate()
    except Exception as exc:  # pylint: disable=broad-except
        raise SystemExit(f"Error en configuración: {exc}") from exc

    write_outputs(cfg, args.output_dir)
    print(f"Archivos generados en {args.output_dir}")


if __name__ == "__main__":
    main()
