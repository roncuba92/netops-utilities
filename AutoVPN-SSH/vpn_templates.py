from __future__ import annotations

import json
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Dict, List


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = BASE_DIR / "vpn_config.json"


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handler:
        data = json.load(handler)
    if not isinstance(data, dict):
        raise ValueError("El archivo de configuración debe contener un objeto JSON.")
    return data


def _uniq_list(values: List[str]) -> List[str]:
    uniq: List[str] = []
    for value in values:
        cleaned = str(value).strip()
        if cleaned and cleaned not in uniq:
            uniq.append(cleaned)
    return uniq


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
    phase1_lifetime: int = 28800
    phase2_lifetime: int = 3600
    dpd_interval: int = 10
    fortigate_interface: str = "port1"
    fortigate_inside_interface: str = "internal"
    fortigate_natt: bool = True
    fortigate_net_device: bool = True
    fortigate_static_gateway: str | None = None
    paloalto_tunnel_unit: str = "tunnel.10"
    paloalto_zone: str = "vpn-network"
    paloalto_inside_zone: str = "LAN"
    paloalto_virtual_router: str = "default"
    paloalto_ike_interface: str = "ethernet1/1"
    paloalto_mgmt_profile: str | None = None
    services_inbound: List[str] = field(default_factory=list)  # genérico para ambos (compat)
    services_outbound: List[str] = field(default_factory=list)  # genérico para ambos (compat)
    applications_inbound: List[str] = field(default_factory=list)  # genérico (compat)
    applications_outbound: List[str] = field(default_factory=list)  # genérico (compat)
    services: List[str] = field(default_factory=lambda: ["ALL"])  # compat: valor único si no se declaran listas
    fortigate_services_inbound: List[str] = field(default_factory=list)
    fortigate_services_outbound: List[str] = field(default_factory=list)
    paloalto_services_inbound: List[str] = field(default_factory=list)
    paloalto_services_outbound: List[str] = field(default_factory=list)
    paloalto_applications_inbound: List[str] = field(default_factory=list)
    paloalto_applications_outbound: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.phase2_proposal:
            self.phase2_proposal = self.phase1_proposal
        self.fortigate_local_subnets = _uniq_list(self.fortigate_local_subnets)
        self.paloalto_local_subnets = _uniq_list(self.paloalto_local_subnets)
        base_services = _uniq_list(self.services)
        base_in = _uniq_list(self.services_inbound or base_services)
        base_out = _uniq_list(self.services_outbound or base_services)
        self.services_inbound = base_in
        self.services_outbound = base_out
        self.fortigate_services_inbound = _uniq_list(self.fortigate_services_inbound or base_in or ["ALL"])
        self.fortigate_services_outbound = _uniq_list(self.fortigate_services_outbound or base_out or ["ALL"])
        self.paloalto_services_inbound = _uniq_list(self.paloalto_services_inbound or base_in or ["application-default"])
        self.paloalto_services_outbound = _uniq_list(self.paloalto_services_outbound or base_out or ["application-default"])
        self.applications_inbound = _uniq_list(self.applications_inbound or ["any"])
        self.applications_outbound = _uniq_list(self.applications_outbound or ["any"])
        self.paloalto_applications_inbound = _uniq_list(
            self.paloalto_applications_inbound or self.applications_inbound or ["any"]
        )
        self.paloalto_applications_outbound = _uniq_list(
            self.paloalto_applications_outbound or self.applications_outbound or ["any"]
        )
        self.services = base_services
        if not self.paloalto_mgmt_profile:
            self.paloalto_mgmt_profile = f"{self.name}-icmp"

    def validate(self) -> None:
        ip_address(self.fortigate_wan_ip)
        ip_address(self.paloalto_wan_ip)
        tunnel = ip_network(self.tunnel_cidr, strict=False)
        if ip_address(self.fortigate_tunnel_ip) not in tunnel:
            raise ValueError("La IP de túnel de FortiGate no pertenece a la red declarada.")
        if ip_address(self.paloalto_tunnel_ip) not in tunnel:
            raise ValueError("La IP de túnel de Palo Alto no pertenece a la red declarada.")
        if not self.fortigate_local_subnets or not self.paloalto_local_subnets:
            raise ValueError("Debe haber al menos una subred local por lado.")
        for subnet in self.fortigate_local_subnets + self.paloalto_local_subnets:
            ip_network(subnet, strict=False)
        if self.ike_version.lower() not in {"ikev1", "ikev2"}:
            raise ValueError("ike_version debe ser ikev1 o ikev2.")
        if not self.pre_shared_key:
            raise ValueError("La PSK no puede estar vacía.")


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> VPNConfig:
    data = _load_json(path)
    cfg = VPNConfig(**data)
    cfg.validate()
    return cfg


def build_fortigate_cli(cfg: VPNConfig) -> List[str]:
    tunnel_net = ip_network(cfg.tunnel_cidr, strict=False)
    # FortiGate requiere /32 en interfaces de túnel, aunque la red sea /30.
    tunnel_mask = "255.255.255.255"
    ike_version_num = 2 if cfg.ike_version.lower() == "ikev2" else 1

    commands: List[str] = []
    commands.extend(
        [
            "config vpn ipsec phase1-interface",
            f"edit {cfg.name}",
            f'set interface "{cfg.fortigate_interface}"',
            f"set remote-gw {cfg.paloalto_wan_ip}",
            f'set psksecret "{cfg.pre_shared_key}"',
            f"set ike-version {ike_version_num}",
            f"set proposal {cfg.phase1_proposal}",
            f"set dhgrp {cfg.phase1_dh}",
            f"set keylife {cfg.phase1_lifetime}",
            "set dpd on-idle",
            f"set dpd-retryinterval {cfg.dpd_interval}",
            f"set nattraversal {'enable' if cfg.fortigate_natt else 'disable'}",
            f"set net-device {'enable' if cfg.fortigate_net_device else 'disable'}",
            "next",
            "end",
        ]
    )

    commands.append("config vpn ipsec phase2-interface")
    selectors: List[tuple[str, str]] = []
    for src in cfg.fortigate_local_subnets:
        for dst in cfg.paloalto_local_subnets:
            selectors.append((src, dst))
    for idx, (src, dst) in enumerate(selectors, start=1):
        src_net = ip_network(src, strict=False)
        dst_net = ip_network(dst, strict=False)
        name = f"{cfg.name}-p2-{idx}" if len(selectors) > 1 else f"{cfg.name}-p2"
        commands.extend(
            [
                f"edit {name}",
                f"set phase1name {cfg.name}",
                f"set proposal {cfg.phase2_proposal}",
                "set pfs enable",
                f"set dhgrp {cfg.phase2_pfs}",
                f"set keylifeseconds {cfg.phase2_lifetime}",
                f"set src-subnet {src_net.network_address} {src_net.netmask}",
                f"set dst-subnet {dst_net.network_address} {dst_net.netmask}",
                "next",
            ]
        )
    commands.append("end")

    commands.extend(
        [
            "config system interface",
            f'edit "{cfg.name}"',
            f'set alias "VPN {cfg.name}"',
            "set type tunnel",
            f'set interface "{cfg.fortigate_interface}"',
            f"set ip {cfg.fortigate_tunnel_ip} {tunnel_mask}",
            f"set remote-ip {cfg.paloalto_tunnel_ip} {tunnel_mask}",
            "set allowaccess ping",
            "next",
            "end",
        ]
    )

    commands.append("config router static")
    for dst in cfg.paloalto_local_subnets:
        dst_net = ip_network(dst, strict=False)
        commands.extend(
            [
                "edit 0",
                f"set dst {dst_net.network_address} {dst_net.netmask}",
                *( [f"set gateway {cfg.fortigate_static_gateway}"] if cfg.fortigate_static_gateway is not None else [] ),
                f'set device "{cfg.name}"',
                "set distance 10",
                "next",
            ]
        )
    commands.append("end")

    commands.append("config firewall address")
    for idx, subnet in enumerate(cfg.fortigate_local_subnets, start=1):
        net = ip_network(subnet, strict=False)
        commands.extend(
            [
                f'edit "{cfg.name}-fgt-{idx}"',
                f"set subnet {net.network_address} {net.netmask}",
                "set type ipmask",
                "next",
            ]
        )
    for idx, subnet in enumerate(cfg.paloalto_local_subnets, start=1):
        net = ip_network(subnet, strict=False)
        commands.extend(
            [
                f'edit "{cfg.name}-pa-{idx}"',
                f"set subnet {net.network_address} {net.netmask}",
                "set type ipmask",
                "next",
            ]
        )
    commands.append("end")

    commands.extend(
        [
            "config firewall addrgrp",
            f'edit "grp-{cfg.name}-fgt-local"',
            "set member " + " ".join(f'"{cfg.name}-fgt-{idx}"' for idx in range(1, len(cfg.fortigate_local_subnets) + 1)),
            "next",
            f'edit "grp-{cfg.name}-pa-remote"',
            "set member " + " ".join(f'"{cfg.name}-pa-{idx}"' for idx in range(1, len(cfg.paloalto_local_subnets) + 1)),
            "next",
            "end",
        ]
    )

    # Forti: outbound = hacia Palo Alto (LAN -> VPN), inbound = desde Palo Alto (VPN -> LAN)
    services_out = [
        ("ALL" if str(svc).lower() == "application-default" else svc)
        for svc in (cfg.fortigate_services_outbound or ["ALL"])
    ]
    services_in = [
        ("ALL" if str(svc).lower() == "application-default" else svc)
        for svc in (cfg.fortigate_services_inbound or ["ALL"])
    ]
    services_clause_out = " ".join(f'"{svc}"' for svc in services_out)
    services_clause_in = " ".join(f'"{svc}"' for svc in services_in)
    commands.extend(
        [
            "config firewall policy",
            "edit 0",
            f'set name "{cfg.name}-lan-to-vpn"',
            f'set srcintf "{cfg.fortigate_inside_interface}"',
            f'set dstintf "{cfg.name}"',
            f'set srcaddr "grp-{cfg.name}-fgt-local"',
            f'set dstaddr "grp-{cfg.name}-pa-remote"',
            "set action accept",
            "set schedule always",
            f"set service {services_clause_out}",
            "set logtraffic all",
            "set nat disable",
            "next",
            "edit 0",
            f'set name "{cfg.name}-vpn-to-lan"',
            f'set srcintf "{cfg.name}"',
            f'set dstintf "{cfg.fortigate_inside_interface}"',
            f'set srcaddr "grp-{cfg.name}-pa-remote"',
            f'set dstaddr "grp-{cfg.name}-fgt-local"',
            "set action accept",
            "set schedule always",
            f"set service {services_clause_in}",
            "set logtraffic all",
            "set nat disable",
            "next",
            "end",
        ]
    )
    return commands


def _pan_cipher(enc: str) -> str:
    normalized = enc.replace("_", "-").replace(" ", "").lower()
    if normalized in {"aes256", "aes-256", "aes256cbc", "aes-256-cbc"}:
        return "aes-256-cbc"
    if normalized in {"aes192", "aes-192", "aes192cbc", "aes-192-cbc"}:
        return "aes-192-cbc"
    if normalized in {"aes128", "aes-128", "aes128cbc", "aes-128-cbc"}:
        return "aes-128-cbc"
    if normalized in {"3des", "triple-des"}:
        return "3des"
    return enc


def _split_proposal(proposal: str) -> tuple[str, str]:
    parts = [item.strip() for item in proposal.split("-") if item.strip()]
    if len(parts) >= 2:
        return parts[0], parts[1]
    return proposal.strip(), "sha256"


def _pa_list_clause(values: List[str], default: str) -> str:
    cleaned = _uniq_list(values)
    if not cleaned:
        return default
    if len(cleaned) == 1:
        return cleaned[0]
    return "[ " + " ".join(cleaned) + " ]"


def build_paloalto_cli(cfg: VPNConfig) -> List[str]:
    ike_enc_raw, ike_hash = _split_proposal(cfg.phase1_proposal)
    esp_enc_raw, esp_hash = _split_proposal(cfg.phase2_proposal or cfg.phase1_proposal)
    ike_enc = _pan_cipher(ike_enc_raw)
    esp_enc = _pan_cipher(esp_enc_raw)
    prefix = ip_network(cfg.tunnel_cidr, strict=False).prefixlen
    ike_profile = f"{cfg.name}-ike"
    ipsec_profile = f"{cfg.name}-ipsec"
    mgmt_profile = cfg.paloalto_mgmt_profile or f"{cfg.name}-icmp"

    commands: List[str] = []
    # Objetos de direcciones (separa nombres para cada lado)
    addr_map: Dict[str, str] = {}
    for idx, subnet in enumerate(cfg.fortigate_local_subnets, start=1):
        name = f"{cfg.name}-fgt-net-{idx}"
        addr_map[subnet] = name
        commands.append(f"set address {name} ip-netmask {subnet}")
    for idx, subnet in enumerate(cfg.paloalto_local_subnets, start=1):
        name = f"{cfg.name}-pa-net-{idx}"
        addr_map[subnet] = name
        commands.append(f"set address {name} ip-netmask {subnet}")

    # Perfiles IKE/IPSec
    commands.extend(
        [
            f"set network ike crypto-profiles ike-crypto-profiles {ike_profile} encryption {ike_enc}",
            f"set network ike crypto-profiles ike-crypto-profiles {ike_profile} hash {ike_hash}",
            f"set network ike crypto-profiles ike-crypto-profiles {ike_profile} dh-group group{cfg.phase1_dh}",
            f"set network ike crypto-profiles ike-crypto-profiles {ike_profile} lifetime seconds {cfg.phase1_lifetime}",
            f"set network ike crypto-profiles ipsec-crypto-profiles {ipsec_profile} esp encryption {esp_enc}",
            f"set network ike crypto-profiles ipsec-crypto-profiles {ipsec_profile} esp authentication {esp_hash}",
            f"set network ike crypto-profiles ipsec-crypto-profiles {ipsec_profile} dh-group group{cfg.phase2_pfs}",
            f"set network ike crypto-profiles ipsec-crypto-profiles {ipsec_profile} lifetime seconds {cfg.phase2_lifetime}",
            f"set network ike gateway {cfg.name} authentication pre-shared-key key '{cfg.pre_shared_key}'",
            f"set network ike gateway {cfg.name} local-address interface {cfg.paloalto_ike_interface}",
            f"set network ike gateway {cfg.name} peer-address ip {cfg.fortigate_wan_ip}",
            f"set network ike gateway {cfg.name} protocol {cfg.ike_version.lower()}",
            f"set network ike gateway {cfg.name} protocol version {cfg.ike_version.lower()}",
            f"set network ike gateway {cfg.name} protocol {cfg.ike_version.lower()} ike-crypto-profile {ike_profile}",
        ]
    )

    # Perfil de management para permitir ping al túnel
    commands.append(f"set network profiles interface-management-profile {mgmt_profile} ping yes")

    commands.extend(
        [
            f"set network tunnel ipsec {cfg.name} auto-key ike-gateway {cfg.name}",
            f"set network tunnel ipsec {cfg.name} auto-key ipsec-crypto-profile {ipsec_profile}",
            f"set network tunnel ipsec {cfg.name} auto-key enable yes",
            f"set network tunnel ipsec {cfg.name} tunnel-interface {cfg.paloalto_tunnel_unit}",
            f"set network interface tunnel units {cfg.paloalto_tunnel_unit} ip {cfg.paloalto_tunnel_ip}/{prefix}",
            f"set network interface tunnel units {cfg.paloalto_tunnel_unit} comment 'VPN a FortiGate {cfg.name}'",
            f"set network interface tunnel units {cfg.paloalto_tunnel_unit} interface-management-profile {mgmt_profile}",
            f"set network virtual-router {cfg.paloalto_virtual_router} interface {cfg.paloalto_tunnel_unit}",
            f"set zone {cfg.paloalto_zone} network layer3 {cfg.paloalto_tunnel_unit}",
        ]
    )

    # Rutas a las subredes de FortiGate
    for idx, subnet in enumerate(cfg.fortigate_local_subnets, start=1):
        route_name = f"to-{cfg.name}-{idx}" if len(cfg.fortigate_local_subnets) > 1 else f"to-{cfg.name}"
        commands.append(
            f"set network virtual-router {cfg.paloalto_virtual_router} routing-table ip static-route {route_name} destination {subnet} interface {cfg.paloalto_tunnel_unit} nexthop ip-address {cfg.fortigate_tunnel_ip}"
        )

    # Política de seguridad básica
    services_in = cfg.paloalto_services_inbound or cfg.services_inbound or ["application-default"]
    services_out = cfg.paloalto_services_outbound or cfg.services_outbound or ["application-default"]
    applications_in = cfg.paloalto_applications_inbound or cfg.applications_inbound or ["any"]
    applications_out = cfg.paloalto_applications_outbound or cfg.applications_outbound or ["any"]
    services_clause_in = _pa_list_clause(services_in, default="application-default")
    services_clause_out = _pa_list_clause(services_out, default="application-default")
    apps_clause_in = _pa_list_clause(applications_in, default="any")
    apps_clause_out = _pa_list_clause(applications_out, default="any")
    pa_sources = "[ " + " ".join(addr_map[sub] for sub in cfg.paloalto_local_subnets) + " ]"
    fgt_sources = "[ " + " ".join(addr_map[sub] for sub in cfg.fortigate_local_subnets) + " ]"
    inbound_name = f"{cfg.name}-inbound-allow"
    outbound_name = f"{cfg.name}-outbound-allow"
    commands.append(
        f"set rulebase security rules {inbound_name} from {cfg.paloalto_zone} to {cfg.paloalto_inside_zone} source {fgt_sources} destination {pa_sources} application {apps_clause_in} service {services_clause_in} action allow"
    )
    commands.append(
        f"set rulebase security rules {outbound_name} from {cfg.paloalto_inside_zone} to {cfg.paloalto_zone} source {pa_sources} destination {fgt_sources} application {apps_clause_out} service {services_clause_out} action allow"
    )

    # Proxy IDs
    selectors: List[tuple[str, str]] = []
    for src in cfg.paloalto_local_subnets:
        for dst in cfg.fortigate_local_subnets:
            selectors.append((src, dst))
    for idx, (src, dst) in enumerate(selectors, start=1):
        proxy_name = f"{cfg.name}-p2-{idx}" if len(selectors) > 1 else f"{cfg.name}-p2"
        commands.append(
            f"set network tunnel ipsec {cfg.name} auto-key proxy-id {proxy_name} local {src} remote {dst} protocol any"
        )
    commands.append("commit")
    return commands


def render_plan(cfg: VPNConfig) -> str:
    params = "\n".join(
        [
            f"- Nombre: {cfg.name}",
            f"- WAN FortiGate: {cfg.fortigate_wan_ip}",
            f"- WAN Palo Alto: {cfg.paloalto_wan_ip}",
            f"- Red de túnel /30: {cfg.tunnel_cidr} (FGT {cfg.fortigate_tunnel_ip}, PA {cfg.paloalto_tunnel_ip})",
            f"- Subredes FortiGate: {', '.join(cfg.fortigate_local_subnets)}",
            f"- Subredes Palo Alto: {', '.join(cfg.paloalto_local_subnets)}",
            f"- PSK: {cfg.pre_shared_key}",
            f"- Phase1: {cfg.phase1_proposal} DH{cfg.phase1_dh} {cfg.ike_version.upper()} lifetime {cfg.phase1_lifetime}s",
            f"- Phase2: {cfg.phase2_proposal} PFS{cfg.phase2_pfs} lifetime {cfg.phase2_lifetime}s",
        ]
    )
    tools = "\n".join(
        [
            "- SSH/CLI con Netmiko (FortiGate `fortinet`, Palo Alto `paloalto_panos`).",
            "- Python 3 para generar comandos y aplicarlos.",
            "- Git para versionar parámetros y artefactos.",
        ]
    )
    steps = "\n".join(
        [
            "1) Validar parámetros (IPs, /30, subredes).",
            f"2) Generar comandos CLI para FortiGate y Palo Alto en `outputs/` (basado en {cfg.name}).",
            "3) Aplicar por SSH con los scripts incluidos; en Palo Alto terminar con `commit`.",
            "4) Probar con pings entre subredes remotas.",
        ]
    )
    considerations = "\n".join(
        [
            "- NAT-T si hay NAT intermedio; abrir UDP 500/4500 y ESP.",
            "- NTP alineado para evitar fallos de PSK/IKE.",
            "- Propuestas/DH/PFS idénticas en ambos lados.",
            "- Proxy-ID (PA) y selectores (FGT) deben coincidir.",
        ]
    )
    validation = "\n".join(
        [
            "- FortiGate: `get vpn ipsec tunnel summary`, `diagnose vpn ike gateway list`.",
            f"- Palo Alto: `show vpn ike-sa`, `show vpn ipsec-sa`, `test vpn ipsec-sa tunnel {cfg.name}`.",
            "- Ping entre subredes remotas.",
        ]
    )
    alerts = "- Syslog/SNMP o webhook ante caída de SA o `commit` fallido."

    lines = [
        "# Plan de Automatización VPN (SSH)",
        "",
        "## Definición de Parámetros",
        params,
        "",
        "## Herramientas/APIs",
        tools,
        "",
        "## Pasos de Automatización",
        steps,
        "",
        "## Consideraciones Específicas",
        considerations,
        "",
        "## Validación y Alertas",
        validation,
        alerts,
    ]
    return "\n".join(lines).strip() + "\n"
