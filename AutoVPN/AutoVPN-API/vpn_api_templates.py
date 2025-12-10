from __future__ import annotations

import json
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Dict, List, Tuple

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
    services_inbound: List[str] = field(default_factory=list)
    services_outbound: List[str] = field(default_factory=list)
    applications_inbound: List[str] = field(default_factory=list)
    applications_outbound: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=lambda: ["ALL"])
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


def build_fortigate_payloads(cfg: VPNConfig) -> Dict[str, Any]:
    tunnel_net = ip_network(cfg.tunnel_cidr, strict=False)
    mask32 = "255.255.255.255"
    selectors: List[tuple[str, str]] = []
    for src in cfg.fortigate_local_subnets:
        for dst in cfg.paloalto_local_subnets:
            selectors.append((src, dst))
    pfs_enabled = str(cfg.phase2_pfs).lower() not in {"off", "disable", "disabled", "none", "no"}

    phase1 = {
        "name": cfg.name,
        "interface": cfg.fortigate_interface,
        "remote-gw": cfg.paloalto_wan_ip,
        "psksecret": cfg.pre_shared_key,
        "ike-version": "2" if cfg.ike_version.lower() == "ikev2" else "1",
        "proposal": cfg.phase1_proposal,
        "dhgrp": cfg.phase1_dh,
        "keylife": cfg.phase1_lifetime,
        "dpd-retryinterval": cfg.dpd_interval,
        "nattraversal": "enable" if cfg.fortigate_natt else "disable",
        "net-device": "enable" if cfg.fortigate_net_device else "disable",
        "add-route": "disable",
    }

    phase2_entries: List[Dict[str, Any]] = []
    for idx, (src, dst) in enumerate(selectors, start=1):
        src_net = ip_network(src, strict=False)
        dst_net = ip_network(dst, strict=False)
        name = f"{cfg.name}-p2-{idx}" if len(selectors) > 1 else f"{cfg.name}-p2"
        phase2_entries.append(
            {
                "name": name,
                "phase1name": cfg.name,
                "proposal": cfg.phase2_proposal,
                "pfs": "enable" if pfs_enabled else "disable",
                **({"dhgrp": cfg.phase2_pfs} if pfs_enabled else {}),
                "keylifeseconds": cfg.phase2_lifetime,
                "src-subnet": f"{src_net.network_address} {src_net.netmask}",
                "dst-subnet": f"{dst_net.network_address} {dst_net.netmask}",
            }
        )

    tunnel_iface = {
        "name": cfg.name,
        "alias": f"VPN {cfg.name}",
        "type": "tunnel",
        "interface": cfg.fortigate_interface,
        "ip": f"{cfg.fortigate_tunnel_ip} {mask32}",
        "remote-ip": f"{cfg.paloalto_tunnel_ip} {mask32}",
        "allowaccess": ["ping"],
    }

    addresses: List[Dict[str, Any]] = []
    for idx, subnet in enumerate(cfg.fortigate_local_subnets, start=1):
        net = ip_network(subnet, strict=False)
        addresses.append(
            {"name": f"{cfg.name}-fgt-{idx}", "subnet": f"{net.network_address} {net.netmask}", "type": "ipmask"}
        )
    for idx, subnet in enumerate(cfg.paloalto_local_subnets, start=1):
        net = ip_network(subnet, strict=False)
        addresses.append(
            {"name": f"{cfg.name}-pa-{idx}", "subnet": f"{net.network_address} {net.netmask}", "type": "ipmask"}
        )

    addrgrps = [
        {
            "name": f"grp-{cfg.name}-fgt-local",
            "member": [{"name": f"{cfg.name}-fgt-{idx}"} for idx in range(1, len(cfg.fortigate_local_subnets) + 1)],
        },
        {
            "name": f"grp-{cfg.name}-pa-remote",
            "member": [{"name": f"{cfg.name}-pa-{idx}"} for idx in range(1, len(cfg.paloalto_local_subnets) + 1)],
        },
    ]

    services_out = [
        ("ALL" if str(svc).lower() == "application-default" else svc)
        for svc in (cfg.fortigate_services_outbound or ["ALL"])
    ]
    services_in = [
        ("ALL" if str(svc).lower() == "application-default" else svc)
        for svc in (cfg.fortigate_services_inbound or ["ALL"])
    ]
    policies = [
        {
            "name": f"{cfg.name}-lan-to-vpn",
            "srcintf": [{"name": cfg.fortigate_inside_interface}],
            "dstintf": [{"name": cfg.name}],
            "srcaddr": [{"name": f"grp-{cfg.name}-fgt-local"}],
            "dstaddr": [{"name": f"grp-{cfg.name}-pa-remote"}],
            "action": "accept",
            "schedule": "always",
            "service": [{"name": svc} for svc in services_out],
            "logtraffic": "all",
            "nat": "disable",
        },
        {
            "name": f"{cfg.name}-vpn-to-lan",
            "srcintf": [{"name": cfg.name}],
            "dstintf": [{"name": cfg.fortigate_inside_interface}],
            "srcaddr": [{"name": f"grp-{cfg.name}-pa-remote"}],
            "dstaddr": [{"name": f"grp-{cfg.name}-fgt-local"}],
            "action": "accept",
            "schedule": "always",
            "service": [{"name": svc} for svc in services_in],
            "logtraffic": "all",
            "nat": "disable",
        },
    ]

    routes: List[Dict[str, Any]] = []
    gw = cfg.fortigate_static_gateway or cfg.paloalto_tunnel_ip
    for subnet in cfg.paloalto_local_subnets:
        net = ip_network(subnet, strict=False)
        routes.append(
            {
                "dst": f"{net.network_address} {net.netmask}",
                "device": cfg.name,
                "gateway": gw,
                "distance": 10,
            }
        )

    return {
        "phase1": phase1,
        "phase2": phase2_entries,
        "interface": tunnel_iface,
        "addresses": addresses,
        "addrgrps": addrgrps,
        "policies": policies,
        "routes": routes,
    }


def _pan_cipher(enc: str) -> str:
    """Normaliza el nombre del cifrado para PAN-OS."""
    normalized = enc.replace("_", "-").replace(" ", "").lower()
    
    # Mapeos directos para abreviaciones comunes
    if normalized in {"aes256", "aes256cbc"}:
        return "aes-256-cbc"
    if normalized in {"aes192", "aes192cbc"}:
        return "aes-192-cbc"
    if normalized in {"aes128", "aes128cbc"}:
        return "aes-128-cbc"
    if normalized in {"3des", "triple-des", "des3"}:
        return "3des"
    
    # Si ya parece formato palo alto (aes-256-cbc), lo devolvemos
    return normalized


def _split_proposal(proposal: str) -> Tuple[str, str]:
    """
    Separa 'aes-256-cbc-sha256' en ('aes-256-cbc', 'sha256').
    Es robusto: busca el hash conocido al final.
    """
    known_hashes = {"sha1", "sha256", "sha384", "sha512", "md5"}
    parts = [p.strip().lower() for p in proposal.split("-") if p.strip()]
    
    if not parts:
        return "aes-256-cbc", "sha256" # Fallback safe

    # Estrategia: Verificar si la última parte es un hash conocido
    if parts[-1] in known_hashes:
        hash_algo = parts[-1]
        cipher_parts = parts[:-1]
    else:
        # Si no hay hash explícito, asumimos sha256 (común en configs simplificadas)
        hash_algo = "sha256" 
        cipher_parts = parts

    cipher_algo = "-".join(cipher_parts)
    
    # Caso borde: si el input era solo "sha256" (raro pero posible error)
    if not cipher_algo:
        cipher_algo = "aes-256-cbc"

    return cipher_algo, hash_algo


def _pa_list_clause(values: List[str], default: str) -> str:
    cleaned = _uniq_list(values)
    if not cleaned:
        return default
    if len(cleaned) == 1:
        return cleaned[0]
    return "[ " + " ".join(cleaned) + " ]"


def build_paloalto_cli(cfg: VPNConfig) -> List[str]:
    # Esta función genera comandos CLI para copiar y pegar
    ike_enc_raw, ike_hash = _split_proposal(cfg.phase1_proposal)
    esp_enc_raw, esp_hash = _split_proposal(cfg.phase2_proposal or cfg.phase1_proposal)
    ike_enc = _pan_cipher(ike_enc_raw)
    esp_enc = _pan_cipher(esp_enc_raw)
    pfs_enabled = str(cfg.phase2_pfs).lower() not in {"off", "disable", "disabled", "none", "no"}
    prefix = ip_network(cfg.tunnel_cidr, strict=False).prefixlen
    ike_profile = f"{cfg.name}-ike"
    ipsec_profile = f"{cfg.name}-ipsec"
    mgmt_profile = cfg.paloalto_mgmt_profile or f"{cfg.name}-icmp"

    commands: List[str] = []
    addr_map: Dict[str, str] = {}
    for idx, subnet in enumerate(cfg.fortigate_local_subnets, start=1):
        name = f"{cfg.name}-fgt-net-{idx}"
        addr_map[subnet] = name
        commands.append(f"set address {name} ip-netmask {subnet}")
    for idx, subnet in enumerate(cfg.paloalto_local_subnets, start=1):
        name = f"{cfg.name}-pa-net-{idx}"
        addr_map[subnet] = name
        commands.append(f"set address {name} ip-netmask {subnet}")

    commands.extend(
        [
            f"set network ike crypto-profiles ike-crypto-profiles {ike_profile} encryption {ike_enc}",
            f"set network ike crypto-profiles ike-crypto-profiles {ike_profile} hash {ike_hash}",
            f"set network ike crypto-profiles ike-crypto-profiles {ike_profile} dh-group group{cfg.phase1_dh}",
            f"set network ike crypto-profiles ike-crypto-profiles {ike_profile} lifetime seconds {cfg.phase1_lifetime}",
            f"set network ike crypto-profiles ipsec-crypto-profiles {ipsec_profile} esp encryption {esp_enc}",
            f"set network ike crypto-profiles ipsec-crypto-profiles {ipsec_profile} esp authentication {esp_hash}",
            *( [f"set network ike crypto-profiles ipsec-crypto-profiles {ipsec_profile} dh-group group{cfg.phase2_pfs}"] if pfs_enabled else [] ),
            f"set network ike crypto-profiles ipsec-crypto-profiles {ipsec_profile} lifetime seconds {cfg.phase2_lifetime}",
            f"set network ike gateway {cfg.name} authentication pre-shared-key key '{cfg.pre_shared_key}'",
            f"set network ike gateway {cfg.name} local-address interface {cfg.paloalto_ike_interface}",
            f"set network ike gateway {cfg.name} peer-address ip {cfg.fortigate_wan_ip}",
            f"set network ike gateway {cfg.name} protocol {cfg.ike_version.lower()}",
            f"set network ike gateway {cfg.name} protocol version {cfg.ike_version.lower()}",
            f"set network ike gateway {cfg.name} protocol {cfg.ike_version.lower()} ike-crypto-profile {ike_profile}",
        ]
    )

    commands.append(f"set network profiles interface-management-profile {mgmt_profile} ping yes")

    commands.extend(
        [
            f"set network interface tunnel units {cfg.paloalto_tunnel_unit} ip {cfg.paloalto_tunnel_ip}/{prefix}",
            f"set network interface tunnel units {cfg.paloalto_tunnel_unit} comment 'VPN a FortiGate {cfg.name}'",
            f"set network interface tunnel units {cfg.paloalto_tunnel_unit} interface-management-profile {mgmt_profile}",
            f"set network tunnel ipsec {cfg.name} auto-key ike-gateway {cfg.name}",
            f"set network tunnel ipsec {cfg.name} auto-key ipsec-crypto-profile {ipsec_profile}",
            f"set network tunnel ipsec {cfg.name} auto-key enable yes",
            f"set network tunnel ipsec {cfg.name} tunnel-interface {cfg.paloalto_tunnel_unit}",
            f"set network virtual-router {cfg.paloalto_virtual_router} interface {cfg.paloalto_tunnel_unit}",
            f"set zone {cfg.paloalto_zone} network layer3 {cfg.paloalto_tunnel_unit}",
        ]
    )

    for idx, subnet in enumerate(cfg.fortigate_local_subnets, start=1):
        route_name = f"to-{cfg.name}-{idx}" if len(cfg.fortigate_local_subnets) > 1 else f"to-{cfg.name}"
        commands.append(
            f"set network virtual-router {cfg.paloalto_virtual_router} routing-table ip static-route {route_name} destination {subnet} interface {cfg.paloalto_tunnel_unit} nexthop ip-address {cfg.fortigate_tunnel_ip}"
        )

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


def build_paloalto_api_payloads(cfg: VPNConfig, vsys: str = "vsys1", device: str = "localhost.localdomain") -> Dict[str, Any]:
    # Parsing robusto de algoritmos
    ike_enc_raw, ike_hash = _split_proposal(cfg.phase1_proposal)
    esp_enc_raw, esp_hash = _split_proposal(cfg.phase2_proposal or cfg.phase1_proposal)
    ike_enc = _pan_cipher(ike_enc_raw)
    esp_enc = _pan_cipher(esp_enc_raw)
    
    pfs_enabled = str(cfg.phase2_pfs).lower() not in {"off", "disable", "disabled", "none", "no"}
    prefix = ip_network(cfg.tunnel_cidr, strict=False).prefixlen
    ike_profile = f"{cfg.name}-ike"
    ipsec_profile = f"{cfg.name}-ipsec"
    mgmt_profile = cfg.paloalto_mgmt_profile or f"{cfg.name}-icmp"

    # Preparacion de Address Objects
    addr_entries: List[Dict[str, Any]] = []
    for idx, subnet in enumerate(cfg.fortigate_local_subnets, start=1):
        name = f"{cfg.name}-fgt-net-{idx}"
        addr_entries.append({"name": name, "subnet": subnet})
    for idx, subnet in enumerate(cfg.paloalto_local_subnets, start=1):
        name = f"{cfg.name}-pa-net-{idx}"
        addr_entries.append({"name": name, "subnet": subnet})

    pa_sources = [entry["name"] for entry in addr_entries if "-pa-net-" in entry["name"]]
    fgt_sources = [entry["name"] for entry in addr_entries if "-fgt-net-" in entry["name"]]

    def _member_block(values: List[str]) -> str:
        return "".join(f"<member>{val}</member>" for val in values)

    # Preparacion de Proxy IDs
    proxy_ids: List[Dict[str, Any]] = []
    for idx, src in enumerate(cfg.paloalto_local_subnets, start=1):
        for dst in cfg.fortigate_local_subnets:
            proxy_name = f"{cfg.name}-p2-{idx}" if len(cfg.paloalto_local_subnets) > 1 else f"{cfg.name}-p2"
            proxy_ids.append({"name": proxy_name, "local": src, "remote": dst})

    # Preparacion de Rutas Estaticas
    routes: List[Dict[str, Any]] = []
    for idx, subnet in enumerate(cfg.fortigate_local_subnets, start=1):
        route_name = f"to-{cfg.name}-{idx}" if len(cfg.fortigate_local_subnets) > 1 else f"to-{cfg.name}"
        routes.append({"name": route_name, "destination": subnet, "nexthop": cfg.fortigate_tunnel_ip})

    services_in = cfg.paloalto_services_inbound or cfg.services_inbound or ["application-default"]
    services_out = cfg.paloalto_services_outbound or cfg.services_outbound or ["application-default"]
    applications_in = cfg.paloalto_applications_inbound or cfg.applications_inbound or ["any"]
    applications_out = cfg.paloalto_applications_outbound or cfg.applications_outbound or ["any"]

    device_xpath = f"/config/devices/entry[@name='{device}']"
    vsys_xpath = f"{device_xpath}/vsys/entry[@name='{vsys}']"

    # Diccionario de payloads
    # NOTA: El orden aqui no importa para el dict, pero si importa para la ejecucion.
    # Abajo retornamos una lista ordenada de llaves.
    payloads: Dict[str, Any] = {
        "addresses": [
            {
                "xpath": f"{vsys_xpath}/address",
                "element": f"<entry name='{entry['name']}'><ip-netmask>{entry['subnet']}</ip-netmask></entry>",
            }
            for entry in addr_entries
        ],
        "ike_profile": {
            "xpath": f"{device_xpath}/network/ike/crypto-profiles/ike-crypto-profiles",
            "element": f"<entry name='{ike_profile}'><encryption><member>{ike_enc}</member></encryption><hash><member>{ike_hash}</member></hash><dh-group><member>group{cfg.phase1_dh}</member></dh-group><lifetime><seconds>{cfg.phase1_lifetime}</seconds></lifetime></entry>",
        },
        "ipsec_profile": {
            "xpath": f"{device_xpath}/network/ike/crypto-profiles/ipsec-crypto-profiles",
            "element": "".join(
                [
                    f"<entry name='{ipsec_profile}'>",
                    "<esp>",
                    f"<encryption><member>{esp_enc}</member></encryption>",
                    f"<authentication><member>{esp_hash}</member></authentication>",
                    "</esp>",
                    # FIX: dh-group sin <member> para evitar error code 12
                    f"{'<dh-group>group' + str(cfg.phase2_pfs) + '</dh-group>' if pfs_enabled else ''}",
                    f"<lifetime><seconds>{cfg.phase2_lifetime}</seconds></lifetime>",
                    "</entry>",
                ]
            ),
        },
        "mgmt_profile": {
            "xpath": f"{device_xpath}/network/profiles/interface-management-profile",
            "element": f"<entry name='{mgmt_profile}'><ping>yes</ping></entry>",
        },
        "tunnel_unit": {
            "xpath": f"{device_xpath}/network/interface/tunnel/units",
            "element": f"<entry name='{cfg.paloalto_tunnel_unit}'><ip><entry name='{cfg.paloalto_tunnel_ip}/{prefix}'/></ip><comment>VPN a FortiGate {cfg.name}</comment><interface-management-profile>{mgmt_profile}</interface-management-profile></entry>",
        },
        "vr_interface": {
            # ADVERTENCIA: Usar siempre action='set' (add) en la llamada API para este xpath.
            # Si se usa 'edit' (replace), se borraran las otras interfaces del router.
            "xpath": f"{device_xpath}/network/virtual-router/entry[@name='{cfg.paloalto_virtual_router}']/interface",
            "element": f"<member>{cfg.paloalto_tunnel_unit}</member>",
        },
        "zone": {
            "xpath": f"{vsys_xpath}/zone",
            "element": f"<entry name='{cfg.paloalto_zone}'><network><layer3><member>{cfg.paloalto_tunnel_unit}</member></layer3></network></entry>",
        },
        "ike_gateway": {
            "xpath": f"{device_xpath}/network/ike/gateway",
            "element": "".join(
                [
                    f"<entry name='{cfg.name}'>",
                    "<authentication><pre-shared-key><key>",
                    f"{cfg.pre_shared_key}",
                    "</key></pre-shared-key></authentication>",
                    
                    # --- INICIO CORRECCIÓN ---
                    "<protocol>",
                        "<ikev2>",
                            f"<ike-crypto-profile>{ike_profile}</ike-crypto-profile>",
                        "</ikev2>",
                        # La versión debe estar DENTRO del bloque protocol
                        "<version>ikev2</version>", 
                    "</protocol>",
                    # --- FIN CORRECCIÓN ---

                    f"<local-address><interface>{cfg.paloalto_ike_interface}</interface></local-address>",
                    f"<peer-address><ip>{cfg.fortigate_wan_ip}</ip></peer-address>",
                    
                    # ANTES ESTABA AQUÍ ABAJO (ERROR), LO HEMOS QUITADO
                    "</entry>",
                ]
            ),
        },
        "ipsec_tunnel": {
            "xpath": f"{device_xpath}/network/tunnel/ipsec",
            "element": f"<entry name='{cfg.name}'><auto-key><ike-gateway><entry name='{cfg.name}'/></ike-gateway><ipsec-crypto-profile>{ipsec_profile}</ipsec-crypto-profile></auto-key><tunnel-interface>{cfg.paloalto_tunnel_unit}</tunnel-interface></entry>",
        },
        "proxy_ids": [
            {
                "xpath": f"{device_xpath}/network/tunnel/ipsec/entry[@name='{cfg.name}']/auto-key/proxy-id",
                "element": f"<entry name='{proxy['name']}'><local>{proxy['local']}</local><remote>{proxy['remote']}</remote><protocol><any/></protocol></entry>",
            }
            for proxy in proxy_ids
        ],
        "static_routes": [
            {
                "xpath": f"{device_xpath}/network/virtual-router/entry[@name='{cfg.paloalto_virtual_router}']/routing-table/ip/static-route",
                "element": f"<entry name='{route['name']}'><destination>{route['destination']}</destination><interface>{cfg.paloalto_tunnel_unit}</interface><nexthop><ip-address>{route['nexthop']}</ip-address></nexthop></entry>",
            }
            for route in routes
        ],
        "security_rules": [
            {
                "xpath": f"{vsys_xpath}/rulebase/security/rules",
                "element": f"<entry name='{cfg.name}-inbound-allow'><from><member>{cfg.paloalto_zone}</member></from><to><member>{cfg.paloalto_inside_zone}</member></to><source>{_member_block(fgt_sources)}</source><destination>{_member_block(pa_sources)}</destination><application>{_member_block(applications_in)}</application><service>{_member_block(services_in)}</service><action>allow</action></entry>",
            },
            {
                "xpath": f"{vsys_xpath}/rulebase/security/rules",
                "element": f"<entry name='{cfg.name}-outbound-allow'><from><member>{cfg.paloalto_inside_zone}</member></from><to><member>{cfg.paloalto_zone}</member></to><source>{_member_block(pa_sources)}</source><destination>{_member_block(fgt_sources)}</destination><application>{_member_block(applications_out)}</application><service>{_member_block(services_out)}</service><action>allow</action></entry>",
            },
        ],
    }
    
    # IMPORTANTE: Definimos el orden estricto de ejecucion para evitar errores de dependencias
    payloads["ordered_steps"] = [
        "addresses",
        "ike_profile",
        "ipsec_profile",
        "ike_gateway",  # Depende de ike_profile
        "mgmt_profile",
        "tunnel_unit",  # Depende de mgmt_profile
        "ipsec_tunnel", # Depende de ike_gateway, ipsec_profile y tunnel_unit
        "vr_interface", # Depende de tunnel_unit
        "zone",         # Depende de tunnel_unit
        "static_routes",
        "proxy_ids",    # Depende de ipsec_tunnel
        "security_rules"
    ]
    
    return payloads


def render_plan(cfg: VPNConfig) -> str:
    # (El render_plan se mantiene igual, es solo documentación)
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
            "- FortiGate API REST (`/api/v2/cmdb` y `/api/v2/monitor`).",
            "- API XML de Palo Alto.",
            "- Python 3 para generar payloads y aplicarlos.",
        ]
    )
    steps = "\n".join(
        [
            "1) Validar parámetros (IPs, /30, subredes).",
            "2) Generar payloads usando `build_paloalto_api_payloads`.",
            "3) Ejecutar llamadas API en el orden indicado en `ordered_steps`.",
            "4) Probar con pings entre subredes remotas.",
        ]
    )
    considerations = "\n".join(
        [
            "- NAT-T si hay NAT intermedio; abrir UDP 500/4500 y ESP.",
            "- NTP alineado para evitar fallos de PSK/IKE.",
            "- Propuestas/DH/PFS idénticas en ambos lados.",
            "- **Importante:** Usar action='set' para la interfaz del Virtual Router para evitar sobrescrituras.",
        ]
    )
    validation = "\n".join(
        [
            "- FortiGate: `get vpn ipsec tunnel summary` o monitor API.",
            f"- Palo Alto: `show vpn ike-sa`, `show vpn ipsec-sa`, `test vpn ipsec-sa tunnel {cfg.name}`.",
            "- Ping entre subredes remotas.",
        ]
    )
    alerts = "- Integrar salida/exit code con scheduler/CI o webhook ante fallos de SA o de commit."

    lines = [
        "# Plan de Automatización VPN (API Forti + API Palo Alto)",
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