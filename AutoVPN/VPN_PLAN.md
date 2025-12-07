# Plan de Automatización VPN IPSec (FortiGate ↔ Palo Alto)

## Definición de Parámetros (ejemplo)
- Nombre del túnel: fgt-pa-ipsec
- IP WAN FortiGate: 198.51.100.10
- IP WAN Palo Alto: 198.51.100.20
- Red de túnel: 169.255.1.0/30 (FGT 169.255.1.1, PA 169.255.1.2)
- Subredes locales FortiGate: 10.10.0.0/24
- Subredes locales Palo Alto: 10.20.0.0/24
- Pre-shared key: **ChangeMe123!**
- IKE: aes256/sha256 DH14 vida 28800s (IKEV2)
- IPSec: aes256/sha256 PFS14 vida 3600s
- DPD: cada 10s, reintentos 3

## Herramientas/APIs sugeridas
- FortiGate REST (`/api/v2`): crear phase1-interface, phase2-interface, rutas y políticas; soporta token API y HTTPS.
- Palo Alto REST/XML API (`type=config&action=set` o REST v10+): carga en candidate-config y requiere `commit`.
- SSH como respaldo para ambos (bibliotecas Netmiko/Paramiko) para dispositivos sin API habilitada.
- Control de versiones: guardar payloads/plantillas en Git y parametrizar con variables de entorno (psk, IPs, interfaces).

## Pasos de Automatización (alto nivel)
1) Validar parámetros de entrada (IPs válidas, subred de túnel /30, PSK no vacía).
2) FortiGate: crear Phase1 con peer 198.51.100.20, PSK y propuestas; habilitar DPD/NAT-T.
3) FortiGate: crear Phase2 con selectores 10.10.0.0/24 → 10.20.0.0/24, PFS y lifetime.
4) FortiGate: asignar IP 169.255.1.1 al interfaz del túnel, ruta estática hacia 10.20.0.0/24 y política de firewall (sin NAT).
5) Palo Alto: definir perfiles IKE/IPSec, gateway remoto 198.51.100.10, túnel fgt-pa-ipsec, interfaz 169.255.1.0/30 IP 169.255.1.2.
6) Palo Alto: agregar el túnel al virtual-router, crear ruta a 10.10.0.0/24 vía 169.255.1.1, y regla de seguridad permitiendo el tráfico.
7) Publicar/commit: `execute vpn tunnel up` o `diagnose vpn ike restart` en FGT si se requiere; `commit` en Palo Alto.
8) Validar SAs e intercambio de tráfico (pings entre subredes, trazas y monitoreo de logs).

## Consideraciones Específicas
- Habilitar NAT-T/keepalive si alguno de los extremos está detrás de NAT.
- Sincronizar hora/NTP para evitar fallas de autenticación por drift de reloj.
- Alinear propuesta IKE/ESP y lifetimes en ambos extremos; cualquier discrepancia levanta fase1 pero no fase2.
- Zones: en Palo Alto, colocar el `tunnel.10` en zona dedicada (p. ej. `vpn-network`) y ajustar políticas desde/hacia esa zona.
- Seguridad: rotar PSK y guardar secretos fuera del repo (variables de entorno o vault).
- Observabilidad: habilitar logs de tráfico y eventos de VPN en ambos dispositivos.

## Validación y Alertas
- FortiGate: `get vpn ipsec tunnel summary`, `diagnose vpn ike gateway list`, `diagnose debug application ike -1`.
- Palo Alto: `show vpn ike-sa`, `show vpn ipsec-sa`, `test vpn ipsec-sa tunnel fgt-pa-ipsec`.
- Probar tráfico real: ping desde 10.10.0.0 hacia 10.20.0.0 y viceversa.
- Alertas: suscribir syslog/SNMP/REST a un sistema externo; disparar alarma si SA baja o si hay renegociaciones frecuentes.

## Endpoints/Payloads de ejemplo (FortiGate REST)
- phase1-interface: /api/v2/cmdb/vpn.ipsec/phase1-interface
- phase2-interface: /api/v2/cmdb/vpn.ipsec/phase2-interface
- static-route: /api/v2/cmdb/router/static
- policy: /api/v2/cmdb/firewall/policy

### Payloads
```json
{
  "phase1-interface": {
    "endpoint": "/api/v2/cmdb/vpn.ipsec/phase1-interface",
    "payload": {
      "name": "fgt-pa-ipsec",
      "type": "static",
      "interface": "port1",
      "local-gw": "198.51.100.10",
      "remote-gw": "198.51.100.20",
      "psksecret": "ChangeMe123!",
      "ike-version": 2,
      "proposal": "aes256-sha256",
      "dpd": "on-idle",
      "dpd-retryinterval": 10,
      "dhgrp": "14",
      "keylife": 28800
    }
  },
  "phase2-interface": {
    "endpoint": "/api/v2/cmdb/vpn.ipsec/phase2-interface",
    "payload": {
      "phase1name": "fgt-pa-ipsec",
      "name": "fgt-pa-ipsec-p2",
      "proposal": "aes256-sha256",
      "pfs": "enable",
      "dhgrp": "14",
      "keylifeseconds": 3600,
      "src-subnet": "10.10.0.0/24",
      "dst-subnet": "10.20.0.0/24"
    }
  },
  "static-route": {
    "endpoint": "/api/v2/cmdb/router/static",
    "payload": {
      "dst": "10.20.0.0/24",
      "gateway": "169.255.1.2",
      "device": "fgt-pa-ipsec",
      "distance": 10
    }
  },
  "policy": {
    "endpoint": "/api/v2/cmdb/firewall/policy",
    "payload": {
      "name": "to-fgt-pa-ipsec",
      "srcintf": [
        {
          "name": "internal"
        }
      ],
      "dstintf": [
        {
          "name": "fgt-pa-ipsec"
        }
      ],
      "srcaddr": [
        {
          "name": "all"
        }
      ],
      "dstaddr": [
        {
          "name": "all"
        }
      ],
      "action": "ipsec",
      "schedule": "always",
      "service": [
        {
          "name": "ALL"
        }
      ],
      "logtraffic": "all",
      "ippool": "disable",
      "nat": "disable"
    }
  }
}
```

## Comandos set para Palo Alto (cargar en candidate-config y luego `commit`)
```bash
set network ike crypto-profiles ike-crypto-profiles fgt-pa-ipsec-ike encryption aes256
set network ike crypto-profiles ike-crypto-profiles fgt-pa-ipsec-ike hash sha256
set network ike crypto-profiles ike-crypto-profiles fgt-pa-ipsec-ike dh-group group14
set network ike crypto-profiles ike-crypto-profiles fgt-pa-ipsec-ike lifetime 28800
set network ike gateway fgt-pa-ipsec authentication pre-shared-key key 'ChangeMe123!'
set network ike gateway fgt-pa-ipsec local-address ip 198.51.100.20
set network ike gateway fgt-pa-ipsec peer-address ip 198.51.100.10
set network ike gateway fgt-pa-ipsec protocol ikev2
set network ike gateway fgt-pa-ipsec ike-crypto-profile fgt-pa-ipsec-ike
set network tunnel ipsec-crypto-profiles ipsec-crypto-profiles fgt-pa-ipsec-ipsec esp encryption aes256
set network tunnel ipsec-crypto-profiles ipsec-crypto-profiles fgt-pa-ipsec-ipsec esp authentication sha256
set network tunnel ipsec-crypto-profiles ipsec-crypto-profiles fgt-pa-ipsec-ipsec dh-group group14
set network tunnel ipsec-crypto-profiles ipsec-crypto-profiles fgt-pa-ipsec-ipsec lifetime 3600
set network tunnel ipsec fgt-pa-ipsec auto-key ike-gateway fgt-pa-ipsec
set network tunnel ipsec fgt-pa-ipsec auto-key ipsec-crypto-profile fgt-pa-ipsec-ipsec
set network tunnel ipsec fgt-pa-ipsec tunnel-interface tunnel.10
set network interface tunnel units tunnel.10 ip 169.255.1.2/30
set network interface tunnel units tunnel.10 comment 'VPN a FortiGate fgt-pa-ipsec'
set network virtual-router default interface tunnel.10
set network virtual-router default routing-table ip static-route to-fortigate destination 10.10.0.0/24 nexthop ip-address 169.255.1.1
set network zone vpn-network network layer3 tunnel.10
set rulebase security rules allow-ipsec from vpn-network to vpn-network source 10.20.0.0/24 destination 10.10.0.0/24 application any service application-default action allow
```
