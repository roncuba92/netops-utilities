# Plan de Automatización VPN IPSec (FortiGate ↔ Palo Alto)

Documento mínimo que cubre los puntos solicitados: parámetros, herramientas/APIs, pasos de automatización, consideraciones y validación/alertas. El enfoque del lab usa SSH con Netmiko por simplicidad, pero se mencionan alternativas.

## Definición de Parámetros (ejemplo base)
- IP WAN FortiGate: `198.51.100.10`
- IP WAN Palo Alto: `203.0.113.10`
- Red de túnel /30: `169.255.1.0/30` (FGT `169.255.1.1`, PA `169.255.1.2`)
- Subredes locales: FortiGate `192.168.10.0/24`, Palo Alto `10.20.10.0/24`
- PSK: `SuperSecreto007!`
- Phase 1: `des-sha1`, DH `2`, lifetime `28800s`, IKEv2
- Phase 2: `des-sha1`, PFS `2`, lifetime `3600s`
- Interfaces/zona: FortiGate WAN `port1`, inside `port3`; Palo Alto túnel `tunnel.10`, zona `vpn-network`, VR `default`, IKE `ethernet1/1`, inside `ethernet1/2`.
- Servicios/app permitidos (ejemplo): 
  - FortiGate servicios inbound: HTTPS, SSH; outbound: HTTPS.
  - Palo Alto servicios inbound: service-https, service-ssh; outbound: service-https.
  - Palo Alto aplicaciones inbound: ssh, ssl, web-browsing; outbound: ssl, web-browsing.
  - Inbound = tráfico de FortiGate hacia Palo Alto (PA: vpn→LAN, FGT: LAN→VPN). Outbound = tráfico de Palo Alto hacia FortiGate (PA: LAN→vpn, FGT: VPN→LAN).

## Identificación de Herramientas/APIs
- Opciones posibles: API REST FortiGate (`/api/v2`), API/XML de Palo Alto o Panorama, herramientas centralizadas (FortiManager/Panorama), CLI por SSH.
- Elección en este lab: SSH con Netmiko (device_type `fortinet` y `paloalto_panos`). Justificación: simple, sin depender de licencias o habilitar APIs en los firewalls de laboratorio; basta con credenciales de configuración.
- Infra de soporte: Python 3, `netmiko` para enviar comandos, Git para versionar JSON de parámetros, scripts y artefactos generados.

## Pasos de Automatización
1. Cargar y validar parámetros desde `vpn_config.json` (IPs válidas, /30 contiene las IP de túnel, subredes sin traslape, PSK no vacía).
2. Generar comandos CLI para ambos equipos: `python3 AutoVPN-SSH/generate_deployment.py --config AutoVPN-SSH/vpn_config.json` escribe `outputs/fortigate_cli.txt` y `outputs/paloalto_cli.txt` (y un plan breve).
3. Aplicar por SSH: `python3 AutoVPN-SSH/deploy_vpn.py ...` lee el mismo JSON, envía los comandos a FortiGate y Palo Alto; en Palo Alto termina con `commit`.
4. Guardar artefactos en `outputs/` para revisión/auditoría.
5. Validar conectividad con `python3 AutoVPN-SSH/validate_vpn.py ...` haciendo ping desde cada firewall hacia la subred remota.

## Consideraciones Específicas
- Propuestas, DH y PFS deben coincidir exactamente en ambos lados; proxy-id (PA) y selectores de Phase 2 (FGT) deben representar las mismas redes.
- Palo Alto requiere `commit`; FortiGate aplica en línea. Manejar errores y reintentos por dispositivo.
- NAT-T: habilitar si hay NAT intermedio; abrir UDP 500/4500 y ESP. Ajustar MSS/MTU si hay fragmentación.
- Reloj: mantener NTP alineado para evitar rechazos de PSK/IKE. Usar cuentas con permisos de configuración y commit.
- APIs: podrían reducir tiempo de conexión y dar idempotencia, pero requieren habilitación, tokens y a veces certificados; por simplicidad el lab usa SSH.

## Validación de Configuración y Alertas
- FortiGate: `get vpn ipsec tunnel summary`, `diagnose vpn ike gateway list`, y los pings del script.
- Palo Alto: `show vpn ike-sa`, `show vpn ipsec-sa`, `test vpn ipsec-sa tunnel <nombre>`, y pings del script.
- Script `validate_vpn.py`: usa SSH para lanzar ping desde cada firewall (fuente = IP de túnel) a la red remota; devuelve JSON con resultado y falla con exit code si algún lado no responde.
- Alertas: se puede integrar salida/exit code con syslog/SNMP/webhook del scheduler/CI para notificar fallos de negociación o de commit.
