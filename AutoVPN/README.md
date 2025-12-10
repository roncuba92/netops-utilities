# AutoVPN

Automatización de la VPN IPSec entre FortiGate y Palo Alto con dos enfoques:
- `AutoVPN-SSH/`: aplica la configuración vía SSH usando Netmiko.
- `AutoVPN-API/`: aplica la configuración vía API (FortiOS REST/JSON y Palo Alto XML/XPath).

Consulta `VPN_PLAN.md` para la planificación técnica completa (parámetros, flujo, herramientas y validación) y luego ejecuta la variante que prefieras con el `vpn_config.json` correspondiente.

Verificación básica: usa `validate_vpn.py` (en esta carpeta) para conectarte por SSH a ambos firewalls, consultar el estado IKE/IPSec y opcionalmente hacer ping entre IPs de túnel. En este lab el ping puede fallar si no hay política de ICMP; añade `--skip-ping` si es tu caso.
