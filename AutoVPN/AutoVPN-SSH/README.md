# AutoVPN-SSH (FortiGate ↔ Palo Alto)

Automatiza la VPN IPSec por SSH/Netmiko. El plan maestro de parámetros/consideraciones vive en `../VPN_PLAN.md`.

## Estructura breve
- `vpn_config.json`: JSON único para generar y aplicar ambos equipos.
- `generate_deployment.py`: genera `outputs/fortigate_cli.txt` y `outputs/paloalto_cli.txt` desde `vpn_config.json`.
- `deploy_vpn.py`: aplica por SSH/Netmiko los comandos de ambos firewalls usando `vpn_config.json`.
- `../validate_vpn.py`: verificación por SSH (estado IKE/IPSec en ambos equipos y ping opcional).
- `outputs/`: se crea al generar; guarda los comandos.

## Flujo rápido
1) Edita parámetros en `vpn_config.json` (WAN, subredes locales, /30 de túnel, PSK, propuestas Phase1/2, servicios/apps por vendor y sentido: `fortigate_services_*`, `paloalto_services_*`, `paloalto_applications_*`).
2) Genera comandos (macOS/Linux con `python3`):
   ```bash
   `python3 AutoVPN-SSH/generate_deployment.py --config AutoVPN-SSH/vpn_config.json`
   ``` 
   En Windows usa
   ```bash
    `python AutoVPN\\AutoVPN-SSH\\generate_deployment.py --config AutoVPN\\AutoVPN-SSH\\vpn_config.json`.
    ```
3) Aplica por SSH (usa el mismo JSON de ambos):
   ```bash
   `python3 AutoVPN-SSH/deploy_vpn.py --config AutoVPN-SSH/vpn_config.json --fortigate-host <ip> --fortigate-user <user> --fortigate-password <pass> --paloalto-host <ip> --paloalto-user <user> --paloalto-password <pass>`
   ```
   En Windows: 
   ```bash
   `python AutoVPN\\AutoVPN-SSH\\deploy_vpn.py --config AutoVPN\\AutoVPN-SSH\\vpn_config.json ...`
   ```
   Añade `--dry-run` si solo quieres los archivos en `outputs/` sin tocar los equipos.
4) Valida el túnel (estado IKE/IPSec en ambos equipos y ping opcional):  
   ```bash
   `python3 AutoVPN/validate_vpn.py --config AutoVPN-SSH/vpn_config.json --fortigate-host <ip> --fortigate-user <user> --fortigate-password <pass> --paloalto-host <ip> --paloalto-user <user> --paloalto-password <pass> [--skip-ping]`
   ```
   En Windows: 
   ```bash
   `python AutoVPN\\validate_vpn.py --config AutoVPN\\AutoVPN-SSH\\vpn_config.json ...`
   ```
   Nota: el ping entre IPs de túnel puede fallar si no hay política de ICMP; usa `--skip-ping` si tu equipo lo bloquea.
