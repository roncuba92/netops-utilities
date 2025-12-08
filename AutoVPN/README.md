# AutoVPN (FortiGate ↔ Palo Alto IPSec)

Automatiza la generación y validación de un túnel IPSec site-to-site. La fuente de verdad es `vpn_config.json`; todos los artefactos se derivan de ese archivo.

## Flujo de trabajo
1) **Definición (Input)**: edita `vpn_config.json` (IPs WAN, IPs de túnel, subredes locales, PSK, propuestas criptográficas, lifetimes, DPD).
2) **Generación (Procesamiento)**: ejecuta `python3 AutoVPN/generate_deployment.py` (lee, valida, normaliza y crea la carpeta `outputs/`).
3) **Salidas (Artefactos)** en `AutoVPN/outputs/`:
   - `VPN_PLAN.md`: documentación con tabla de parámetros, flujo lógico y sección obligatoria de "Desafíos y Consideraciones".
   - `fortigate_payload.json`: cuerpo JSON listo para `/api/v2/cmdb/...` en FortiGate.
   - `paloalto_commands.txt`: comandos `set` listos para cargar en candidate-config de Palo Alto (luego `commit`).
4) **Validación (Check)**: ejecuta `python3 AutoVPN/validate_vpn.py --fortigate-host https://FGT --fortigate-token <token> --paloalto-host <PA> --paloalto-user <user> --paloalto-password <pass>` para confirmar que el túnel esté UP (REST en FGT y SSH/Netmiko en PA).

## Archivos relevantes
- `vpn_config.json`: fuente de verdad de parámetros.
- `generate_deployment.py`: genera los artefactos en `outputs/`.
- `deploy_vpn.py`: aplica los artefactos en FortiGate (REST) y Palo Alto (SSH/Netmiko).
- `validate_vpn.py`: verifica el estado del túnel (SA IKE/IPSec).
- `outputs/`: artefactos generados (se crean al correr el generador).

## Uso rápido
- Generar artefactos: `python3 AutoVPN/generate_deployment.py --config AutoVPN/vpn_config.json`
- Desplegar artefactos: `python3 AutoVPN/deploy_vpn.py --fortigate-host https://198.51.100.10 --fortigate-token <token> --paloalto-host 198.51.100.20 --paloalto-user admin --paloalto-password <pass> [--verify-ssl]`
- Validar túnel: `python3 AutoVPN/validate_vpn.py --config AutoVPN/vpn_config.json --fortigate-host https://198.51.100.10 --fortigate-token <token> --paloalto-host 198.51.100.20 --paloalto-user admin --paloalto-password <pass>`

## Notas
- Palo Alto se configura en candidate-config; recuerda hacer `commit`.
- FortiGate usa `/api/v2/cmdb/...`; el payload generado es JSON listo para API.
- Dependencias: `requests` y `netmiko` (ver `pyproject.toml`).
