# AutoVPN-API (FortiGate por API + Palo Alto por SSH)

Proyecto paralelo a `AutoVPN` que aplica la VPN FortiGate ↔ Palo Alto usando la API REST del Forti y SSH/Netmiko para Palo Alto. Reutiliza el mismo `vpn_config.json`.

## Estructura
- `vpn_config.json`: parámetros únicos (IP WAN, túnel /30, subredes locales, PSK, propuestas, servicios/apps, interfaces).
- `vpn_api_templates.py`: validación de config y generación de payloads Forti + comandos Palo.
- `deploy_vpn.py`: genera artefactos y aplica (Forti vía API, Palo Alto vía SSH/commit).
- `outputs/`: se crea al ejecutar; guarda payloads, CLI y plan.

## Requisitos
- Python 3.10+, paquetes `requests` y `netmiko`.
- Token de API Forti (`Authorization: Bearer ...`) con permisos de escritura en el VDOM.
- Acceso SSH a Palo Alto (admin/commit).

## Uso rápido
1) Edita parámetros en `vpn_config.json`.
2) Solo generar artefactos:
   ```bash
   python3 AutoVPN-API/deploy_vpn.py --config AutoVPN-API/vpn_config.json --fortigate-host 10.24.133.202 --fortigate-token <TOKEN> --paloalto-host <PA_IP> --paloalto-user <user> --paloalto-password <pass> --dry-run
   ```
3) Aplicar Forti (API) + Palo (SSH):
   ```bash
   python3 AutoVPN-API/deploy_vpn.py \
     --config AutoVPN-API/vpn_config.json \
     --fortigate-host 10.24.133.202 --fortigate-token <TOKEN> \
     --paloalto-host <PA_IP> --paloalto-user <user> --paloalto-password <pass>
   ```
   Añade `--skip-paloalto` si solo quieres Forti. Usa `--fortigate-verify` si tienes un certificado válido y quieres validar TLS.

Artefactos generados en `outputs/`:
- `fortigate_payloads.json`: Phase1/2, interfaz, objetos, políticas y rutas para la API Forti.
- `paloalto_cli.txt`: comandos `set ...` + `commit` para Palo Alto.
- `plan.md`: resumen de parámetros y pasos.

## Notas rápidas
- La aplicación en Forti es idempotente: usa `PUT` y cae a `POST` si no existe; políticas/rutas se actualizan si ya hay una con el mismo nombre/destino.
- Si tienes varias subredes, se crean múltiples Phase2/Proxy-ID.
- El gateway de las rutas en Forti usa `fortigate_static_gateway` si está definido, de lo contrario la IP de túnel de Palo (`paloalto_tunnel_ip`).
- Palo Alto sigue la misma lógica que el proyecto original: SSH con Netmiko y `commit`.
