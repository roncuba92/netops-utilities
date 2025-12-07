# AutoVPN (Plan IPSec FortiGate ↔ Palo Alto)

Proyecto ubicado en `AutoVPN/`. Genera un plan en Markdown y ejemplos de payloads/comandos para automatizar un túnel IPSec entre FortiGate y Palo Alto.

## Uso rápido
- Con parámetros por defecto: `python AutoVPN/vpn.py --output AutoVPN/VPN_PLAN.md`
- Con JSON de entrada: `python AutoVPN/vpn.py --config AutoVPN/vpn_config.json --output AutoVPN/VPN_PLAN.md`
- Puedes sobreescribir campos puntuales con flags (`--name`, `--fgt-wan`, `--pa-wan`, `--tunnel-cidr`, `--fgt-tunnel-ip`, `--pa-tunnel-ip`, `--fgt-local`, `--pa-local`, `--psk`, `--ike-version`).

## Archivos
- `vpn.py`: script principal (solo usa librerías estándar).
- `vpn_config.json`: ejemplo de parámetros para generar el plan.
- `VPN_PLAN.md`: salida de ejemplo generada con los valores por defecto.

## Salida
Genera un Markdown con: resumen de parámetros, pasos de automatización, payloads REST para FortiGate y comandos `set` para Palo Alto. El archivo se crea en la ruta que indiques con `--output`.
