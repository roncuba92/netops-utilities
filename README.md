# netops-utilities (NetConfigurator y AutoVPN)

Este README sirve como referencia breve. Para instalación y uso detallado, revisa los README dentro de cada proyecto.

## Proyectos
- `NetConfigurator/`: app de escritorio (CustomTkinter + Netmiko) para gestionar hostname, VLANs y respaldos en switches Cisco IOS. Más info en `NetConfigurator/README.md`.
- `AutoVPN-SSH/`: generación y aplicación por SSH/Netmiko para túnel IPSec FortiGate ↔ Palo Alto. Más info en `AutoVPN-SSH/README.md`.
- `AutoVPN-API/`: FortiGate por API REST + Palo Alto por API REST (misma config JSON). Más info en `AutoVPN-API/README.md`.
- `VPN_PLAN.md`: documento único con parámetros, herramientas, pasos, consideraciones y validación; desde ahí editas `vpn_config.json` y eliges la variante SSH o API.

## Dependencias compartidas
- `pyproject.toml`, `uv.lock`: manejo de dependencias (uv). Ambos proyectos usan el mismo entorno virtual en la raíz.
