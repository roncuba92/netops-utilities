# netops-utilities (NetConfigurator y AutoVPN)

Este README sirve como referencia breve. Para instalación y uso detallado, revisa los README dentro de cada proyecto.

## Proyectos
- `NetConfigurator/`: app de escritorio (CustomTkinter + Netmiko) para gestionar hostname, VLANs y respaldos en switches Cisco IOS. Más info en `NetConfigurator/README.md`.
- `AutoVPN/AutoVPN-SSH/`: generación y aplicación por SSH/Netmiko para túnel IPSec FortiGate ↔ Palo Alto. Más info en `AutoVPN/AutoVPN-SSH/README.md`.
- `AutoVPN/AutoVPN-API/`: FortiGate por API REST + Palo Alto por API REST (misma config JSON). Más info en `AutoVPN/AutoVPN-API/README.md`.
- `AutoVPN/VPN_PLAN.md`: documento único con parámetros, herramientas, pasos, consideraciones y validación; desde ahí editas `vpn_config.json` y eliges la variante SSH o API.

## Dependencias compartidas
- `pyproject.toml`, `uv.lock`: manejo de dependencias (uv). Ambos proyectos usan el mismo entorno virtual en la raíz.

## Videos de laboratorio (Google Drive)
- NetConfigurator: https://drive.google.com/file/d/1BrL3Odh-NmuV9ZLjzW5tPs0W-rbU1-GX/view?usp=share_link
- AutoVPN-API: https://drive.google.com/file/d/1xMnO0awIFtFQCKlC3o2XKdpBQC_38a4j/view?usp=share_link
- AutoVPN-SSH: https://drive.google.com/file/d/1NQHQ6Xt65pN_N8pHyuxXMbIHcbCSQqui/view?usp=share_link

Nota: los enlaces abren en Google Drive (requieren acceso al recurso compartido).
