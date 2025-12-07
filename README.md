# NetConfigurator (Automatización de tareas Switch Cisco)

Antes de empezar, lee este README completo. Se debe usar `uv` en lugar de `pip` para instalar dependencias.

Script en Python con interfaz gráfica (CustomTkinter) para configurar hostname y VLANs (ID y Nombre) en un switch Cisco IOS (físico o simulado) usando Netmiko. Permite validar la configuración aplicada, guardar en NVRAM y realizar respaldos locales o de forma remota vía TFTP.

## Requisitos previos
- Python 3.10 o superior.
- Dependencias: `customtkinter`, `netmiko`.
- Acceso SSH habilitado en el switch y credenciales con modo enable.
- Opcional: servidor TFTP accesible desde el switch (para backup remoto).

## Instalación (con uv)
1) Instala `uv` si no lo tienes: https://docs.astral.sh/uv/getting-started/
2) Crea el entorno y sincroniza dependencias:
```bash
uv venv
source .venv/bin/activate  # En Windows: .venv\Scripts\activate
uv sync
```
Si prefieres sin modo editable:
```bash
uv pip install customtkinter netmiko
```

## Ejecución
```bash
uv run python main.py
```
También puedes activar el entorno (`source .venv/bin/activate`) y ejecutar `python main.py` si lo prefieres.

## Uso rápido (UI)
1. Completa IP, usuario, password y enable; pulsa **Conectar**.
2. Para hostname: escribe el nuevo nombre y pulsa **Agregar**.
3. Para VLANs: ingresa ID (1–4094) y nombre, pulsa **Agregar** tantas como necesites.
4. Las tareas aparecerán en la lista de la derecha; puedes quitar las seleccionadas con **Quitar Seleccionado**.
5. Pulsa **Aplicar Cambios** para enviar la configuración; la app valida hostname y VLANs y muestra desviaciones en los logs/alertas.
6. Respaldo:
   - **Local (PC)**: guarda `show running-config` en `repositorio_backups/`.
   - **Servidor Remoto (TFTP)**: ingresa IP TFTP y pulsa **Enviar a TFTP**. La salida del comando de copia se registra.

## Validación y logs
- El backend revisa que el hostname resulte el esperado y que cada VLAN solicitada exista con el nombre indicado; cualquier discrepancia se muestra en los logs y en la alerta de la UI.
- Errores devueltos por el switch (comandos inválidos, VLAN fuera de rango, etc.) se registran y la tarea se marca como desviación.

## Estructura del proyecto
- `main.py`: interfaz gráfica y gestión de tareas encoladas.
- `core.py`: lógica de conexión, aplicación de cambios, validación y backups.
- `pyproject.toml`: metadatos y dependencias del proyecto.
- `screenshots/`: capturas de la UI y pruebas (ver `screenshots/ORDER.md` para un recorrido sugerido).

## Notas y buenas prácticas
- Ejecuta la app desde una red con alcance SSH al switch y con la IP del TFTP accesible (si usas backup remoto).
