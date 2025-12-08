# NetConfigurator (Automatización de tareas en Switch Cisco)

Script en Python con interfaz gráfica (CustomTkinter) para configurar hostname y VLANs (ID y Nombre) en un switch Cisco IOS (físico o simulado) usando Netmiko. Permite validar la configuración aplicada, guardar en NVRAM y realizar respaldos locales o de forma remota vía TFTP.

## Requisitos previos
- Python 3.10 o superior.
- Dependencias: `customtkinter`, `netmiko`.
- Acceso SSH habilitado en el switch y credenciales con modo enable.
- Opcional: servidor TFTP accesible desde el switch (para backup remoto).

## Instalación (con uv)
1) Instala `uv` si no lo tienes: https://docs.astral.sh/uv/getting-started/
2) Desde la raíz del repo (donde está `pyproject.toml`), crea el entorno y sincroniza dependencias:
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
uv run python NetConfigurator/main.py
```
También puedes activar el entorno (`source .venv/bin/activate`), entrar a `NetConfigurator/` y ejecutar `python main.py` si lo prefieres.

## Uso rápido (UI)
1. Ingresa dirección IP del switch, usuario y password local, password de enable; pulsa **Conectar**.
2. Para hostname: escribe el nombre que deseas configurarle al switch; pulsa **Agregar**.
3. Para VLANs: ingresa ID (1–4094) y nombre; pulsa **Agregar**, tantas VLANs como necesites.
4. Las tareas aparecerán en el panel de la derecha (TAREAS A EJECUTAR); puedes eliminar la que desees, seleccionándola y luego presionando **Quitar Seleccionado**.
5. Pulsa **Aplicar Cambios** para enviar la configuración al switch; la app valida hostname, VLANs y muestra desviaciones en los logs/alertas.
6. En el caso de las VLANs reservadas por el sistema (1002-1005) si intentas modificar alguna, habrá un error de validación porque el switch no permite modificarlas; se mostrará una alerta en la ventana de logs del sistema. (Se dejó intencionalmente la posibilidad de querer modificar estas VLANs para probar la funcionalidad de validación)
7. Respaldo:
   - **Local (PC)**: guarda `show running-config` en `repositorio_backups/` (se crea en la raíz del proyecto si no existe).
   - **Servidor Remoto (TFTP)**: ingresa IP TFTP y pulsa **Enviar a TFTP**. La salida del comando de copia se registra.

## Validación y logs
- El backend revisa que el hostname resulte el esperado y que cada VLAN solicitada exista con el nombre indicado; cualquier discrepancia se muestra en los logs y en la alerta de la UI.
- Errores devueltos por el switch (comandos inválidos, VLAN fuera de rango, etc.) se registran y la tarea se marca como desviación.

## Estructura del proyecto
- `NetConfigurator/main.py`: interfaz gráfica y gestión de tareas encoladas.
- `NetConfigurator/core.py`: lógica de conexión, aplicación de cambios, validación y backups.
- `NetConfigurator/screenshots/`: capturas de la UI y pruebas (ver `screenshots/ORDER.md` para un recorrido sugerido).

## Notas y buenas prácticas
- Ejecuta la app desde una red con alcance SSH al switch y con la IP del TFTP accesible (si usas backup remoto).
