import os
import datetime
import re
from netmiko import ConnectHandler

ERROR_PATTERNS = ("invalid","incomplete","ambiguous","error","denied","not allowed","% ",)
SUCCESS_COPY_PATTERNS = ("bytes copied", "ok", "copy complete")

class GestorRed:
    def obtener_info_dispositivo(self, ip, usuario, password, enable):
        return {
            "device_type": "cisco_ios",
            "host": ip.strip(),
            "username": usuario.strip(),
            "password": password.strip(),
            "secret": enable.strip(),
        }

    def probar_conexion(self, info_dispositivo):
        with ConnectHandler(**info_dispositivo) as conn:
            return conn.find_prompt()

    def aplicar_cambios(self, info_dispositivo, lista_tareas, callback_log=None):
        registrar = callback_log or (lambda *_: None)
        registrar(">>> INICIANDO CONEXIÓN SSH...")

        hostname_esperado = None
        vlans_esperadas = {}
        desviaciones = []

        with ConnectHandler(**info_dispositivo) as conn:
            conn.enable()
            for tarea in lista_tareas:
                tipo_tarea = tarea.get("tipo")
                descripcion_tarea = tarea.get("descripcion", "")
                registrar(f"Procesando: {descripcion_tarea}")

                if tipo_tarea == "HOSTNAME":
                    nuevo_hostname = (tarea.get("hostname") or "").strip()
                    if not nuevo_hostname:
                        desviaciones.append("Hostname vacío no es válido.")
                        registrar("⚠ Hostname vacío; se omite.")
                        continue
                    salida = conn.send_config_set([f"hostname {nuevo_hostname}"])
                    if self._salida_con_error(salida):
                        desviaciones.append(f"Error al configurar hostname '{nuevo_hostname}': {salida.strip()}")
                        registrar(f"⚠ Fallo hostname: {salida.strip()}")
                        continue
                    conn.base_prompt = nuevo_hostname
                    hostname_esperado = nuevo_hostname
                    registrar(f"✔ Hostname actualizado: {conn.find_prompt()}")

                elif tipo_tarea == "VLAN":
                    vlan_id = str(tarea.get("vlan_id") or "").strip()
                    vlan_nombre = (tarea.get("vlan_nombre") or "").strip()
                    if not vlan_id or not vlan_nombre:
                        desviaciones.append(f"No se pudo leer VLAN de la tarea: {descripcion_tarea}")
                        registrar(f"⚠ Tarea VLAN inválida: {descripcion_tarea}")
                        continue

                    if not vlan_id.isdigit() or not 1 <= int(vlan_id) <= 4094:
                        desviaciones.append(f"VLAN {vlan_id} fuera de rango (1-4094)")
                        registrar(f"⚠ VLAN {vlan_id} fuera de rango")
                        continue

                    salida = conn.send_config_set([f"vlan {vlan_id}", f"name {vlan_nombre}"])
                    if self._salida_con_error(salida):
                        desviaciones.append(f"No se pudo crear VLAN {vlan_id}: {salida.strip()}")
                        registrar(f"⚠ Fallo VLAN {vlan_id}: {salida.strip()}")
                        continue

                    vlans_esperadas[vlan_id] = vlan_nombre
                    registrar(f"✔ VLAN {vlan_id} configurada.")

                else:
                    registrar(f"⚠ Tipo de tarea no reconocido: {tipo_tarea}")
                    desviaciones.append(f"Tarea desconocida ignorada: {tipo_tarea}")

            registrar("Guardando en NVRAM (wr mem)...")
            conn.save_config()
            prompt = conn.find_prompt()

            hostname_actual = conn.find_prompt().rstrip("#")
            if hostname_esperado and hostname_actual != hostname_esperado:
                desviaciones.append(f"Hostname esperado '{hostname_esperado}', encontrado '{hostname_actual}'")

            if vlans_esperadas:
                salida_vlans = conn.send_command("show vlan brief")
                for vlan_id, vlan_nombre in vlans_esperadas.items():
                    linea_vlan = self._buscar_linea_vlan(salida_vlans, vlan_id)
                    if not linea_vlan:
                        desviaciones.append(f"VLAN {vlan_id} no existe")
                        continue
                    nombre_actual = linea_vlan.split()[1] if len(linea_vlan.split()) > 1 else ""
                    if nombre_actual.lower() != vlan_nombre.lower():
                        desviaciones.append(
                            f"VLAN {vlan_id} nombre esperado '{vlan_nombre}', encontrado '{nombre_actual}'"
                        )

            if desviaciones:
                for desviacion in desviaciones:
                    registrar(f"⚠ Configuración no estándar: {desviacion}")
            else:
                registrar("✔ Validación OK: Configuración aplicada correctamente.")

            return prompt, desviaciones

    def realizar_respaldo(self, info_dispositivo, modo, ip_tftp=None, callback_log=None):
        registrar = callback_log or (lambda *_: None)
        registrar(">>> INICIANDO BACKUP...")
        with ConnectHandler(**info_dispositivo) as conn:
            conn.enable()
            hostname = conn.find_prompt().rstrip("#")
            sello_tiempo = datetime.datetime.now()
            if modo == "Local (PC)":
                os.makedirs("repositorio_backups", exist_ok=True)
                nombre_archivo = f"repositorio_backups/{hostname}_backup_{sello_tiempo:%Y-%m-%d_%H-%M-%S}.txt"
                with open(nombre_archivo, "w", encoding="utf-8") as archivo:
                    archivo.write(conn.send_command("show running-config"))
                return "LOCAL", nombre_archivo

            if not ip_tftp:
                raise ValueError("Falta IP TFTP")

            nombre_archivo = f"{hostname}-{sello_tiempo:%Y%m%d-%H%M}.cfg"
            salida = conn.send_command_timing(f"copy running-config tftp://{ip_tftp}/{nombre_archivo}")
            for _ in range(5):
                salida_min_tmp = salida.lower()
                if any(
                    prompt in salida_min_tmp
                    for prompt in ("address or name", "destination filename", "confirm", "overwrite")
                ) or salida.strip().endswith("?"):
                    salida += conn.send_command_timing("\n")
                else:
                    break

            salida_filtrada = self._filtrar_salida_tftp(salida)
            if salida_filtrada:
                registrar(f"Salida TFTP:\n{salida_filtrada}")

            salida_min = salida.lower()
            if any(palabra in salida_min for palabra in ERROR_PATTERNS):
                raise Exception(f"Fallo TFTP:\n{salida}")
            if not any(palabra in salida_min for palabra in SUCCESS_COPY_PATTERNS):
                registrar("⚠ No se detectó texto de confirmación de copia; verifique el archivo en el TFTP.")
                return "REMOTE", nombre_archivo
            return "REMOTE", nombre_archivo

    def desconectar_dispositivo(self, info_dispositivo, callback_log=None):
        registrar = callback_log or (lambda *_: None)
        registrar(">>> CERRANDO SESIÓN SSH...")
        try:
            with ConnectHandler(**info_dispositivo) as conn:
                conn.disconnect()
            registrar("Sesión cerrada.")
        except Exception as exc:
            registrar(f"No se pudo cerrar sesión: {exc}")
            raise

    @staticmethod
    def _parsear_tarea_vlan(descripcion):
        if not descripcion:
            return None, None
        match = re.search(r"VLAN\s+(\d+)\s*:\s*Nombre\s*'?(.*?)'?$", descripcion.strip())
        if not match:
            return None, None
        return match.group(1), match.group(2).strip()

    @staticmethod
    def _salida_con_error(salida):
        salida_min = salida.lower()
        return any(patron in salida_min for patron in ERROR_PATTERNS)

    @staticmethod
    def _buscar_linea_vlan(salida_vlans, vlan_id):
        return next((ln for ln in salida_vlans.splitlines() if ln.strip().startswith(str(vlan_id))), None)

    @staticmethod
    def _filtrar_salida_tftp(salida):
        lineas_filtradas = []
        for linea in salida.splitlines():
            linea_min = linea.strip().lower()
            if any(palabra in linea_min for palabra in ("address or name", "destination filename", "confirm", "overwrite")):
                continue
            lineas_filtradas.append(linea)
        return "\n".join(lineas_filtradas).strip()
