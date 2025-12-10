from __future__ import annotations

import argparse
from pathlib import Path

from vpn_templates import BASE_DIR, DEFAULT_CONFIG_PATH, build_fortigate_cli, build_paloalto_cli, load_config


DEFAULT_OUTPUT_DIR = BASE_DIR / "outputs"


def write_outputs(config_path: Path, output_dir: Path) -> None:
    cfg = load_config(config_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    fgt_cmds = build_fortigate_cli(cfg)
    pa_cmds = build_paloalto_cli(cfg)
    (output_dir / "fortigate_cli.txt").write_text("\n".join(fgt_cmds) + "\n", encoding="utf-8")
    (output_dir / "paloalto_cli.txt").write_text("\n".join(pa_cmds) + "\n", encoding="utf-8")
    print(f"Archivos de configuración escritos en {output_dir}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Genera comandos CLI para FortiGate y Palo Alto desde vpn_config.json.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Ruta al archivo vpn_config.json.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR, help="Directorio de salida.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        write_outputs(args.config, args.output_dir)
    except Exception as exc:  # pylint: disable=broad-except
        raise SystemExit(f"Error generando archivos de configuración: {exc}") from exc


if __name__ == "__main__":
    main()
