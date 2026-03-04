#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import sys
from typing import Any, Dict, Optional

from scapy.all import ICMP, IP, TCP, UDP, sniff  # type: ignore


def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def get_layer_field(packet: Any, layer: Any, field: str, default: Optional[Any] = None) -> Any:
    if not packet.haslayer(layer):
        return default
    try:
        return getattr(packet[layer], field)
    except Exception:
        return default


def packet_to_event(packet: Any, server_ip: Optional[str]) -> Optional[Dict[str, Any]]:
    if not packet.haslayer(IP):
        return None

    src_ip = get_layer_field(packet, IP, "src")
    dst_ip = get_layer_field(packet, IP, "dst")

    if server_ip and src_ip != server_ip and dst_ip != server_ip:
        return None

    event: Dict[str, Any] = {
        "timestamp_utc": iso_now(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "ip_proto": get_layer_field(packet, IP, "proto"),
        "packet_len": len(packet),
        "direction": "to_server" if server_ip and dst_ip == server_ip else "from_server" if server_ip and src_ip == server_ip else "unknown",
        "layer4": "OTHER",
        "src_port": None,
        "dst_port": None,
        "flags": None,
        "icmp_type": None,
        "icmp_code": None,
    }

    if packet.haslayer(TCP):
        event["layer4"] = "TCP"
        event["src_port"] = get_layer_field(packet, TCP, "sport")
        event["dst_port"] = get_layer_field(packet, TCP, "dport")
        flags = get_layer_field(packet, TCP, "flags")
        event["flags"] = str(flags) if flags is not None else None
    elif packet.haslayer(UDP):
        event["layer4"] = "UDP"
        event["src_port"] = get_layer_field(packet, UDP, "sport")
        event["dst_port"] = get_layer_field(packet, UDP, "dport")
    elif packet.haslayer(ICMP):
        event["layer4"] = "ICMP"
        event["icmp_type"] = get_layer_field(packet, ICMP, "type")
        event["icmp_code"] = get_layer_field(packet, ICMP, "code")

    return event


def fmt_event(event: Dict[str, Any]) -> str:
    base = (
        f"[{event['timestamp_utc']}] "
        f"{event['direction']} "
        f"{event['layer4']} "
        f"{event['src_ip']}:{event['src_port']} -> {event['dst_ip']}:{event['dst_port']} "
        f"len={event['packet_len']}"
    )

    if event["layer4"] == "TCP" and event["flags"]:
        base += f" flags={event['flags']}"
    if event["layer4"] == "ICMP":
        base += f" type={event['icmp_type']} code={event['icmp_code']}"

    return base


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Monitor de red de bajo nivel entre tu PC y un servidor (TCP/UDP/ICMP)."
    )
    parser.add_argument("--iface", help="Interfaz de red (opcional). Ej: Ethernet, Wi-Fi")
    parser.add_argument("--server-ip", help="IP del servidor para filtrar el trafico")
    parser.add_argument(
        "--bpf",
        default="ip",
        help="Filtro BPF opcional. Ej: 'host 192.168.1.10 and (tcp or udp or icmp)'",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Cantidad de paquetes a capturar (0 = infinito)",
    )
    parser.add_argument(
        "--out",
        default="network_lowlevel_log.jsonl",
        help="Archivo de salida JSONL",
    )

    args = parser.parse_args()

    print("Iniciando captura...")
    print(f"Interfaz: {args.iface or 'auto'}")
    print(f"Filtro BPF: {args.bpf}")
    if args.server_ip:
        print(f"Filtrando por servidor: {args.server_ip}")
    print(f"Guardando eventos en: {args.out}")
    print("Presiona Ctrl+C para detener.\n")

    processed = 0

    try:
        with open(args.out, "a", encoding="utf-8") as fp:
            def on_packet(packet: Any) -> None:
                nonlocal processed
                event = packet_to_event(packet, args.server_ip)
                if not event:
                    return
                fp.write(json.dumps(event, ensure_ascii=False) + "\n")
                fp.flush()
                print(fmt_event(event))
                processed += 1

            sniff(
                iface=args.iface,
                filter=args.bpf,
                prn=on_packet,
                store=False,
                count=args.count if args.count > 0 else 0,
            )

    except PermissionError:
        print(
            "Error: permisos insuficientes para capturar paquetes. Ejecuta la terminal como administrador.",
            file=sys.stderr,
        )
        return 1
    except OSError as exc:
        print(f"Error del sistema al iniciar la captura: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        pass

    print(f"\nCaptura finalizada. Eventos procesados: {processed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
