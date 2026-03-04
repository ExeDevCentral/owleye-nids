# owleye-nids

`owleye-nids` es una herramienta de observabilidad de red de bajo nivel para detectar comportamiento anomalo entre tu PC y un servidor en tiempo real.

## Potencial
- Convierte trafico crudo (TCP/UDP/ICMP) en telemetria accionable.
- Detecta temprano patrones de riesgo: `SYN flood`, `port scan`, picos de trafico y puertos sensibles.
- Escala de laboratorio a operacion: dashboard live + notificaciones a Discord/Telegram.
- Base practica para hardening, respuesta a incidentes y tuning de motores de red (ej. OwlEyeEngine).

## Quick Start
```powershell
pip install -r requirements.txt
Copy-Item .\.env.example .\.env
.\run.ps1 -ServerIp 192.168.1.50
```

Abrir: `http://127.0.0.1:8787`

## Archivos clave
- `net_lowlevel_monitor.py`: captura y exporta eventos a JSONL.
- `net_lowlevel_dashboard.py`: visualizacion, reglas de alerta y notificaciones.
- `run.ps1`: levanta monitor + dashboard en dos terminales.
- `docs/resumen-examen-cisco.md`: guia corta para examen Cisco.
- `docs/owleyeengine-tecnico.md`: guia tecnica de rendimiento/kernel.
