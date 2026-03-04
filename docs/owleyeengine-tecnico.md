# OwlEyeEngine - Notas Tecnicas de Bajo Nivel

## 1) Registros y rendimiento
Los registros CPU son el almacenamiento mas rapido y mas volatil.
No persisten entre procesos ni tras cambio de contexto.

Implicacion:
- Si tu pipeline mueve datos innecesariamente entre registros y RAM, sube la latencia.
- Si hay exceso de threads, crecen los context switches y cae el throughput util.

## 2) Context switch y costo real
En cada cambio de contexto, el scheduler debe:
1. Guardar estado del proceso actual (registros + metadata).
2. Cargar estado del proximo proceso.
3. Rehidratar caches/TLB de forma indirecta.

Riesgo en motores de red:
- Mucha concurrencia fina + lock contention = CPU alta sin trabajo util.

Recomendaciones:
- Preferir modelo event-driven o worker pool acotado.
- Medir: switches/seg, uso CPU en kernel mode, latencia p95/p99.
- Evitar crear/destruir hilos por request.

## 3) Privilegios y registros protegidos
Registros de control (ej. `CR3` en x86) son de modo privilegiado.

Regla:
- User-space no debe escribir registros protegidos directamente.
- Usar syscalls/APIs del sistema operativo.

En C/C++:
- Usar `asm` solo si hay justificacion de performance medible.
- Validar ABI, clobbers y portabilidad.

## 4) Integracion con este proyecto
Este repositorio captura eventos de red y detecta patrones anormales:
- SYN flood probable.
- Port scan probable.
- Acceso a puertos sensibles.
- Picos de trafico.

Uso recomendado en OwlEyeEngine:
1. Ejecutar captura en host de prueba.
2. Ajustar umbrales por entorno (`ALERT_*`).
3. Enviar alertas de severidad media/alta a canal operativo.
4. Correlacionar con metricas de scheduler y CPU para diagnostico.
