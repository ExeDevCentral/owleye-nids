# Resumen Examen Cisco - Configuration Register

## 1) Control de boot
El `configuration register` define como arranca el router.

- `0x2102` (normal):
  - Carga `startup-config` desde NVRAM.
  - Busca y carga IOS desde Flash.

Cambiar este valor cambia el flujo de arranque del equipo.

## 2) Recuperacion de contrasena
El valor clasico para bypass de configuracion es:

- `0x2142`:
  - Arranca ignorando temporalmente `startup-config`.
  - Permite entrar en modo privilegiado y resetear credenciales.

Flujo tipico:
1. Cambiar registro a `0x2142`.
2. Reiniciar.
3. Entrar a modo privilegiado sin aplicar config previa.
4. Recuperar/definir contrasenas.
5. Restaurar `0x2102`.
6. Guardar y reiniciar.

## 3) Comandos utiles (referencia)
```text
show version
show running-config
show startup-config
conf t
config-register 0x2102
end
write memory
reload
```

## 4) Punto de examen
- `0x2102` = arranque normal.
- `0x2142` = ignora startup-config para recovery.
- Siempre volver al valor normal al finalizar la recuperacion.
