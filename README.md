# SSL Labs Scanner

Programa en Go que utiliza la API de SSL Labs para verificar la seguridad TLS de un dominio dado.

## Descripción

Este programa analiza la configuración TLS/SSL de un dominio usando la API pública de SSL Labs (Qualys). El análisis incluye:

- **Calificación de seguridad TLS** (Grade: A+, A, A-, B, C, D, E, F, T, M)
- **Protocolos TLS soportados** (TLS 1.2, TLS 1.3, etc.)
- **Información del certificado** (emisor, validez)

## Requisitos

- Go 1.16 o superior
- Conexión a Internet

## Instalación

No requiere instalación. Solo clona el repositorio y ejecuta directamente con `go run`.

## Uso

```bash
go run main.go <domain>
```

### Ejemplos

```bash
# Verificar seguridad TLS de google.com
go run main.go google.com

# Verificar seguridad TLS de github.com
go run main.go github.com
```

### Ejemplo de salida

```
SSL Labs Scanner - Verificando seguridad TLS de: google.com

Resolviendo DNS...
Evaluando seguridad TLS...
Evaluando seguridad TLS... (84%)
Evaluación completada.

✅ Evaluación completada

=== Resultados de Seguridad TLS ===
Dominio: google.com
Grade General: A+

--- Endpoint 1: 142.250.80.110 ---
Grade: A+
Protocolos TLS: TLS 1.2, TLS 1.3
Certificado Emisor: Google Trust Services LLC
Certificado Válido: 2024-01-01 hasta 2024-12-31
```

## Características

- ✅ Validación de dominio de entrada
- ✅ Polling variable (5s hasta IN_PROGRESS, luego 10s) según recomendaciones de SSL Labs
- ✅ Timeout de 10 minutos para evitar loops infinitos
- ✅ Manejo robusto de errores (HTTP, red, timeout, etc.)
- ✅ Soporte para múltiples endpoints
- ✅ Comparación de grades para determinar el peor cuando hay múltiples endpoints
- ✅ Información clara y legible de seguridad TLS

## Decisiones Técnicas Importantes

### Polling Variable

El programa implementa polling variable según las recomendaciones de SSL Labs:
- **5 segundos** de espera hasta que el estado cambie a `IN_PROGRESS`
- **10 segundos** de espera después de `IN_PROGRESS` hasta completar

Esto ayuda a evitar rate limiting y es más eficiente, ya que las evaluaciones suelen tomar 60-90 segundos.

### Comparación de Grades

Cuando hay múltiples endpoints, el programa compara los grades y muestra el peor como "Grade General". El orden de comparación es:

`A+ > A > A- > B+ > B > B- > C+ > C > C- > D+ > D > D- > E > F > T > M`

### Protocolos TLS

El programa solo muestra protocolos TLS seguros (donde `Q == null` en la respuesta de la API). Los protocolos inseguros (donde `Q == 0`) son filtrados automáticamente.

### Manejo de Errores

El programa maneja los siguientes casos de error:

- **Dominio inválido**: Validación antes de hacer llamadas a la API
- **Errores de red**: Timeout, DNS, sin conexión
- **Códigos HTTP**: 400, 429, 500, 503, 529
- **Estado ERROR**: Muestra el mensaje de error de la API
- **Timeout**: Si la evaluación toma más de 10 minutos
- **Errores de parsing**: Manejo de errores de JSON

Todos los errores se muestran en `stderr` y el programa termina con código de salida 1.

## Estructura del Proyecto

```
.
├── main.go              # Código principal del programa
├── go.mod              # Módulo Go
├── TODO.md             # Lista de tareas y progreso
├── README.md           # Este archivo
└── ssllabs-api-docs-v2-deprecated.md  # Documentación de la API
```

## API de SSL Labs

Este programa utiliza la API pública de SSL Labs:
- Base URL: `https://api.ssllabs.com/api/v2/`
- Endpoint principal: `/analyze`
- Documentación: Ver `ssllabs-api-docs-v2-deprecated.md`

**Nota**: La API de SSL Labs tiene términos y condiciones. Este programa:
- No publica resultados (`publish=off`)
- Usa polling variable para evitar sobrecargar el servicio
- Respeta los rate limits

## Licencia

Este proyecto fue desarrollado como parte del reto Nebula.

## Autor

Desarrollado para el Challenge Nebula.
