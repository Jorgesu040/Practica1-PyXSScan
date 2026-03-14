# Practica1-PyXSScan

Escáner XSS en Python para Hacking Ético en U-tad. Detecta parámetros GET/POST y PATH, analiza el contexto de reflexión, prueba filtros y genera payloads e informes Markdown.

[Informe de ejemplo](reportes_ejemplo/reporte_xss_ej4.md)

## Arquitectura

- `main.py`: Flujo de escaneo.
- `modelos.py`: Modelos de dominio (`PuntoInyeccion`) y enums (`TipoXSS`, `Contexto`).
- `http_requester.py`: Capa de red, crawling de formularios/inputs, envío de payloads y detección de filtros.
- `context_analyzer.py`: Análisis de contexto en DOM con BeautifulSoup.
- `payload_generator.py`: Selección de payloads base y mutaciones de evasión.
- `reporter.py`: Salida en consola y generación de reporte Markdown.
- `payloads.py`: Catálogo base de payloads por contexto.
- `filters.py`: Batería de filtros/caracteres a testear.

## Requisitos

- Python 3.10+
- Dependencias:
  - `requests`
  - `beautifulsoup4`

Instalación rápida:

```bash
pip install requests beautifulsoup4
```

## Ejecución

```bash
python main.py
```

Luego introduce una URL objetivo cuando el programa la solicite, por ejemplo:

```text
http://127.0.0.1/xss/example6.php?name=hacker
```

## Flujo de escaneo

1. Descubre parámetros y puntos de inyección.
2. Verifica reflexión/persistencia con canary.
3. Determina contexto (`SCRIPT`, `ATTRIBUTE`, `PLAIN_TEXT`, `COMENTARIO`, etc.).
4. Detecta filtros activos para cada entrada.
5. Genera payloads context-aware + evasión.
6. Muestra resumen y guarda reporte.

## Reportes

Al finalizar, se genera un reporte Markdown en:

- `./reportes/reporte_xss_YYYYMMDD_HHMMSS.md`

El reporte incluye:

- Punto de inyección.
- Tipo de XSS detectado.
- Contexto.
- Filtros detectados.
- Payloads generados.
- Enlaces listos para pruebas (GET/PATH URL-encoded).

## Nota de uso responsable

Esta herramienta está pensada para laboratorios, docencia y auditorías autorizadas.
No la uses contra sistemas sin permiso explícito.
