# Practica1-PyXSScan

Herramienta en Python para automatizar la identificación de vectores XSS, con enfoque en descubrimiento de entradas, verificación, análisis de contexto, detección de filtros y generación de payloads con evasión.

Diseñada con fines educativos y para mi asignatura de Hacking ético, permite a los usuarios verificar la seguridad de parámetros GET/POST y PATH en aplicaciones web y, en caso de detectar reflexión/persistencia, crear payloads XSS.

El proyecto esta testeado en Web for Pentesters (primeros niveles)

## Objetivo

Este proyecto implementa un escáner modular para:

1. Descubrir entradas inyectables (GET, POST y PATH).
2. Verificar reflexión (Reflected XSS).
3. Verificar persistencia (Stored XSS).
4. Analizar el contexto HTML/JS de reflexión.
5. Detectar filtros (bloqueo o codificación).
6. Aplicar técnicas de evasión.
7. Generar payloads por contexto.
8. Presentar resultados en consola y en reporte Markdown.

## Arquitectura

El proyecto está modularizado aplicando responsabilidad única:

- `main.py`: Orquestador del flujo completo de escaneo.
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
