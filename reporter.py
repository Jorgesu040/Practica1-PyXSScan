# reporter.py
import os
from datetime import datetime

class ConsoleReporter:
    @staticmethod
    def mostrar_resumen(puntos_finales: list):
        """ Muestra un resumen de los puntos de inyección encontrados, su tipo de XSS, contexto y posibles payloads generados."""
        print("====== RESULTADOS DEL ESCANEO ======")
        for punto in puntos_finales:
            print(f"[*] Se han generado {len(punto.payloads_finales)} posibles payloads para el parámetro '{punto.parametro}':")
            for payload in punto.payloads_finales:
                print(f"    [{punto.metodo} - {punto.parametro}] -> {payload}")
            print("-" * 50)

    @staticmethod
    def crear_reporte_md(puntos_finales: list, url: str):
        """ Crea un reporte en formato Markdown con los resultados del escaneo. """
        # Asegurar que el directorio 'reportes' existe
        os.makedirs("reportes", exist_ok=True)
        
        # Generar nombre con timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join("reportes", f"reporte_xss_{timestamp}.md")
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("# Reporte de Escaneo XSS\n\n")
            f.write(f"**URL Objetivo:** `{url}`\n\n---\n\n")
            
            for punto in puntos_finales:
                f.write(f"## Punto de Inyección: `({punto.metodo}) {punto.parametro}`\n\n")
                f.write(f"- **Tipo de XSS:** `{punto.tipo_xss.name if punto.tipo_xss else 'NONE'}`\n")
                f.write(f"- **Contexto Evaluado:** `{punto.contexto.name if punto.contexto else 'NONE'}`\n")
                f.write(f"- **Filtros Detectados:** `{', '.join(punto.filtros_detectados) if punto.filtros_detectados else 'Ninguno'}`\n")
                
                f.write(f"\n### Payloads Generados ({len(punto.payloads_finales)})\n\n")
                
                # Usamos bloques de código para evitar que el markdown parsee HTML o rompa el formato
                f.write("```markdown\n")
                for payload in punto.payloads_finales:
                    f.write(f"{payload}\n")
                f.write("```\n\n---\n\n")

            f.write("# Enlaces Listos para Probar\n\n")
            for punto in puntos_finales:
                if not punto.payloads_finales:
                    continue
                    
                f.write(f"### `{punto.metodo}` - `{punto.parametro}`\n\n")
                for i, payload in enumerate(punto.payloads_finales, start=1):
                    if punto.metodo == 'GET':
                        import urllib.parse
                        # Codificar el payload para que el enlace sea válido y clickable
                        payload_encoded = urllib.parse.quote(payload)
                        enlace = f"[Enlace {i}]({url}?{punto.parametro}={payload_encoded})"
                        f.write(f"- {enlace}\n")
                    elif punto.metodo == 'POST':
                        f.write(f"- **[POST]** a `{url}` con cuerpo: `{punto.parametro}={payload}`\n")
                    elif punto.metodo == 'PATH':
                        import urllib.parse
                        payload_encoded = urllib.parse.quote(payload)
                        # Aseguramos que la URL no termine en / para no duplicarla con la inyección
                        base_url = url.rstrip('/')
                        enlace = f"[Enlace {i}]({base_url}/{payload_encoded})"
                        f.write(f"- {enlace}\n")
                    else:
                        f.write(f"- Método desconocido: `{payload}`\n")
                f.write("\n")
        
