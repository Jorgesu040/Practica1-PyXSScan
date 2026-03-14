"""
Jorge Matesanz - Hacking etico - INSO 3A.

Para la presente practica, el alumno debera desarrollar las siguientes tareas:


- Desarrollar un script/herramienta que permita automatizar la identificacion y explotacion de vulnerabilidades XSS en Web for Pentesters (primeros 8 niveles). La herramienta debera incluir, como minimo, los siguientes apartados funcionales:

 1. Descubrimiento de entradas: deteccion automatica de parametros GET en URL, formularios POST en el HTML y puntos de inyeccion en la ruta (path injection).

 2. Verificacion de reflexion: envio de un texto único por cada entrada detectada y comprobacion de si el valor se refleja en la respuesta.

 3. Verificacion de persistencia (Stored XSS): tras inyectar el texto, realizar al menos una segunda peticion limpia para comprobar si la entrada persiste.

 4. Analisis de contexto: determinar donde se refleja el texto introducido, para adaptar el payload al contexto real.

 5. Deteccion de filtros: identificar caracteres bloqueados/codificados (por ejemplo <, >, comillas) y palabras prohibidas (por ejemplo script, alert, onerror).

 6. Tecnicas de evasion: proponer variantes de payloads (cambio de mayusculas/minusculas, alternativas de funciones JS como prompt/confirm, etc.) en funcion de los filtros detectados.

 7. Generacion de payloads: construir una lista de posibles payloads segun el contexto y los filtros identificados.

 10. Salida de resultados: mostrar de forma clara los parámetros pontencialmente vulnerables, el tipo de XSS y los payload propuestos.


"""


from context_analyzer import ContextAnalyzer
from http_requester import HttpRequester
from modelos import PuntoInyeccion, TipoXSS
from payload_generator import PayloadGenerator
from reporter import ConsoleReporter
import argparse




class XSSScanner:

    def __init__(self, url, canary = "p3nt35ting"):
        self.requester = HttpRequester(url)
        self.analyzer = ContextAnalyzer()
        self.generator = PayloadGenerator()
        self.canary = canary

    def _limpiar_puntos_none(self, puntos_inyeccion: list[PuntoInyeccion]) -> list[PuntoInyeccion]:
        """Elimina de self.puntos_inyeccion aquellos que no sean ni REFLECTED ni STORED"""
        return [p for p in puntos_inyeccion if p.tipo_xss != TipoXSS.NONE]
        
    def ejecutar(self):
        print(f"[*] Escaneando: {self.requester.url.geturl()}")
        puntos_inyeccion = self.requester.descubrir_entradas()
        
        print("[*] Puntos de inyección encontrados:")
        for punto in puntos_inyeccion:
            print(f" - {punto.metodo}: {punto.parametro}")
            self.requester.verificar_reflexion(punto, self.canary)
            self.requester.verificar_persistencia(punto, self.canary)

        puntos_inyeccion = self._limpiar_puntos_none(puntos_inyeccion)

        try:
            for punto in puntos_inyeccion:
                html = self.requester.inyectar_payload(punto, self.canary).text
                punto.contexto = self.analyzer.analizar(html, self.canary)
                self.requester.detectar_filtros(punto, self.canary)
            
                tipo_xss_str = punto.tipo_xss.name if punto.tipo_xss else 'NONE'
                contexto_str = punto.contexto.name if punto.contexto else 'NONE'
                
                print(f"[*] Generando payloads para:")
                print(f"    - Punto de inyección: ({punto.metodo}) {punto.parametro}")
                print(f"    - Tipo de XSS: {tipo_xss_str}")
                print(f"    - Contexto evaluado: {contexto_str}")
                
                payloads_base = self.generator.generar_payloads_base(punto.contexto)
                payloads_finales = set()
                
                for pb in payloads_base:
                    variantes_evasion = self.generator.aplicar_evasion(pb, punto.filtros_detectados)
                    payloads_finales.update(variantes_evasion)

                punto.payloads_finales = payloads_finales
                
        except KeyboardInterrupt:
            print("\n[!] Escaneo interrumpido por el usuario. Generando reporte parcial...")
        except Exception as e:
            print(f"\n[!] Error durante el escaneo: {str(e)}\nGenerando reporte parcial...")
        finally:
            ConsoleReporter.mostrar_resumen(puntos_inyeccion)
            ConsoleReporter.crear_reporte_md(puntos_inyeccion, self.requester.url.geturl())
            print("[*] Reporte Markdown generado.")

def main():
    """Main entry point of the application."""
    parser = argparse.ArgumentParser(description="PyXSScan - Escáner automatizado de inyección XSS")
    parser.add_argument("-u", "--url", type=str, help="URL objetivo a escanear (junto con http/https)")
    parser.add_argument("-c", "--canary", type=str, default="p3nt35ting", help="Modificar la cadena 'canary' o testigo para inyecciones (default: p3nt35ting)")
    
    args = parser.parse_args()

    url = args.url
    if not url:
        url = input("Ingrese la URL a escanear: ")

    scanner = XSSScanner(url, canary=args.canary)
    scanner.ejecutar()

if __name__ == "__main__":
    main()