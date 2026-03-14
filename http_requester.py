# http_requester.py
import requests
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from modelos import PuntoInyeccion, TipoXSS
from filters import filters  # Importamos tu lista actual de filtros

class HttpRequester:

    @staticmethod
    def sanitize_url(url):
        # Eliminar espacios y caracteres no deseados
        url = url.strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url  # Agregar http:// por defecto si no se especifica
        return url

    # Helper method to construct a URL with the payload injected into the path
    def _url_con_path_inyectado(self, payload):
        return self.url._replace(path=f"{self.url.path.rstrip('/')}/{payload}").geturl()


    def __init__(self, url: str):
        self.url = urlparse(self.sanitize_url(url))
        self.session = requests.Session() # Para el requisito 3 (Stored XSS)

    def descubrir_entradas(self) -> list[PuntoInyeccion]:
        """Devuelve una lista de Puntos de inyección detectados con GET/POST/PATH"""
        
        puntos_inyeccion = []
        
        # Descubrir parámetros GET
        query_params = parse_qs(self.url.query)
        for param in query_params:
            puntos_inyeccion.append(PuntoInyeccion(metodo='GET', parametro=param, url_destino=self.url.geturl()))

        # Punto de inyección en la ruta (path injection)
        puntos_inyeccion.append(PuntoInyeccion(metodo='PATH', parametro=self.url.path or '/', url_destino=self.url.geturl()))

        # Lógica con BeautifulSoup para llenar self.puntos_inyeccion
        response = self.session.get(self.url.geturl())
        soup = BeautifulSoup(response.content, 'html.parser')
        form_tags = soup.find_all("form")
        for form in form_tags:
            # El segundo argumento de .get() siempre es el valor por defecto
            # Obtener el método del formulario (GET o POST), si no se especifica, se asume GET
            method = form.get('method', 'GET').upper()
            action = form.get('action', '')
            
            from urllib.parse import urljoin
            target_url = urljoin(self.url.geturl(), action) if action else self.url.geturl()
            
            inputs = form.find_all('input')
            for input_tag in inputs:
                # Filtrar los inputs de tipo submit, ya que son botones
                if input_tag.get("type", "text").lower() == "submit":
                    continue
                name = input_tag.get('name')
                if name:
                    puntos_inyeccion.append(PuntoInyeccion(metodo=method, parametro=name, url_destino=target_url))
        
        return puntos_inyeccion

    def inyectar_payload(self, punto: PuntoInyeccion, payload: str) -> requests.Response:
        """Hace la petición y devuelve el HTML de respuesta"""
        # Obtenemos la url_destino del punto (si no tiene, caemos a la url original)
        url_target = punto.url_destino if punto.url_destino else self.url.geturl()
        
        if punto.metodo == 'GET':
            params = {punto.parametro: payload}
            response = self.session.get(url_target, params=params)
        elif punto.metodo == 'POST':
            data = {punto.parametro: payload}
            response = self.session.post(url_target, data=data)
        elif punto.metodo == 'PATH':
            response = self.session.get(self._url_con_path_inyectado(payload))
        
        return response
        
    def verificar_reflexion(self, punto: PuntoInyeccion, canary: str) -> bool:
        """Usa inyectar_payload y modifica el Enum del punto según resultado"""
        # Enviar un canary único y verificar si se refleja en la respuesta
        response = self.inyectar_payload(punto, canary)
        
        count = response.text.count(canary)
        
        if  count > 0:
            print(f"[*] Reflexión detectada en {punto.metodo}: {punto.parametro} ({count} veces)")
            punto.tipo_xss = TipoXSS.REFLECTED
            return True
        elif punto.tipo_xss != TipoXSS.STORED:
            print(f"[-] No se detectó reflexión en {punto.metodo}: {punto.parametro}")
            punto.tipo_xss = TipoXSS.NONE
            return False

    def verificar_persistencia(self, punto: PuntoInyeccion, canary: str) -> bool:
        """Usa inyectar_payload, luego hace una nueva petición para ver si el canary sigue ahí"""
        # Enviar un canary único y verificar si se refleja en la respuesta
        canary += 'per'
        
        self.inyectar_payload(punto, canary)

        count = self.session.get(self.url.geturl()).text.count(canary)
        
        if count > 0:
            print(f"[*] Persistencia detectada en {punto.metodo}: {punto.parametro} ({count} veces)")
            punto.tipo_xss = TipoXSS.STORED
            return True
        elif punto.tipo_xss != TipoXSS.REFLECTED:
            punto.tipo_xss = TipoXSS.NONE
        
        return False

    def detectar_filtros(self, punto_inyeccion: PuntoInyeccion, canary: str) -> None:
        """
        Envía peticiones con distintos filtros para ver cuáles son bloqueados o sanitizados.
        Si la respuesta no refleja el filtro, se añade a punto_inyeccion.filtros_detectados.
        """
        import html
        
        for filter_char_or_word in filters:
            test_canary = canary + filter_char_or_word
        
            # Inyectamos y obtenemos el texto de la respuesta cruda
            response_text = self.inyectar_payload(punto_inyeccion, test_canary).text

            # Si el texto exacto desaparece, el filtro está bloqueando o codificando la entrada 
            if test_canary not in response_text:
                if html.escape(test_canary) in response_text and filter_char_or_word != html.escape(filter_char_or_word):
                    print(f"[-] Filtro detectado en {punto_inyeccion.metodo}: {punto_inyeccion.parametro} - El carácter '{filter_char_or_word}' se codifica a HTML ({html.escape(filter_char_or_word)})")
                else:
                    print(f"[-] Filtro detectado en {punto_inyeccion.metodo}: {punto_inyeccion.parametro} - Caracter/Palabra bloqueada: '{filter_char_or_word}'")
                
                punto_inyeccion.filtros_detectados.append(filter_char_or_word)

