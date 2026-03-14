# context_analyzer.py
from bs4 import BeautifulSoup, Comment
from modelos import Contexto

class ContextAnalyzer:
    def analizar(self, html: str, canary: str) -> Contexto:
        """
        Analiza el HTML y determina el contexto donde se refleja el canary.
        
        """
        soup = BeautifulSoup(html, 'html.parser')

        # Caso 1: Comentario HTML
        comment_finds = soup.find_all(
            string=lambda text: isinstance(text, Comment) and canary in text
        )
        if len(comment_finds) > 0:
            return Contexto.COMENTARIO
        
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
                    return Contexto.SCRIPT_SINGLE_QUOTE
                elif f'"{canary}"' in script_content or f'"{canary}' in script_content or f'{canary}"' in script_content:
                    return Contexto.SCRIPT_DOUBLE_QUOTE
                else:
                    return Contexto.SCRIPT_NONE_QUOTE
            # Caso 2.2: Texto plano
            else:
                return Contexto.PLAIN_TEXT

        # Caso 3: Atributo HTML
        if any(canary in str(v) for tag in soup.find_all(True) for v in tag.attrs.values()):
            return Contexto.ATTRIBUTE

        # Si no encaja en nada o no se encuentra
        return Contexto.OTHER


