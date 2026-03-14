# modelos.py
from enum import Enum
from dataclasses import dataclass, field

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
    metodo: str
    parametro: str
    url_destino: str = "" # URL específica (ej. para action de formularios)
    tipo_xss: TipoXSS = TipoXSS.NONE
    contexto: Contexto = Contexto.OTHER
    filtros_detectados: list[str] = field(default_factory=list)
    payloads_finales: set[str] = field(default_factory=set)