# Registro de cambios

## v1.3.2 — 2026-06-05

### Endurecimiento de la capa HTTP (afecta a todas las peticiones)

- **Reintentos de red:** la sesion monta un HTTPAdapter con reintentos ante errores de conexion/lectura transitorios (connect/read = 2, backoff 0.3). No reintenta por codigo de estado (`status=0`), de modo que 429 y 5xx siguen llegando intactos a los modulos de rate-limit y deteccion de errores. Reduce falsos negativos, especialmente en la fuerza bruta de login (un corte transitorio ya no se cuenta como credencial fallida).
- **Pool de conexiones:** pool elevado a 50 conexiones por host. Antes urllib3 limitaba a 10, estrangulando los modulos con hilos (vhost, directorios, fuerza bruta); ahora la concurrencia real no tiene cuello de botella.
- **--delay global:** el retardo entre peticiones se aplica ahora a TODAS las peticiones de la sesion mediante un hook de respuesta, no solo a los tres modulos con hilos. Fuente unica de verdad; eliminados los `time.sleep` locales redundantes. Mejora la evasion de WAF/rate-limit en objetivos autorizados.

## v1.3.1 — 2026-06-05

### Reportes y tablas visuales para modulos avanzados

- **Tablas CLI:** tras cada sub-modulo de pruebas avanzadas se imprime una tabla box-drawing con los hallazgos (SSRF, SSTI, XXE, CRLF, Smuggling, Cache Poisoning) y una tabla resumen global al final con contador por modulo.
- **Reporte HTML:** nueva seccion "Pruebas Avanzadas" con paneles independientes para cada modulo; KPI "Adv. Security" anadido al dashboard con icono shield-warning; la seccion solo aparece si el modulo fue ejecutado.
- **Reporte Markdown:** bloque "## Pruebas Avanzadas de Seguridad" con tabla resumen y sub-secciones detalladas por modulo (solo si hay hallazgos).
- **Reporte TXT:** bloque "[PRUEBAS AVANZADAS DE SEGURIDAD]" con lista por modulo y detalle de cada hallazgo.
- **scan_stats:** seis nuevas metricas (adv_ssrf_hits, adv_ssti_hits, adv_xxe_hits, adv_crlf_hits, adv_smuggling_hits, adv_cache_hits) en el JSON de estadisticas.
- **Resumen final:** tabla ejecutiva ampliada con los seis contadores; tabla detallada por modulo con colores de severidad (rojo: SSRF/SSTI/XXE/Smuggling; amarillo: CRLF/Cache), mostrada solo cuando hay hallazgos.
- **README:** menu actualizado con indicacion de que opciones 16/17 aparecen solo tras escanear.

## v1.3.0 — 2026-06-05

### Nuevos modulos

- **Login headless (Playwright):** autenticacion en SPAs Angular/Vue/React y flujos OAuth2/PKCE. Se intenta automaticamente cuando no hay formulario HTML; admite campos de email/usuario en dos pasos (Next/Siguiente); extrae cookies del navegador y las carga en la sesion requests. Si Playwright no esta instalado se ofrece instalarlo en el momento. Fallback al modo manual.
- **SSRF:** payloads contra parametros URL (url, redirect, src, etc.) y cabeceras HTTP (X-Forwarded-For, X-Original-URL, Client-IP, Referer, Origin); detecta respuestas con marcadores de metadatos cloud (AWS IMDSv1, GCP, Alibaba); soporte OOB con URL de colaborador externo (Burp Collaborator, interactsh).
- **SSTI:** deteccion por math probes ({{7*7}}, ${7*7}, #{7*7}, <%= 7*7 %>, etc.) para Jinja2, Twig, FreeMarker, ERB, Pebble, Tornado/Mako, Thymeleaf. Identifica el engine y detecta errores de template.
- **XXE:** descubrimiento de endpoints XML/SOAP (xmlrpc.php, /soap, /api/xml, .asmx); inyeccion de entidades externas (file:///etc/passwd, /etc/hostname) y SSRF via DTD externo a metadatos cloud.
- **CRLF Injection:** payloads %0d%0a y variantes unicode en path y parametros de redireccion; verifica cabeceras inyectadas sin seguir redirecciones.
- **HTTP Request Smuggling:** usa smuggler.py si esta disponible; prueba manual CL.TE con socket raw; instrucciones de instalacion si falta.
- **Cache Poisoning:** inyecta X-Forwarded-Host, X-Host, X-Original-URL, X-Rewrite-URL, X-Forwarded-Server con valor aleatorio unico; confirma si el valor persiste en respuesta posterior sin la cabecera; detecta presencia de cache via X-Cache/Age/CF-Cache-Status.
- **Menu opcion 10** dedicada a pruebas avanzadas; opciones siguientes renumeradas hasta la 18.

### Mejoras a modulos existentes

- **JWT avanzado:** alg:none bypass activo, advertencia RS256->HS256 key confusion, deteccion de kid path traversal y kid SQLi, brute force de secreto HMAC con wordlist reducida, deteccion de token caducado aceptado.
- **Rate limiting:** ademas de HTTP 429, detecta soft-block por latencia progresiva (factor 2.5x), captcha en respuesta y ban por IP (5+ respuestas 403 consecutivas).

## v1.2.1 — 2026-06-05

- Validacion real de credenciales en Basic Auth: solo valido si el servidor responde `401 WWW-Authenticate: Basic` y luego acepta las credenciales. Corrige falso positivo donde cualquier HTTP 200 (incluyendo pagina de login tras redireccion) se reportaba como exito.
- La sesion Basic Auth fija `session.auth` para que peticiones posteriores envien realmente las credenciales.
- Login con usuario o email mediante un unico campo identificador; se detecta el tipo por `@` y se rellena el campo de formulario correcto (`user`/`login` o `email`/`correo`).
- User-Agent personalizado configurable, aplicado al login con credenciales y al modo manual.
- Deteccion de fallo de login (marcadores ES/EN) y rechazo si la respuesta sigue mostrando un campo de contrasena.
- Verificacion post-login que reaccede al objetivo para confirmar que la sesion persiste.

## v1.2.0 — 2026-05-16

- Deteccion automatica de WordPress en el flujo de pentesting completo: primero se revisan los resultados de WhatWeb y despues se usa deteccion manual por patrones antes de ejecutar WPScan.
- Senales de deteccion manual de WordPress para `wp-content`, `wp-includes`, `wp-json`, `wp-login.php`, `xmlrpc.php`, metadatos `generator` y assets comunes.
- Salida CLI nativa de WPScan durante la enumeracion y la fuerza bruta, conservando el parseo JSON estructurado para el resumen final.
- Resumen de WordPress ampliado con version del core, plugins, temas, usuarios, hallazgos interesantes, vulnerabilidades y credenciales.
