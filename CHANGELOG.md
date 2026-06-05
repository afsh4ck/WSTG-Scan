# Registro de cambios

## v1.4.0 — 2026-06-05

### Soporte multi-objetivo

- **Lista de objetivos:** ademas de `-u` (ahora repetible y con varias URLs separadas por comas) se anade `-L/--list` para cargar ficheros con una URL por linea (admite comentarios `#` y lineas vacias). Las fuentes se combinan y deduplican normalizando la URL.
- **Modo batch (`--batch`):** no interactivo. Ejecuta el pentest completo en cada objetivo, guarda un reporte por objetivo en `reports/<host>/` y muestra un resumen global con hallazgos por objetivo. El modulo Active Directory se omite en batch. Requiere `-u`/`-L`.
- **Modo multi-objetivo interactivo:** al pasar mas de un objetivo sin `--batch`, el menu muestra la lista y cada opcion seleccionada se ejecuta secuencialmente en todos los objetivos. Cada objetivo mantiene su propio estado (`SCAN_DATA`/`FINDINGS`) entre modulos, de modo que se pueden encadenar varias pruebas y al salir se guarda un reporte por objetivo.
- **Selector interactivo sin argumentos:** al ejecutar el script sin `-u`/`-L` se pregunta si el objetivo es una URL unica o una lista. En modo lista se aceptan varias URLs (coma/espacio) o la ruta a un fichero, y se ofrece elegir entre batch y multi interactivo.
- **Estado por objetivo:** nueva factoria `_fresh_scan_data()` y helpers de reset/snapshot/restore para aislar el estado global entre objetivos sin reescribir los modulos existentes.
- **Compatibilidad:** el flujo de un solo objetivo (interactivo) permanece igual; `run_full_pentest` acepta `interactive_ad` para poder omitir el prompt de Active Directory en batch.

## v1.3.3 — 2026-06-05

### Mejoras al testing de APIs (OWASP API Top 10)

- **Hallazgos de API en los reportes:** descubrimiento (Swagger expuesto), auth bypass, IDOR/BOLA, Mass Assignment, GraphQL y errores verbose ahora se registran en `FINDINGS` y aparecen en HTML/Markdown/TXT y en el resumen final. Antes solo se imprimian en consola y se perdian al cerrar.
- **Fix de bug latente en reportes:** los hallazgos en formato dict (modulos SSRF/SSTI/XXE/CRLF/Smuggling/Cache/JWT/Rate) crasheaban el reporte TXT y el resumen final, que asumian cadenas. Nuevo normalizador `_finding_text` aplicado en los cuatro renders (HTML, Markdown, TXT, resumen); convierte dict y str al formato canonico `[CAT] nombre: detalle`.
- **IDOR/BOLA con menos falsos positivos:** sonda de control con un id inexistente; si el endpoint devuelve el mismo contenido para cualquier id (shell/SPA) se descarta. Solo se reporta cuando el objeto alterno difiere de la representacion de "no existe". Eliminado el id invalido `../1`.
- **Mass Assignment con verificacion de persistencia:** tras inyectar el campo privilegiado se hace re-GET del objeto y se confirma que el valor persistio (severidad alta). Si solo se refleja en la respuesta sin confirmar persistencia, se reporta como posible (media). Sustituye la heuristica anterior de buscar "success" en el body.
- **Descubrimiento de endpoints multihilo:** el fuzzing recursivo prefijo x recurso se ejecuta con `ThreadPoolExecutor` (aprovecha el pool de conexiones de v1.3.2). Ganancia grande en objetivos con muchos prefijos.
- **JWT con mas fuentes:** ademas de cabeceras y header Authorization, se buscan tokens en el jar de cookies de la sesion, en el cuerpo de la respuesta (SPAs) y en los endpoints de API descubiertos.
- **Auth bypass mas preciso:** las cabeceras `X-Original-URL`/`X-Rewrite-URL` apuntan al path real del endpoint restringido; baseline que descarta paginas de login/SPA genericas para no marcar 200 inocuos.
- **Limpieza:** eliminadas dos definiciones duplicadas y muertas (`test_jwt_tokens` y `test_api_rate_limiting`) que quedaban sombreadas por las versiones de v1.3.0.

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
