# Registro de cambios

## Sin publicar - 2026-06-05 (v1.3.1)

### Nuevos modulos

- **Login headless (Playwright):** autenticacion en SPAs Angular/Vue/React y flujos OAuth2/PKCE. El tool intenta el login headless automaticamente cuando no detecta un formulario HTML; admite campos de email/usuario en dos pasos (Next/Siguiente), extrae cookies del navegador y las carga en la sesion requests. Si Playwright no esta instalado se ofrece instalarlo. Fallback al modo manual.
- **SSRF:** payloads contra parametros URL (url, redirect, src, etc.) y cabeceras HTTP (X-Forwarded-For, X-Original-URL, Client-IP, Referer, Origin); detecta respuestas con marcadores de metadatos cloud (AWS IMDSv1, GCP, Alibaba); soporte OOB con URL de colaborador externo (Burp Collaborator, interactsh).
- **SSTI:** deteccion por math probes ({{7*7}}, ${7*7}, #{7*7}, <%= 7*7 %>, etc.) para Jinja2, Twig, FreeMarker, ERB, Pebble, Tornado/Mako, Thymeleaf. Identifica el engine y detecta errores de template.
- **XXE:** descubrimiento de endpoints XML/SOAP (xmlrpc.php, /soap, /api/xml, .asmx); inyeccion de entidades externas (file:///etc/passwd, /etc/hostname) y SSRF via DTD externo a metadatos cloud.
- **CRLF Injection:** payloads %0d%0a y variantes unicode en path y parametros de redireccion; verifica cabeceras inyectadas sin seguir redirecciones.
- **HTTP Request Smuggling:** usa smuggler.py si esta disponible; prueba manual CL.TE con socket raw (deteccion de 400 por conflicto CL/TE); instrucciones de instalacion si falta.
- **Cache Poisoning:** inyecta X-Forwarded-Host, X-Host, X-Original-URL, X-Rewrite-URL, X-Forwarded-Server con valor aleatorio unico; confirma si el valor persiste en respuesta posterior sin la cabecera; detecta presencia de cache via X-Cache/Age/CF-Cache-Status.
- **Nuevo menu opcion 10** para las pruebas avanzadas; opciones 10-17 renumeradas a 11-18.

### Mejoras a modulos existentes

- **JWT avanzado:** alg:none bypass activo (genera token modificado y comprueba si el servidor lo acepta), advertencia RS256->HS256 key confusion, deteccion de kid path traversal y kid SQLi, brute force de secreto HMAC con wordlist reducida (configurable), deteccion de token caducado aceptado.
- **Rate limiting:** ademas de HTTP 429, detecta soft-block por latencia progresiva (factor 2.5x entre primeras y ultimas peticiones), captcha en respuesta, ban por IP (5+ respuestas 403 consecutivas).
- Version bump a 1.3.0.

## Sin publicar - 2026-06-05 (v1.3.1)

### Reportes y tablas visuales para modulos avanzados

- **Tablas CLI en run_advanced_security_tests:** tras cada sub-modulo se imprime una tabla box-drawing con los hallazgos (SSRF, SSTI, XXE, CRLF, Smuggling, Cache Poisoning) y una tabla resumen global al final con contador por modulo.
- **Reporte HTML:** nueva seccion "Pruebas Avanzadas" con paneles independientes para cada modulo (resumen + SSRF + SSTI + XXE + CRLF + Smuggling + Cache Poisoning); KPI "Adv. Security" anadido al dashboard con icono shield-warning; la seccion solo aparece si el modulo fue ejecutado.
- **Reporte Markdown:** bloque "## Pruebas Avanzadas de Seguridad" con tabla resumen y sub-secciones detalladas por modulo (solo si hay hallazgos).
- **Reporte TXT:** bloque "[PRUEBAS AVANZADAS DE SEGURIDAD]" con lista por modulo y detalle de cada hallazgo.
- **scan_stats:** seis nuevas metricas (adv_ssrf_hits, adv_ssti_hits, adv_xxe_hits, adv_crlf_hits, adv_smuggling_hits, adv_cache_hits) incluidas en el JSON de stats para trazabilidad.
- **print_final_summary:** tabla ejecutiva ampliada con los seis contadores de pruebas avanzadas; tabla detallada por modulo con colores (rojo para criticos: SSRF/SSTI/XXE/Smuggling; amarillo para medios: CRLF/Cache) mostrada solo cuando hay hallazgos.

## Sin publicar - 2026-06-05

- Validacion real de credenciales en Basic Auth: solo se da por valido si el servidor responde `401 WWW-Authenticate: Basic` y luego acepta las credenciales. Corrige un falso positivo en el que cualquier HTTP 200 (incluida la pagina de login tras redireccion) se reportaba como login exitoso.
- La sesion Basic Auth fija `session.auth`, de modo que las peticiones posteriores envian realmente las credenciales (antes la sesion no quedaba autenticada).
- Login con usuario o email mediante un unico campo identificador; se detecta el tipo por `@` y se rellena el campo de formulario correcto (`user`/`login` o `email`/`correo`), separando ambos en la deteccion del formulario.
- User-Agent personalizado configurable, aplicado al login con credenciales y al modo manual de sesion.
- Deteccion de fallo de login (marcadores ES/EN) y rechazo si la respuesta sigue mostrando un campo de contrasena; el modo manual valida la sesion contra el objetivo antes de confiar en ella.
- Verificacion post-login que reaccede al objetivo para confirmar que la sesion persiste (detecta redirecciones/CSRF que invalidan el login).

## Sin publicar - 2026-05-16

- Se anadio deteccion automatica de WordPress en el flujo de pentesting completo: primero se revisan los resultados de WhatWeb y despues se usa deteccion manual por patrones antes de ejecutar WPScan.
- Se anadieron senales de deteccion manual de WordPress para `wp-content`, `wp-includes`, `wp-json`, `wp-login.php`, `xmlrpc.php`, metadatos `generator` y assets comunes de WordPress.
- Se mantiene la ejecucion directa de WPScan desde la opcion manual de WordPress.
- Se anadio salida CLI nativa de WPScan durante la enumeracion y la fuerza bruta de WordPress, conservando el parseo JSON estructurado para el resumen final.
- Se amplio el resumen de WordPress con version del core, plugins, temas, usuarios, hallazgos interesantes, vulnerabilidades y credenciales.
