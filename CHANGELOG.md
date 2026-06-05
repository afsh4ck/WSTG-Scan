# Registro de cambios

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
