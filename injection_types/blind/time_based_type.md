---
layout: default
title: 4.3 Basadas en tiempo
permalink: /injection_types/blind/time_based_type
nav_order: 3
parent: 4. Inyecciones ciegas
has_children: true
---

# Inyecciones ciegas basadas en tiempo

Esta variante utiliza **retrasos en la consulta SQL** para determinar si la inyección ha sido exitosa, por ejemplo, inducir una demora de 10 segundos. El tiempo preciso **depende de las demoras naturales del servidor** en procesar y responder **sumado a la latencia de la red**. En ocasiones 2 segundos podría ser más que suficiente para distinguir el resultado de la inyección, es algo que debe ajustarse para optimizar.

Continuando con el ejemplo anterior, se supone ahora que la aplicación detecta errores del DBMS y los maneja mejor, donde una consulta **ya no causa ninguna diferencia en la respuesta**. En esta situación, aún podría explotarse una inyección al provocar retrasos de forma condicional en la respuesta. 

Las técnicas para activar una demora **son muy específicas para el tipo de base de datos** que se utiliza. En *Microsoft SQL Server* por ejemplo, una entrada como la siguiente se puede usar para probar una condición y desencadenar un retraso dependiendo de si la expresión es verdadera:

```
'; IF (1=2) WAITFOR DELAY '0:0:10'-- 
'; IF (1=1) WAITFOR DELAY '0:0:10'-- 
```

En este caso la primera entrada no provoca un retaso al ser falsa la condición, y la segunda condición provoca un retraso de 10 segundos. Partiendo de esta consulta base podemos recuperar datos como ya se explicó en [4.2 Basadas en error](/sqli-en-la-practica/injection_types/blind/error_based_type), probando un caracter a la vez (`{delay}` debe ser sustituido por los segundos de demora):

```
'; IF (SELECT COUNT(Username) FROM Users 
    WHERE Username = 'Administrator' 
        AND SUBSTRING(Password, 1, 1) = 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
```

Respecto a optimizar las demoras, además de prueba y error o heurísticas, es de gran utilidad la sección de optimizaciones en [4.1 Con respuestas condicionales](/sqli-en-la-practica/injection_types/blind/conditional_type#optimizaciones), dado que apunta a reducir la cantidad necesaria de pedidos HTTP por caracter a adivinar.

Sintaxis para demoras en algunos otros DBMS:

| Oracle | `dbms_pipe.receive_message(('a'),10)` |
| PostgreSQL | `SELECT pg_sleep(10)` |
| MySQL | `SELECT SLEEP(10)` |