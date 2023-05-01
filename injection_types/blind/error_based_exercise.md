---
layout: default
title: Ejercicio práctico
permalink: /injection_types/blind/error_based_type/error_based_exercise
nav_order: 1
parent: 4.2 Basadas en error
grand_parent: 4. Inyecciones ciegas
---

# Ejercicio práctico de inyección ciega basada en error

> Ejercicio basado en el laboratorio "Lab: Blind SQL injection with conditional errors" de Web Security Academy (PortSwigger).

## Consigna

Este laboratorio contiene una vulnerabilidad de inyección de SQL ciega. La aplicación usa una cookie de rastreo (*tracking*) para análisis y ejecuta una consulta SQL con el valor de esta cookie. 

Los datos de la consulta no se retornan y la aplicación no responde diferente basado en si la consulta resulta en algún registro válido. Si la consulta SQL causa un error, la aplicación devuelve un mensaje de error.

La base de datos contiene una tabla diferente llamada `users`, con columnas llamadas `username` y `password`.

Para resolver el laboratorio, obtener el usuario y contraseña del usuario `administrator` e iniciar sesión con estas credenciales.

## Resolución manual + OWASP ZAP

Luego de un primer acceso a la aplicación y por sugerencia de la consigna, analizando las cookies se observa que figura una llamada `TrackingId` con un valor alfanumérico. Para modificarla en pedidos siguientes es pertinente usar un proxy de ataque como OWASP ZAP para practicidad.

De la lista de la pestaña "History", seleccionar un pedido HTTP que incluya la cookie `TrackingId` y abrirlo en la herramienta "Requester" con `Ctrl+W` o seleccionando la opción "Open in Requester Tab..." del menú contextual con click derecho. Esto muestra el mismo pedido pero en modo de edición:

![Requester](/sqli-en-la-practica/assets/error_ex_1.png)

Desde aquí hay que comenzar con las técnicas de detección para generar un error de la aplicación. Al tratarse de un parámetro de texto, es seguro comenzar por agregar el caracter `'` para provocar un error de sintaxis. Esto ya resulta en un error HTTP 500 con un mensaje personalizado:

![Payload 2](/sqli-en-la-practica/assets/error_ex_2.png)

Lo que se debería verificar es que el error es efectivamente por interpretación de SQL y no por otro tipo de error de la propia aplicación. Para esto se puede fabricar una consulta de sintaxis válida más compleja que no de error, corroborando que el problema sea sintaxis de SQL específicamente. Algunos ejemplos de *payloads* para intentar extender el texto original por concatenación (se sobreentiende que existe una comilla simple al final que hay que contemplar):

```
yfjurW4iPlPPGgRH'+(SELECT '')+'
yfjurW4iPlPPGgRH'||(SELECT '')||'
yfjurW4iPlPPGgRH' (SELECT '') '
```

Todas ellas resultan en error cuando alguna sintaxis debería haber funcionado para el DBMS en cuestión. Sin embargo, si se tratara de Oracle se estaría obligado a incluir la cláusula `FROM`, por lo que se puede probar con la tabla `DUAL` como se explicó en la sección [Valores NULL de inyecciones clásicas](/sqli-en-la-practica/injection_types/classic#valores-null). Esto deja de provocar error, indicando sintaxis válida:

![Payload 3](/sqli-en-la-practica/assets/error_ex_3.png)

Para terminar de comprobar que el procesamiento se da a nivel de SQL en el DBMS, se puede incluir una tabla que no exista de forma que la consulta sea sintácticamente válida pero en el DBMS provoque un error por la referencia inexistente. Por ejemplo con `yfjurW4iPlPPGgRH'||(SELECT '' FROM no-existe)||'`.

Desde este punto es posible incluir condiciones complejas para Oracle que en un caso retornen un texto y en otro generen un error, por ejemplo con conversiones inválidas o división por 0:

```
...'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM DUAL)||'
```

Cambiando `1=1` por `1=2` no da error. Siempre que la condición se **evalúe como verdadera habrá error**. Para verificar la existencia de un registro particular, como un usuario con nombre `administrator`, aplica la siguiente consulta:

```sql
SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END 
    FROM users WHERE username='administrator'
```

Si el `WHERE` provoca el retorno de un registro, se aplica el `CASE`, generando un error porque la condición escrita es siempre verdadera. Si no hay registros, no se ejecuta el `CASE`. Esta es una buena base para las siguientes consultas, donde la condición va a cambiar por lo que se necesite averiguar, comenzando por ejemplo con el largo del campo `password` para ese usuario:

```sql
SELECT CASE WHEN LENGTH(password)=1 THEN TO_CHAR(1/0) ELSE '' END 
    FROM users WHERE username='administrator'
```

Aplicando este fragmento de SQL en el punto de inyección, el resultado será `200 OK` hasta que variando el número se coincida con el largo real para ese registro, generando `500 Internal Server Error`. Este proceso puede hacerse manualmente pero es más veloz con la herramienta **Fuzzer** de OWASP ZAP. Dado el siguiente pedido en *Requester*:

![Payload 4](/sqli-en-la-practica/assets/error_ex_4.png)

Seleccionando el texto "1" correspondiente al largo a adivinar en `LENGTH(password)=1` y haciendo click derecho, seleccionar la opción `Fuzz..`.

![Fuzzer 1](/sqli-en-la-practica/assets/error_ex_5.png)

Esta ventana permite agregar más de un punto de *fuzzing* para iterar sobre valores indicados en los *payloads* asociados. En este caso interesa probar números desde 1 en adelante hasta dar con el valor correcto. Haciendo click sobre la única "Fuzz Location" presente en al lista, tocar el botón `Payloads...`, en la nueva ventana hacer click sobre `Add...`. En la ventana resultante hay varias opciones tipo de *payload*, siendo la pertinente `Numberzz`, donde se puede seleccionar `From` 1, `To` 25 (por poner un tope) e `Increment` 1 (hasta puede generarse una vista previa de los *payloads*):

![Fuzzer 2](/sqli-en-la-practica/assets/error_ex_6.png)

Luego de confirmar todo, en la ventana principal hacer click en `Start Fuzzer`. Se abre en OWASP ZAP una nueva pestaña llamada `Fuzzer` con la ejecución de los 25 pedidos y detalles de los resultados. Ordenando por las columnas `Code` o `Reason` se observa que el único pedido con error está asociado al *payload* `20`:

![Fuzzer 3](/sqli-en-la-practica/assets/error_ex_7.png)

Conociendo el largo exacto de la contraseña la consulta puede evolucionar a adivinar los caracteres que la componen. Una consulta que aplica para obtener el primer caracter comparando con otro es:

```sql
SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END 
    FROM users WHERE username='administrator'
```

Adaptar esto al *payload* en *Requester* permite utilizar nuevamente la herramienta *Fuzzer* para probar todas las combinaciones de caracteres y posiciones del *substring* (de 1 a 20). La primera *Fuzz Location* es el primer número de `SUBSTR` con los *payloads* numéricos como ya se explicó. La segunda se agrega sobre la letra `a` del ejemplo. En este caso el *payload* puede ser de varios tipos dependiendo la practicidad pero se aprovecha la funcionalidad del tipo `Regex (*Experimental*)` para este ejemplo simple. Allí en el campo `Regex` con el valor `[ -~]` se genera todo el rango los caracteres ASCII desde el espacio hasta el `~`. Sin transformaciones extra esto daría problemas con `'`,`%` y `;` puesto que alteran el pedido HTTP o la sintaxis SQL. Otra opción que aplica a este laboratorio que usa contraseñas alfanuméricas es generar con `\w`:

![Fuzzer 4](/sqli-en-la-practica/assets/error_ex_8.png)

Iniciar el ataque con ambas posiciones y sus respectivos *payloads*. Para más velocidad se puede aumentar el número de hilos en la pestaña `Options` de *Fuzzer*. Nuevamente ordenando por código HTTP se observan las combinaciones de *payloads* válidos, revelando así la posición de cada caracter de la contraseña que debe ser ensamblada. Se puede exportar un CSV para pos-procesamiento.

![Fuzzer 5](/sqli-en-la-practica/assets/error_ex_9.png)
