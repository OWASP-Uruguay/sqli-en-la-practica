---
layout: default
title: Ejercicio práctico
permalink: /injection_types/blind/conditional_type/conditional_exercise
nav_order: 1
parent: 4.1 Con respuestas condicionales
grand_parent: 4. Inyecciones ciegas
---

# Ejercicio práctico de inyección ciega con respuestas condicionales

> Ejercicio basado en el laboratorio "Lab: Blind SQL injection with conditional responses" de Web Security Academy (PortSwigger).

## Consigna

Este laboratorio contiene una vulnerabilidad de inyección de SQL ciega. La aplicación usa una cookie de rastreo (*tracking*) para análisis y ejecuta una consulta SQL con el valor de esta cookie.

Los datos de la consulta no se retornan y no se muestran mensajes de error. Pero la aplicación muestra el mensaje "Welcome back" si la consulta resulta en al menos una fila.

La base de datos contiene una tabla diferente llamada `users`, con columnas llamadas `username` y `password`.

Para resolver el laboratorio, obtener el usuario y contraseña del usuario `administrator` e iniciar sesión con estas credenciales.

## Resolución manual + Burp Suite

Luego de un primer acceso a la aplicación y por sugerencia de la consigna, analizando las cookies se observa que figura una llamada `TrackingId` con un valor alfanumérico. Para modificarla en pedidos siguientes es pertinente usar un proxy de ataque como Burp Suite para practicidad.

De la lista de la subpestaña "HTTP History" dentro de la pestaña "Proxy", seleccionar un pedido HTTP que incluya la cookie `TrackingId` y abrirlo en la herramienta "Repeater" con `Ctrl+R` o seleccionando la opción "Send to Repeater" del menú contextual con click derecho. Esto muestra el mismo pedido pero en modo de edición. Presionar en "Send" envía el pedido y la respuesta contiene el mensaje "Welcome back":

![Repeater](/sqli-en-la-practica/assets/conditional_ex_1.png)

Desde aquí hay que comenzar con las técnicas de detección para generar comportamientos diferentes en la aplicación. Al tratarse de un parámetro de texto, es seguro comenzar por agregar en `TrackingId` el caracter `'` y agregar condiciones simples que sean siempre verdaderas o falsas, por ejemplo:

```
TrackingId=kW4rLm6gbX2SikFr' AND '1'='1
TrackingId=kW4rLm6gbX2SikFr' AND '1'='2
```

Enviando los dos pedidos independientemente, se observa que "Welcome back" solo figura cuando la condición extra es `'1'='1'`. Con una sola condición booleana se puede inferir un resultado. Desde este punto se puede probar directamente con una condición sobre una consulta más completa que consulte datos como la siguiente sabiendo que existe el usuario `administrator`:

```
...' AND (SELECT 'a' FROM users WHERE username='administrator')='a
```

La presencia del registro hace que el `SELECT` decida retornar las columnas especificadas (la letra fija `a`). En caso contrario, se daría un error interno o no habrían resultados. Pero la consulta planteada sí devuelve el mensaje de bienvenida:

![Repeater](/sqli-en-la-practica/assets/conditional_ex_2.png)

Esta es una buena base para las siguientes consultas, donde la lista de condiciones es ampliable por lo que se necesite averiguar, comenzando por ejemplo con el largo del campo `password` para ese usuario:

```sql
SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)=1
```

Aplicando este fragmento de SQL en el punto de inyección, el resultado no tendrá el mensaje de bienvenida porque ya es poco probable que la contraseña sea tan reducida, pero variando el número eventualmente coincidirá con el largo real para ese registro, devolviendo el mensaje de bienvenida. Este proceso puede hacerse manualmente pero es más veloz con las herramienta **Intruder** o la extensión **Turbo Intruder** de Burp Suite. Como Burp Suite Community Edition provee ataques más lentos para **Intruder**, es preferible utilizar directamente **Turbo Intruder** o **Fuzzer** de OWASP ZAP (como se muestra en la solución del ejercicio de inyecciones ciegas basdas en error). Dado el siguiente pedido en *Repeater*:

![Repeater 2](/sqli-en-la-practica/assets/conditional_ex_3.png)

Seleccionando el texto “1” correspondiente al largo a adivinar en `LENGTH(password)=1`, hacer click derecho y luego en `Extensions > Turbo Intruder > Send to turbo intruder` (la extensión debe estar previamente instalada).

![Turbo Intruder](/sqli-en-la-practica/assets/conditional_ex_4.png)

Esta ventana muestra en la parte superior el pedido HTTP original y debajo un código Python que procesa el pedido base, lo modifica y lo agrega a una cola de pedidos que se envían automáticamente. Notar que donde había un "1" para el largo de contraseña **tiene que figurar el texto** `%s` porque es la posición de reemplazo que Python utiliza. Si está mal colocado por defecto, reubicarlo para que el *payload* sea:

```
...AND LENGTH(password=%s)='a...
```

De la lista desplegable que dice "Last code used" conviene seleccionar el código de ejemplo base `examples/basic.py`. Lo relevante a modificar es que en lugar de utilizarse un archivo de palabras (`'/usr/share/dict/words'`) simplemente se itere sobre número desde 1 hasta un tope (por ejemplo 25), cambiando el bloque `for` por:

```python
for i in range(1,26):
    engine.queue(target.req, str(i))
```

Esto reemplazará la versión en texto del número `i` desde 1 a 25. Luego en la definición de la función `handleResponse` se puede indicar que solo agregue la respuesta a la tabla de resultados si el mensaje "Welcome back" está presente:

```python
if 'Welcome back' in req.response:
    table.add(req)
```

Con el código final, presionar el botón "Attack" y ver el único resultado que cumple la condición (20 en este caso):

![Turbo Intruder 2](/sqli-en-la-practica/assets/conditional_ex_5.png)
![Turbo Intruder 3](/sqli-en-la-practica/assets/conditional_ex_6.png)

Conociendo el largo exacto de la contraseña la consulta puede evolucionar a adivinar los caracteres que la componen. Una consulta que aplica para obtener el primer caracter comparando con otro es:

```sql
(SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a'
```

Adaptar esto al *payload* en *Repeater* permite utilizar nuevamente la herramienta *Turbo Intruder* para probar todas las combinaciones de caracteres y posiciones del *substring* (de 1 a 20). Ahora las posiciones de reemplazo `%s` son dos, una en el primer número de `SUBSTRING` y la otra es sobre la letra `a` del ejemplo.

El código cambia ligeramente. Primero dentro de las varias formas de implementarlo, se declara una lista de los caracteres imprimibles transformando cada número de ASCII en su versión de caracter:

```python
printable_chars = [chr(i) for i in range(32,127)]
```

Luego se utiliza un `for` anidado para recorrer primero sobre las posiciones de la contraseña y segundo sobre cada caracter imprimible. El pedido modificado se agrega especificando una lista de dos elementos, el número y el caracter:

```python
for i in range(1,21):
    for c in printable_chars:
        engine.queue(target.req, [str(i), c])
```

Con esta modificación ya se puede ejecutar el ataque final:

![Turbo Intruder 4](/sqli-en-la-practica/assets/conditional_ex_7.png)
![Turbo Intruder 5](/sqli-en-la-practica/assets/conditional_ex_8.png)

De la tabla resultante se debe ensamblar la contraseña que en este ejemplo fue `6j32l89e7cftdilq86v0`.