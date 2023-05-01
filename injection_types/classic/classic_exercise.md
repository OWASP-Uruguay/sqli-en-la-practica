---
layout: default
title: Ejercicio práctico
permalink: /injection_types/classic/exercise
nav_order: 1
parent: 3. Inyecciones clásicas con datos visibles
---

# Ejercicio práctico de inyección clásica

> Ejercicio basado en el laboratorio "Lab: SQL injection UNION attack, retrieving data from other tables" de Web Security Academy (PortSwigger).

## Consigna

Este laboratorio contiene una vulnerabilidad de inyección de SQL en el filtro de categorías de productos. Los resultados de la consulta se retornan en la respuesta de la aplicación, por lo que podría usarse un ataque de `UNION` para obtener datos de otras tablas.

La base de datos contiene una tabla diferente llamada `users`, con columnas llamadas `username` y `password`.

Para resolver el laboratorio, se debe obtener el usuario y contraseña del usuario `administrator` e iniciar sesión con estas credenciales.

## Resolución manual

Al ingresar al laboratorio se muestra una página principal con una lista de textos y un área con botones para "refinar la búsqueda":

![Home page](/sqli-en-la-practica/assets/classic_ex_1.png)

Al hacer click en uno de los botones, por ejemplo "Pets", la página se recarga y la ruta en la URL cambia a `/filter?category=Pets`. Por la sugerencia de la consigna es conveniente probar inyectar en este parámetro de filtro `category` como se vio en las [técnicas de detección](/sqli-en-la-practica/detection). Agregar una comilla simple `'` al final de `Pets` resulta en un error del servidor:

![Internal Server Error](/sqli-en-la-practica/assets/classic_ex_2.png)

Asumiendo que este es el punto de inyección correcto, se toma la siguiente consulta potencial:

```sql
SELECT ... FROM ... WHERE category = 'Pets'
```

No se conoce nada sobre la tabla o las columnas. Para un ataque con `UNION` el siguiente paso es determinar la cantidad de columnas. Se utiliza la técnica de agregar valores nulos hasta dar con el número correcto. Comenzar con:

```
/filter?category=Pets' UNION SELECT NULL--
```

Resulta en el mismo error. Probando con: 

```
/filter?category=Pets' UNION SELECT NULL,NULL--
```

El resultado es otro:

![Nulls](/sqli-en-la-practica/assets/classic_ex_3.png)

Esto evidencia que el `SELECT` original tiene **dos columnas**. Además, como se tiene un "título" y un "cuerpo" por cada elemento de la lista resultante, se entiende que **ambas columnas son de tipo texto**. Finalmente se pueden sustituir los valores nulos por los nombres de las columnas y agregar el `FROM` para obtener todas las credenciales de los usuarios con los datos de la consigna:

```
/filter?category=Pets' UNION SELECT username,password FROM users--
```

En las filas resultantes figuran los productos junto con las credenciales por tener algún tipo de ordenamiento intermedio por la aplicación:

![Credentials](/sqli-en-la-practica/assets/classic_ex_4.png)

## Resolución con `sqlmap`

La herramienta `sqlmap` condensa variadas técnicas de ataque para SQLi contemplando distintas versiones de DBMSs, transformaciones de los *payloads*, heurísticas para tomar decisiones y más.

En este laboratorio, basta indicarle a `sqlmap` (por comando instalado o su *script* de Python) cual es la URL objetivo y el punto de inyección (parámetro). Una ejecución que lleva al mismo resultado sería la siguiente:

```bash
sqlmap -u "https://LAB-ID.web-security-academy.net/filter?category=Pets" \
    -p category -T users --ignore-code=500 --dump
```

Donde:
- `-u`, `--url`: La URL objetivo. Puede tener un `*` en el punto de inyección si se le quiere indicar explícitamente a `sqlmap` dónde probar.
- `-p`: Parámetros objetivo de punto de inyección. Si hay más de uno se separan por coma (`,`).
- `-T`: Indica las tablas objetivo si las hay. Si hay más de una se separan por coma (`,`).
- `--ignore-code`: Ignorar códigos HTTP problemáticos. En este ejemplo `sqlmap` cortaría la ejecución si detecta exceso de errores `500`.
- `--dump`: Extraer e imprimir los datos especificados. Para hacer una extracción de todo lo accesible, usar `--dump-all` (enfoque agresivo).

El siguiente es un fragmento de la salida del comando con la extracción de la tabla `users`:

![sqlmap](/sqli-en-la-practica/assets/classic_ex_5.png)
