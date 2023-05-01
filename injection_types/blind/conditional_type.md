---
layout: default
title: 4.1 Con respuestas condicionales
permalink: /injection_types/blind/conditional_type
nav_order: 1
parent: 4. Inyecciones ciegas
has_children: true
---

# Inyecciones ciegas con respuestas condicionales

Esta explotación se puede llevar a cabo cuando la aplicación tiene un **cambio de comportamiento** posible de apreciar en el momento en que la consulta realizada **retorna un dato**.

Se presenta el siguiente escenario: una aplicación usa una cookie para identificar usuarios.

```
Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4
```

Cuando la cookie está presente, la aplicación ejecuta la siguiente consulta que se asumirá inyectable en el valor de `TrackingId`:

```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
```

**Si hay resultados**, la aplicación presenta un mensaje de bienvenida. Si no los hay, no hay mensaje. Partiendo de este comportamiento se puede recuperar información activando diferentes respuestas condicionalmente.

Enviando estos valores en `TrackingId` en dos consultas separadas:

```
…Tj4' AND '1'='1 
…Tj4' AND '1'='2
```

En la primera, si se usa un `TrackingId` válido al inicio, se debería observar el cambio en la aplicación ya que **la consulta es verdadera**. Mientras que la segunda no retorna ningún dato **por forzar que sea falsa la condición completa**, por ende no se apreciaría el mensaje de bienvenida. 

Suponiendo entonces que existe una tabla de usuarios con las columnas `username` y `password`, se quiere conocer la contraseña de alguno de ellos, sabiendo de antemano un `username`. Se puede determinar su contraseña con una serie de consultas **para verificar un caracter a la vez**:

```
…Tj4' AND SUBSTRING(
    (SELECT Password FROM Users WHERE Username = 'Jhon'), 1, 1) = 's
```

Esta consulta retorna verdadero **si el primer caracter** de la contraseña del usuario `Jhon` es `'s'`, causando así que, se aprecie el mensaje de bienvenida.

Sería cuestión de **automatizar las consultas** para probar las **diferentes combinaciones** hasta determinar la contraseña del usuario. Para automatizar este tipo de consultas es útil **identificar la cantidad de caracteres** que tiene el *string* objetivo (en este caso la contraseña), por ejemplo con la siguiente consulta base:

```
…Tj4' AND LENGTH(
    (SELECT Password FROM Users WHERE Username = 'Jhon')) > 8
```

Si la consulta es falsa, no deberíamos apreciar un cambio (mensaje de bienvenida en nuestro ejemplo). La idea es **variar el largo consultado hasta llegar al número exacto** de caracteres de la contraseña.

## Optimizaciones

Si bien el procedimiento anterior funciona, requiere probar **con todos los catacteres imprimibles** hasta dar con el indicado. Programar el ataque implica tener la lista de caracteres escrita en una lista, que suele ser engorroso. Las optimizaciones que se plantean a continuación aplican para todos los tipos de inyecciones que requieren adivinar caracteres.

### ASCII

La codificación ASCII asocia ciertos números a los caracteres que soporta. En total hay 95 que son imprimibles. En notación decimal van del `32` al `126`, en hexadecimal del `20` al `7E`. Estos rangos son fácilmente utilizados en un `for` o `while` si se programa un script de ataque, o con herramientas auxiliares.

¿Cómo aplica al ejemplo anterior? Si con el siguiente fragmento de SQL se obtiene el primer caracter de la contraseña para John:

```sql
SUBSTRING((SELECT Password FROM Users WHERE Username = 'Jhon'), 1, 1)
```

Basta con **transformar el resultado** (caracter) a su representación decimal correspondiente de ASCII (número). En general la sintaxis es aplicando la función `ASCII()`:

```sql
ASCII(SUBSTRING((SELECT Password FROM Users WHERE Username = 'Jhon'), 1, 1))
```

Finalmente la comparación en la condición pasa a ser de comparar por ejemplo, el caracter `'s'` a el número `115`.

### Binario

ASCII ya facilita. Pero aún así en el peor de los casos **si se itera secuencial** el rango desde 32 a 126, se harían demasiados pedidos si los caracteres a adivinar están más al final que al principio del rango (como una contraseña con muchas `'z'`, ASCII `122`). Hay formas de optimizar teniendo un rango numérico, pero una implementación más interesante es el uso de **la representación en binario del número**.

Si se toma una letra, luego se obtiene un número, y finalmente un *string* binario, la consulta **pasa a ser si cada uno de los 8 dígitos es 0 o 1**. Como son dos valores, preguntar si es `0` por ejemplo ya es suficiente, si la consulta da verdadero es `0`, sino es `1`. Por lo tanto **con 8 consultas fijas** se puede adivinar el caracter con total certeza. En general esto va a reducir la cantidad total de consultas, un ataque acelerado.

Obtener el binario de un número varía entre los DBMS, no es una sintaxis única. En MySQL es con la función `BIN()`, en PostgreSQL con el *cast* `::bit(8)`, por poner algunos ejemplos. Aplicado a los ejemplos anteriores, con el siguiente fragmento SQL se obtiene el binario del ASCII para la primera letra de la contraseña de John:

```sql
BIN(ASCII(SUBSTRING((SELECT Password FROM Users WHERE Username = 'Jhon'), 1, 1)))
```

Si fuera la letra `'s'`, el resultado sería `01110011`. Con la ayuda de `SUBSTRING` se puede extraer cada número, de a una consulta a la vez, y preguntar si es `'0'` o `'1'`.

Para más información y variantes:
- [ExploitDB - Faster Blind MySQL Injection Using Bit Shifting](https://www.exploit-db.com/papers/17073).
- [Ender's Blogs - Blind MySQL Injection Using Bit Shifting](https://enderspub.kubertu.com/blind-mysql-injection-using-bit-shifting).