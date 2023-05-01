---
layout: default
title: 3. Inyecciones clásicas con datos visibles
permalink: /injection_types/classic
nav_order: 5
has_children: true
---

# Inyecciones clásicas con datos visibles

Existen muchas variantes donde afectar en un punto de inyección cambia los resultados, por ejemplo en un **nombre de columna o las condiciones** de la cláusula `WHERE`. Esto extrae datos no previstos por la aplicación dentro de la tabla de la consulta original.

Sin embargo, cuando se quiere obtener información en masa y de otras partes de la base de datos, hay técnicas efectivas que se adaptan. La predominante se da con ataques que utilizan el operador `UNION`.

## Introducción a ataques UNION

La palabra `UNION` permite ejecutar más de una consulta `SELECT` y ubicar el resultado de una después de la otra, en el orden que se hayan escrito. En el siguiente ejemplo genérico:

```sql
SELECT a, b FROM tabla1 UNION SELECT c, d FROM tabla2
```

Si `tabla1` es:

| a | b |
| :-: | :-: |
| 111 | aaa |
| 222 | bbb |

Y `tabla2` es:

| c | d |
| :-: | :-: |
| 333 | yyy |

La consulta retorna el conjunto:

| col1 | col2 |
| :-: | :-: |
| 111 | aaa |
| 222 | bbb |
| 333 | yyy |

Para que una consulta `UNION` funcione, las **dos condiciones que tienen que cumplirse son**:
1. El **número de columnas** de todas las uniones coincide.
2. Los **tipos de datos** de cada columna deben ser compatibles en la misma posición resultante.

Determinar el número de columnas y tipos de datos de cada una en la consulta SQL original es vital.

## Determinar número de columnas

### ORDER BY

Hay dos formas básicas de determinar el número de columnas de la consulta original. La primera es abusar de la cláusula `ORDER BY`. Si bien lo común es escribir el nombre de la columna por la cual ordenar, también se permite elegir un número de posición o índice. Por ejemplo, asumiendo la siguiente consulta vulnerable:

```sql
SELECT a, b FROM tabla1 WHERE b = 'INYECTABLE AQUÍ'
```

El *payload* `' ORDER BY 1--` se reflejaría así:

```sql
SELECT a, b FROM tabla1 WHERE b = 'XYZ' ORDER BY 1--'
```

La consulta no tiene errores de sintaxis. Así se puede continuar con el número 2, 3, etc. hasta que eventualmente surja un error por pasarse del índice máximo, como:

```
The ORDER BY position number 3 is out of range of the number of items in the select list.
```

Las reacciones de la aplicación pueden ser varias, pero deben indicar un cambio de comportamiento debido a un error. Luego de esto se puede escribir el `UNION` con la cantidad de columnas exactas.

### Valores NULL

La segunda forma es inyectar el `UNION` comenzando por una sola columna, con el valor `NULL`, e incrementar las columnas nulas hasta que ya no se detecten errores:

```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

Un ejemplo de error podría ser:

```
All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.
```

Esto funciona porque `NULL` es convertible a cualquier tipo de dato común. A tener en cuenta: en los DBMS populares esa sintaxis es viable, pero en el caso de Oracle se necesita referir a una tabla que viene con ese DBMS llamada `DUAL`:

```
' UNION SELECT NULL FROM DUAL--
```

## Determinar columnas con tipo de dato útil

El objetivo de SQLi con `UNION` es obtener datos, por lo general va a interesar que sean de tipo texto o *string*. Identificar la mayor cantidad de columnas de texto da flexibilidad para extraer y procesar los resultados. Sabiendo ya el número de columnas exactas, solo es necesario **probar con cualquier texto literal fijo** en cada columna y ver cuáles combinaciones arrojan error, por ejemplo:

```
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```

Si el tipo de dato no es compatible hay chances de que se genere un error como:

```
Conversion failed when converting the varchar value 'a' to data type int.
```

Esto es análogo para otros tipos de dato si fuera necesario aplicarlo.

## Acumular en una columna

¿Qué sucede si se necesita más de una columna para los datos que se intentan extraer pero la consulta no tiene suficientes columnas de ese tipo?

Suponiendo un escenario donde el `UNION` admite **una sola columna** de tipo texto, pero como atacante se quieren obtener al menos dos columnas, se pueden aplicar operaciones de concatenación (u otras transformaciones) **sobre una única columna**. El siguiente es un ejemplo en Oracle para concatenar las credenciales de un usuario:

```
' UNION SELECT username || '~' || password FROM users--
```

Esto devuelve **una columna** con el contenido de dos, separando con el caracter `~` para distinguir comienzo y fin de cada una. El operador `||` es la concatenación. Como referencia de operadores válidos (puede diferir en versiones):

| Oracle, PostgreSQL | `'foo'||'bar'` |
| SQL Server | `'foo'+'bar'` |
| MySQL | `'foo' 'bar'` [Con espacio] <br> `CONCAT('foo','bar')` |
