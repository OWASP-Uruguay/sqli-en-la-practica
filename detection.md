---
layout: default
title: 2. Detección
permalink: /detection/
nav_order: 4
---

# Detección

## ¿Cómo detectar una inyección?

A pesar de poder ejecutar herramientas automatizadas en toda la aplicación, este enfoque suele tomar mucho tiempo dependiendo de la superficie de ataque (cantidad de *endpoints*, parámetros, cookies, otros cabezales HTTP). Un enfoque manual y más preciso, es útil para detectar alguna señal que dé lugar a más pruebas manuales o automatizarlas centradas en potenciales puntos de inyección.

Estas son algunas técnicas de detección manual, que implican enviar a la aplicación:
- Los distintos caracteres de **comillas** ya sean la **comilla simple** (`'`) o **comillas dobles** (`"`) en busca de errores o cambios de comportamiento.
- **Condiciones lógicas** como `OR 1=1` y `OR 1=2` buscando diferencias en las respuestas.
- Contenido con sintaxis SQL que resulte en **demoras** controladas (ver el punto de inyecciones ciegas).
- Contenido diseñado para disparar **interacciones de red** fuera de banda (*out-of-band*), que son ejecutadas dentro de la consulta SQL, que pueden ser monitoreadas con un servicio que está alerta en caso de recibir tal pedido de interacción. Implica tener infraestructura preparada (ver el punto de inyecciones ciegas).

Si se tiene acceso al código fuente, además de poder revisarlo manualmente, existen herramientas de **análisis estático** que ayudan a identificar potenciales inyecciones y que suelen automatizarse como parte de procesos de integración continua.

## Puntos de inyección

El escenario clásico de SQLi es en la cláusula `WHERE` de una sentencia `SELECT`, aunque pueden ocurrir en cualquier otra parte y con los otros tipos de sentencias. Las ubicaciones más comunes son:
- `UPDATE`: en los valores actualizados o la cláusula `WHERE`.
-  `INSERT`: en los valores insertados.
-  `SELECT`:
   -  en los nombres de tabla o columnas.
   -  en la cláusula `ORDER BY`, en las columnas a ordenar o la dirección (`ASC`/`DESC`).

## Detectar tecnologías

Para explotar con suficiente conocimiento una SQLi, se busca aprender sobre la tecnología detrás, el manejador de base de datos o **DBMS** (*Database Management System*), **su versión** y cualquier otra información relevante.

Este conocimiento determina la sintaxis válida para consultas más complejas y **técnicas de bypass** específicas al DBMS.

Suponiendo que se encontró un punto de inyección del que extraer datos con una consulta totalmente controlable, es viable probar obtener una versión con las siguientes sentencias:

| DBMS | Query |
| ---- | ----- |
| SQLServer, MySQL | `SELECT @@version` |
| Oracle | `SELECT version FROM v$instance` <br> `SELECT banner FROM v$version` |
| PostgreSQL | `SELECT version()` |

En ejemplos posteriores se verá como el tipo de DBMS impacta en la sintaxis de las explotaciones.

En ocasiones **la propia estructura de la base de datos** informa sobre el tipo de DBMS. Una consulta como:

```sql
SELECT * FROM information_schema.tables
```

Podría revelar nombres de tablas como `pg_catalog.pg_attribute` que corresponden a PostgreSQL.
