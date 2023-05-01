---
layout: default
title: 1. Introducción
permalink: /intro/
nav_order: 3
---

# Introducción

## ¿Qué es una inyección SQL (SQLi)?

La inyección SQL (*SQL injection*, **SQLi**) es una vulnerabilidad que permite a un atacante interferir con las sentencias que una aplicación ejecuta al interactuar con su base de datos, asumiendo que éstas son generadas con el lenguaje de consulta SQL. 

Las fallas de SQLi se introducen cuando los desarrolladores crean consultas a la base de datos de forma dinámica con concatenaciones de *strings*, o transformaciones similares, que incluyen datos provenientes de un usuario de la aplicación.

## Impacto

Generalmente, una SQLi permite al atacante **visualizar datos** a los que normalmente no tendría acceso, tales como datos de otros usuarios o internos de la aplicación en sí misma. Usualmente también es posible **modificar o eliminar** estos registros.

Transformando esto en impacto, un atacante puede causar cambios persistentes en el **contenido o comportamiento** de la aplicación. También acceder a **información confidencial** para llevar a cabo otros ataques más complejos o hacerla pública con fines comerciales o daños de reputación/imagen. Dependiendo de la explotabilidad, sería posible escalar un ataque de SQLi para **comprometer el servidor** de base de datos e infraestructura adyacente, o ejecutar ataques de **denegación de servicio**.

## Ejemplo de flujo básico

Se plantea una funcionalidad de filtro de un catálogo de productos por categorías. Si el usuario aplica el filtro para listar productos de jardín, el navegador consulta a la siguiente URL:

```
https://insecure-website.com/products?category=Garden
```

Esto posiblemente resulte en la siguiente consulta SQL generada por la aplicación:

```sql
SELECT * FROM products WHERE category = 'Garden' AND released = 1
```

Esta consulta pide a la base de datos:
- Todos los campos/columnas (`*`).
- de la tabla `products` (`FROM products`).
- donde la categoría es `Garden` (`WHERE category = 'Garden'`),
- y los productos están liberados/habilitados para ser listados (`AND released = 1`).

Este último dato **no es visible ni evidente**. Un atacante podría intuir que la consulta tiene más parámetros de filtro e intentar abusar de eso, por sentido común o conocimiento del negocio y la plataforma. Un valor asociado a producto no liberado sería `released = 0`.

El siguiente es un ejemplo de cómo la consulta SQL anterior podría ser construida de forma insegura (en Java):

```java
String query = "SELECT * FROM products WHERE category = '"
             + request.getParameter("category")
             + "' AND released = 1";
try {
    Statement statement = connection.createStatement();
    ResultSet results = statement.executeQuery(query);
}
...
```

¿Por qué esta implementación es insegura? El parámetro `category` es obtenido directamente del *request* (o pedido HTTP) y, sin ningún tratamiento previo, es insertado **en la estructura** de la consulta. Esto permite que un usuario pueda alterar la consulta a partir del **punto de inyección** (valor de categoría) y afectar desde allí en adelante. En otras palabras, el motor de base de datos que interpreta la consulta tomará una estructura manipulada y retornará a la aplicación (y luego al usuario) información que no era la inicialmente esperada.

Basándose en la implementación de ejemplo, un atacante podría acceder a la siguiente URL:

```
https://insecure-website.com/products?category=Garden'--
```

Que resulta en la consulta SQL:

```sql
SELECT * FROM products WHERE category = 'Garden'--' AND released = 1
```

Aquí se abusa de la sintaxis de SQL, aplicando luego de `Garden` una comilla simple (`'`) que **cierra la comilla inicial**, generando hasta ese punto una consulta sintácticamente válida. Si bien el resto de la consulta podría ser adaptada para lograr el mismo resultado, se opta por usar un **comentario de SQL** (`--` en este caso) que permite **ignorar** todo lo que haya desde ese punto en adelante. Consecuentemente, la consulta final **interpretada** retorna todos los productos de jardín independientemente de su estado de habilitación (`released`):

```sql
SELECT * FROM products WHERE category = 'Garden'
```

Esta es la base de la que derivan todos los tipos de inyección, que varían según la **posición** del punto de inyección, **validaciones** aplicadas, la **tecnología** del motor de base de datos y demás factores. Los métodos de prevención se describen en la sección [Cómo prevenir las SQLi](/sqli-en-la-practica/prevention).

**Nota**: Los comentarios de SQL varían según el motor de base de datos, algunas opciones son:

| Oracle | `--comentario` |
| SQL Server | `--comentario` <br> `/*comentario*/` |
| PostgreSQL | `--comentario` <br> `/*comentario*/` |
| MySQL | `#comentario` <br> `-- comentario` [Con espacio] <br> `/*comentario*/` <br> |
