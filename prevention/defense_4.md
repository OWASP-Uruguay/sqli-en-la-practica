---
layout: default
title: Opción de defensa 4
permalink: /prevention/primary_defenses/defense_4/
parent: Defensas primarias
grand_parent: 5. Cómo prevenir las SQLi
nav_order: 4
---

# Opción de defensa 4: Escapar todas las entradas de usuario
  
Esta técnica debe ser considerada como **último recurso** después de haber intentado otras defensas como la validación de entradas, ya que **puede ser frágil y no garantiza la prevención** de todas las SQLi. La técnica de escape de caracteres funciona escapando toda la entrada suministrada por el usuario utilizando el esquema de escape adecuado para la base de datos utilizada.

El escape puede ser **manual o con la ayuda de bibliotecas**. [OWASP Enterprise Security API (ESAPI)](https://owasp.org/www-project-enterprise-security-api/) es un ejemplo de biblioteca multipropósito para validaciones y sanitizaciones. La versión principal es para Java, existen proyectos ya no mantenidos para otros lenguajes. En este momento, ESAPI tiene codificadores de base de datos para Oracle y MySQL.

## Detalles específicos de escapado

A continuación se detallan algunos ejemplos de escapado en distintos escenarios para Oracle y MySQL, algunos son extrapolables a otros DBMS. Para más detalles sobre técnicas de escapado ver [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) y sus referencias.

### Escape en Oracle

#### Escapar consultas dinámicas 

Como ejemplo de uso de un *encoder* de ESAPI, para Oracle es algo así:

```java
ESAPI.encoder().encodeForSQL(new OracleCodec(),  unsafeParameter);
```

Aplicado a una consulta dinámica con variables de este estilo:

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
Se reescribiría de la siguiente manera:

```java
Codec ORACLE_CODEC = new OracleCodec();
String query = "SELECT * FROM products WHERE category = '"
             + ESAPI.encoder().encodeForSQL(ORACLE_CODEC, request.getParameter("category"))
             + "' AND released = 1";
try {
    Statement statement = connection.createStatement();
    ResultSet results = statement.executeQuery(query);
}
...
```

Caracteres sensibles para la estructura de la consulta serán escapados para el parámetro `category` y considerados como literales.

Esta información es basada en [Oracle Escape character information](http://www.orafaq.com/wiki/SQL_FAQ#How_does_one_escape_special_characters_when_writing_SQL_queries.3F).

#### Escapar caracteres *wildcard* en cláusulas `LIKE`

La palabra clave `LIKE` permite realizar búsquedas de exploración de texto. En Oracle, el carácter `_` sólo coincide con un carácter, mientras que `%` se utiliza para coincidir con cero o más apariciones de cualquier carácter. Estos caracteres deben escaparse en la cláusula `LIKE`.

Por ejemplo:

```sql
SELECT name FROM product WHERE category LIKE '%/_%' ESCAPE '/'; 
SELECT name FROM product WHERE category LIKE '%\%%' ESCAPE '\';
```

### Escape en MYSQL

Existen dos modos específicos para realizar esto:

1. `ANSI_QUOTES SQL`: Escapar todos los caracteres `'`, con `''`.
2. `MySQL Mode` que hace lo siguiente:

    ```
    NUL (0x00) --> \0
    BS  (0x08) --> \b
    TAB (0x09) --> \t
    LF  (0x0a) --> \n
    CR  (0x0d) --> \r
    SUB (0x1a) --> \Z
    "   (0x22) --> \"
    %   (0x25) --> \%
    '   (0x27) --> \'
    \   (0x5c) --> \\
    _   (0x5f) --> \_

    todos los demás caracteres no alfanuméricos con valores ASCII
    inferior a 256 --> \c donde 'c' es el carácter no alfanumérico original.
    ```

Los modos se establecen al ejecutar el servicio o con comandos en tiempo de ejecución, esencialmente **cambian la forma de interpretar** ciertos caracteres especiales. 

Esta información esta basada en [MySQL Escape character information](https://dev.mysql.com/doc/refman/5.7/en/string-literals.html).

## Codificar toda la entrada en hexadecimal 

Un mecanismo genérico es el escape por codificación de la entrada del usuario a caracteres hexadecimales. Esta transformación debe ser producida por la aplicación antes de incluirla en la sentencia SQL, la cual debe tener esto en cuenta en su diseño.

Por ejemplo, si se quiere buscar un producto que su categoría coincida con `'Garden'`, la aplicación primero debe codificar el texto a su representación hexadecimal y luego insertarlo en el texto de la consulta. Esto se vería así:

```sql
SELECT * FROM products WHERE hex_encode(category) = '47617264656E'
```

Donde `'47617264656E'` es el texto provisto por el usuario, insertado dinámicamente, por ejemplo con una variable por parámetro. La función `hex_encode` debe sustituirse por la sintaxis particular del DBMS en cuestión. 

Si un atacante intentara inyectar con la típica comilla simple `'` y un espacio, el SQL final se vería:

```sql
SELECT * FROM products WHERE hex_encode(category) = '2720...'
```

`27` es el código ASCII (en hexadecimal) de la comilla simple y `20` el del espacio en blanco. Como la transformación solo genera dígitos numéricos y letras de la A a la F, ningún caracter especial puede causar la inyección.
