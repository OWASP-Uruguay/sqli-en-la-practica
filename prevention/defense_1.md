---
layout: default
title: Opción de defensa 1
permalink: /prevention/primary_defenses/defense_1/
parent: Defensas primarias
grand_parent: 5. Cómo prevenir las SQLi
nav_order: 1
---

# Opción de defensa 1: *Prepared statements* (con consultas parametrizadas)

El uso de *prepared statements* con variables asociadas (*variable binding*), también referido como *consultas parametrizadas*, es el método preferido para escribir sentencias SQL. Son simples de escribir y más fáciles de entender que las sentencias dinámicas tradicionales. Su esencia es **definir todo el código SQL** primero y **después asociar** cada parámetro variable. Este tipo de construcción permite a la base de datos **distinguir entre código** (estructura) **y datos** (valores) sin importar qué entradas proporcionó un usuario.

En el ejemplo que se menciona más abajo, si un atacante quisiera ingresar el parámetro `category` con el texto `Garden'--`, la consulta parametrizada no sería vulnerable. En su lugar se trataría de encontrar una categoría que **literalmente coincida** con el texto completo `Garden'--`.

## Recomendaciones para lenguajes específicos

- **Java** – usar `PreparedStatement()` asociando variables.
- **.NET** – usar métodos como `SqlCommand()` o `OleDbCommand()` con parámetros asociados a variables.
- **PHP** – usar PDO (*PHP Data Objects*) con consultas parametrizadas fuertemente tipadas (usando `bindParam()` o de forma implícita).
- **Hibernate** - usar `createQuery()` asociando variables (llamadas *named parameters* en Hibernate).
- **SQLite** - usar `sqlite3_prepare()` para crear un objeto de sentencia.

Es necesario aclarar que **la sintaxis de todos los ejemplos y recomendaciones puede variar** según la tecnología de la **aplicación** y de **motor de base de datos**.

Para ver más ejemplos de consultas parametrizadas en otros lenguajes, se sugiere ver [OWASP Query Parameterization Cheat Sheet][query-param-cheatsheet] o [Bobby Tables][bobby-tables].

## Ejemplo seguro en Java

```java
// Este parámetro debería ser validado de todas formas
String category = request.getParameter("category");
String query = "SELECT * FROM products WHERE category = ? AND released = 1";

PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, category);

ResultSet results = pstmt.executeQuery();
```

Notar el uso de la clase `PreparedStatement` indicando primero el contenido (`query`) y luego especificando el primer parámetro (`1`) con el valor dinámico de la variable `category`.

## Ejemplo seguro en C# (.NET)

```csharp
// Este parámetro debería ser validado de todas formas
string category = Request.QueryString["category"];
string query = "SELECT * FROM products WHERE category = @Category AND released = 1";

SqlCommand command = new SqlCommand(query, connection);
command.Parameters.Add(new SqlParameter("@Category", System.Data.SqlDbType.VarChar));
command.Parameters["@CustomerId"].Value = category;

using(SqlDataReader reader = command.ExecuteReader()) 
{
    // …
}
```

En este ejemplo los parámetros son por nombre y no se indica posición. Al crear el parámetro instanciando `SqlParameter` se indica el nombre y tipo de dato. Luego se especifica el valor.

## Ejemplo seguro en PHP

```php
// Este parámetro debería ser validado de todas formas
$category = $_GET["category"];
$query = 'SELECT * FROM products WHERE category = :category AND released = 1';

$sth = $dbh->prepare($query, [PDO::ATTR_CURSOR => PDO::CURSOR_FWDONLY]);
$sth->execute(['category' => $category]);
$results = $sth->fetchAll();
```

El parámetro por nombre y su valor se especifica sobre el *prepared statement*, directo en la invocación a `execute()`.

## Ejemplo seguro en Hibernate (HQL)

Uno de los propósitos o ventajas del uso de abstracciones de SQL, como sucede con los ORM (*Object Relational Mapping*) como Hibernate para Java, es evitar escribir consultas SQL directamente. Estos *frameworks* permiten crear objetos que se asocian a entidades en la base de datos y las operaciones que requerirían SQL son generadas internamente, transparente a la programación.

Sin embargo, se suelen proporcionar mecanismos para escribir SQL como con HQL (*Hibernate Query Language*) que tienen los mismos problemas de inyección. HQL particularmente soporta consultas parametrizadas para evitar SQLi:

```java
// Este parámetro debería ser validado de todas formas
String category = request.getParameter("category");
Query safeHQLQuery = session.createQuery("from Product where category=:category");
safeHQLQuery.setParameter("category", category);
```

[query-param-cheatsheet]: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
[bobby-tables]: https://bobby-tables.com/