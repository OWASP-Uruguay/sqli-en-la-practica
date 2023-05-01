---
layout: default
title: Opción de defensa 2
permalink: /prevention/primary_defenses/defense_2/
parent: Defensas primarias
grand_parent: 5. Cómo prevenir las SQLi
nav_order: 2
---

# Opción de defensa 2: Procedimientos almacenados

Los procedimientos almacenados (*stored procedures*) son código guardado en la base de datos que pueden verse como funciones reutilizables y de acceso rápido por el motor de base de datos.

En general utilizarlos, cuando el caso de uso lo permite, ya es una buena forma de parametrizar los valores de las sentencias SQL. Sin embargo, si fueron programados de forma insegura con ejecución dinámica de SQL el problema seguirá allí. Por ejemplo, este es un *stored procedure* vulnerable:

```sql
CREATE PROCEDURE sp_getProductByCategory 
    @category VARCHAR(50)
AS
BEGIN
    SET NOCOUNT ON;
    
    DECLARE @query NVARCHAR(MAX);
    SET @query = 'SELECT * FROM products WHERE category = ''' + @category + ''' AND released = 1';
    EXECUTE sp_executesql @query;
END
```

Al crear una consulta internamente con un valor dinámico que **afecta a la estructura** (es parte del texto *crudo* de la consulta), la situación es la misma que invocando SQL por programación. El *stored procedure* podría verse así con el parámetro como valor y no como parte de la estructura de la sentencia:

```sql
CREATE PROCEDURE sp_getProductByCategory 
    @category VARCHAR(50)
AS
BEGIN
    SET NOCOUNT ON;
    
    SELECT * FROM products WHERE category = @category AND released = 1;
END
```

Aquí el motor de base de datos interpreta la consulta **con su estructura predefinida**. El valor por parámetro `@category` se utiliza de forma literal en la comparación.

Asumiendo que la implementación del *stored procedure* es segura, a continuación se muestran invocaciones en algunos lenguajes que siguen ese lineamiento.

## Ejemplo seguro en Java

```java
// Este parámetro debería ser validado de todas formas
String category = request.getParameter("category");
try {
  CallableStatement cs = connection.prepareCall("{call sp_getProductByCategory(?)}");
  cs.setString(1, category);
  ResultSet results = cs.executeQuery();
  // Manejo de resultados
} catch (SQLException se) {
  // Manejo de errores
}
```

## Ejemplo seguro en C# (.NET)

```csharp
// Este parámetro debería ser validado de todas formas
string custname = request.QueryString["category"];
try {
    using (SqlConnection conn = new SqlConnection(connectionString)) {
        conn.Open();
        using (SqlCommand cmd = new SqlCommand("sp_getProductByCategory", conn)) {
            cmd.CommandType = CommandType.StoredProcedure;
            cmd.Parameters.Add(new SqlParameter("@category", SqlDbType.NVarChar)).Value = custname;
            using (SqlDataReader reader = cmd.ExecuteReader()) {
                // Manejo de resultados
            }
        }
    }
} catch (SqlException ex) {
    // Manejo de errores
}
```