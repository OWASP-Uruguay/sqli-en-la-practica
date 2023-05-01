---
layout: default
title: Opción de defensa 3
permalink: /prevention/primary_defenses/defense_3/
parent: Defensas primarias
grand_parent: 5. Cómo prevenir las SQLi
nav_order: 3
---

# Opción de defensa 3: Validación contra valores permitidos

**No todo elemento es reemplazable con consultas parametrizadas**. Las defensas anteriores no aplican a estos casos de posiciones "ilegales", como **nombres de tablas o columnas** y el **indicador de orden** (`ASC` o `DESC`) de la cláusula `ORDER BY`. En esta situación la defensa más apropiada es **validar** las entradas de usuario y/o **rediseño** de la sentencia SQL. 

Para nombres de tablas o columnas idealmente se usan valores fijos en el código, no desde parámetros de usuario. Aunque si estos deben ser variables, el parámetro debería ser **asociado a un nombre esperado** para que no se utilice directamente en el SQL final. Es recomendable reevaluar el diseño cuando esto sucede.

Ejemplo de validación de nombre de tabla:

```java
String tableName;
switch(unsafeUserParameter): // Proveniente de entrada de usuario
  case "clients": tableName = "table_clients";
                 break;
  case "sellers": tableName = "table_sellers";
                 break;
  ...
  default      : throw new InputValidationException("unexpected value provided"
                                                  + " for table name");
```
La variable `tableName` puede ser insertada directamente en una sentencia SQL, es considerada legal y esperada. Lo mismo aplica para nombres de columnas.

Para orden de los resultados, al tratarse de solo dos direcciones podría convertirse la entrada de usuario a un valor *boolean* (`true` o `false`). En base a esto se genera programáticamente el texto final para la cláusula `ORDER BY`. Por ejemplo:

```java
public String getProducts(boolean sortOrder) {
 String query = "SELECT * FROM products ORDER BY price " + (sortOrder ? "ASC" : "DESC");
 // ...
}
```

Es igual de importante **utilizar los tipos de datos apropiados**. Si una entrada de usuario puede ser convertida a datos como fecha, numérico, *boolean*, enumerado, etc., se sabe que el valor a insertar en la consulta es seguro por tener que **haber sido de un tipo diferente a texto**.

Validar las entradas **se recomienda siempre** como defensa secundaria (en profundidad), aunque se apliquen otras defensas. Para más información sobre aplicar validaciones, ver la [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html).