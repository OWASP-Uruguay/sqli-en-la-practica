---
layout: default
title: Menor privilegio
permalink: /prevention/additional_defenses/least_privilege/
parent: Defensas adicionales
grand_parent: 5. Cómo prevenir las SQLi
nav_order: 1
---

# Menor privilegio

Para minimizar el daño de un ataque SQLi exitoso, se debería a su vez minimizar los privilegios asignados a **la cuenta en la base de datos que usa la aplicación** vulnerable. Algunos lineamientos generales:

- En lugar de asignar roles/permisos de DBA o administrador, lo ideal es comenzar con un usuario sin privilegios y asignarle de a poco lo que se planea que necesite.
- **Dar acceso de lectura o escritura solo a las tablas requeridas** para el funcionamiento. Incluso si se debe acceder a una porción de una tabla, podría considerarse la **creación de una vista** que represente tal sección de datos y asignar permisos directamente sobre la vista en lugar de a la tabla directamente.
- Usualmente las aplicaciones no precisan acceso a manipular la estructura de la base de datos, **solo a registros**.
- Si solo se permite a las aplicaciones invocar *stored procedures*, dar permisos para ejecutar solo los necesarios.
- Minimizar los privilegios de la cuenta del **sistema operativo** que usa el DBMS. No correr el DBMS como `root` o `SYSTEM`, algunos proveedores toman este camino en instalaciones por defecto y es necesario ajustarlo.
- Crear, configurar y asignar **un usuario de base de datos por aplicación** que se conecte. Permite segmentar los permisos y configurar accesos más granulares.

