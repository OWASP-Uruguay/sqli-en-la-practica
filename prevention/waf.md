---
layout: default
title: Web Application Firewall
permalink: /prevention/additional_defenses/waf/
parent: Defensas adicionales
grand_parent: 5. Cómo prevenir las SQLi
nav_order: 2
---

# Web Application Firewall

Un WAF (*Web Application Firewall*) es una herramienta de seguridad que **filtra**, **monitorea** y **bloquea** tráfico HTTP identificado como malicioso que viaja hacia una aplicación que se intenta proteger. También previene que información no autorizada "salga" de la aplicación en una respuesta. Para esto se definen políticas que determinan qué implica que el tráfico sea seguro o no, y aplican para muchos tipos de vulnerabilidad además de SQLi.

Esta protección es una barrera y hay otras herramientas de detección de intrusiones que pueden sumar. Es válido y recomendable su uso si el escenario y los recursos lo permiten, pero **NO ES UNA DEFENSA PRIMARIA**, es **complementaria**. Los problemas raíz de la aplicación no se solucionan con un WAF y continuamente se hacen públicas **técnicas de bypass** para WAF de distintas tecnologías y proveedores.

Para información inicial sobre técnicas de bypass de WAF: 
- [SQL Injection Bypassing WAF](https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF).
- [HackTricks - SQL Injection](https://book.hacktricks.xyz/pentesting-web/sql-injection#waf-bypass).