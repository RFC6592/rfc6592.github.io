---
layout: post
title: Golden Ticket Attack
subtitle: There's lots to learn!
tags: [CyberSec]
comments: true
---

## Introduction

L'attaque par ticket d'or intervient dans TGS-REQ (*Ticket-Granting Service Request*). Le TGT (*Ticket Granting Ticket*) est chiffré à l'aide du hash KRBTGT.<br/>

Lorsqu'un utilisateur se connecte à un système dans le domaine, les données de pré-authentification, qui consistent en l'horodatage chiffré avec le **hash mdp** (*hachage du mot de passe*) du compte utilisateur, sont envoyées au KDC (Centre de Distribution de Clés).<br/>

Le KDC (*Key Distribution Center*) lit le **nom d'utilisateur** et obtient le **hash mdp** (*hachage du mot de passe*) à partir de la base de données du gestionnaire de compte dans le contrôleur de domaine.<br/>

Le KDC (*Key Distribution Center*) le déchiffre et émet le ticket de service avec les mêmes membres de groupe et les mêmes informations de validation que ceux trouvés dans le TGT. Ainsi, si vous avez le **hachage KRBTGT**, vous pouvez forger votre propre TGT qui inclut les données PAC avec n'importe quelle appartenance de groupe que vous voulez, y compris les administrateurs de domaine. En envoyant cela au KDC, vous obtiendrez **un ticket de service avec une appartenance de groupe d'administrateur de domaine à l'intérieur**.


![Alt text](https://rfc6592.github.io/assets/img/visiogoldenticket.png)

## L'attaque

Tout d'abord, nous allons lancer *mimikatz.exe*. Puis utiliser une commande spécifique de Mimikatz qui permet de manipuler les données du service d'autorité de sécurité locale (LSA) sur un système Windows. Le service LSA est responsable de la gestion des informations d'authentification, notamment les mots de passe des utilisateurs.

```md
lsadump::lsa /inject /name:krbtgt
```

• ```/inject``` : Permet d'injecter du code dans le processus *LSA*.<br/>
• ```/name:krbtgt ``` : Spécifie le nom du compte d'utilisateur que Mimikatz doit cibler. "krbtgt" est le nom d'utilisateur qui stocke les clés de chiffrement des tickets kerberos.<br/>

Les informations qui vont nous intéresser sont le *Hash NTLM*, *Domain SID* (S-1-18-1...), *User*. Ensuite, nous allons utiliser une commande pour générer notre ticket 'Golden Ticket'.

```md
kerberos::golden /user:<AnyUsername> /domain:TST.grp /sid:<DomainSID> /krbtgt:<TGT-NTLM-Hash> /id:<500>
```
Ce ticket d'or (Golden Ticket) va nous donner un accès complet et persistant au réseau. Enfin, nous utiliserons ensuite ce ticket d'or (Golden Ticket) pour accéder à d'autres machines. Cependant, vous devez avoir un accès RDP afin de visualiser le 'command prompt'.

```
misc::cmd
```

## Sources

* (ManageEngine, 2023) https://www.manageengine.com/log-management/cyber-security/golden-ticket-attack.html<br/>
* (AdSecurity, 2023) https://adsecurity.org/?p=1515<br/>
* (Practical Network Penetration Tester (PNPT), 2023) https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course<br>
