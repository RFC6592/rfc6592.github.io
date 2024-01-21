---
layout: post
title: Pivoting - ProxyChains
subtitle: There's lots to learn!
tags: [CyberSec]
comments: true
---

## Overview Pivoting w/ ProxyChains

Le "pivoting" au travers d'un proxy est un exemple de mouvement latéral dans lequel un attaquant
tente de se déplacer de manière furtive et persistante à l'intérieur d'un réseau.

* **L'Attaquant Initial** : L'attaquant commence par compromettre un système externe au réseau cible, par exemple, un serveur web sur Internet.
* **Configuration de ProxyChains** : L'attaquant configure le système compromis pour utiliser ProxyChains. ProxyChains est un outil qui permet de rediriger le trafic réseau à travers des serveurs proxy. L'attaquant configure ProxyChains pour utiliser plusieurs serveurs proxy en série.
* **Passage par les Proxies** : Une fois ProxyChains configuré, tout le trafic réseau généré par l'attaquant sur le système compromis est acheminé à travers les serveurs proxy spécifiés dans ProxyChains. Ces serveurs proxy agissent comme des relais pour le trafic de l'attaquant.
* **Accès au Réseau Cible** : L'attaquant utilise le "pivoting" au travers de ProxyChains pour accéder aux systèmes du réseau cible. Le trafic passe d'abord par le serveur proxy externe, puis à travers chaque serveur proxy intermédiaire spécifié dans ProxyChains, et enfin atteint les systèmes du réseau cible.
* **Navigation Latérale** : Une fois que l'attaquant a accès au réseau cible, il peut entreprendre des actions telles que l'exploration du réseau, la recherche d'autres systèmes vulnérables, et la tentative d'escalade de privilèges.

## Walkthrough w/ ProxyChains

Nous pouvons également réaliser ce pivoting à l'aide des outils commme : **SSHutle**, **Chisel**. Cependant, nous allons nous concentrer sur uniquement ProxyChains pour le moment.<br/>

***Tout d'abord***, nous allons accèder à notre machine compromise (10.10.155.5) en SSH afin de lister nos interfaces. 
```
ssh -i pivot root@10.10.155.5
```

![Alt text](https://rfc6592.github.io/assets/img/interfaces-pivoting.png)

Nous sommes dans le réseau de la **machine compromise** avec comme adresse IP **10.10.155.5**. <br/>
Cependant, nous disposons d'une autre interface réseau sur cette machine avec l'adresse IP **10.10.10.5**.<br/> 
Que pouvons-nous faire pour accéder à ce réseau ?<br/>
-> Effectuer un "pivoting" à travers un proxy."<br/>

De ce fait, nous allons établir un pivot à travers cette machine pour pouvoir accéder au réseau *10.10.10.5/24*.<br/>
Pour ce faire, nous allons depuis notre **machine Kali** visualiser le fichier *proxychains4.conf*, qui est utilisé pour configurer les paramètres de ProxyChains :<br/>

```
cat /etc/proxychains4.conf
```

```
# defaults set to "tor"
socks4 127.0.0.1 9050
```

* **socks4** est le type de proxy à utiliser. Dans ce cas, il s'agit d'un serveur proxy de type SOCKS4.
* **127.0.0.1** est l'adresse IP du serveur proxy. Ici, il s'agit de l'adresse IP locale (localhost), c'est-à-dire que le serveur proxy est exécuté sur la même machine que l'application ProxyChains.
* **9050** est le numéro de port du serveur proxy. Dans ce cas, le serveur proxy SOCKS4 est configuré pour écouter sur le port 9050 de la machine locale.

Le port *9050* est celui auquel nous allons nous lier pour établir un 'pivot'.<br/> 

***Ensuite***, nous allons établir un tunnel SSH dynamique en arrière-plan (port 9050) en utilisant un fichier d'identité appelé "pivot".<br/>
Cela permettra de faire transiter le trafic réseau via la machine distante (adresse IP 10.10.155.5) sans exécuter de commandes sur cette machine.

```
ssh -f -N -D 9050 -i pivot root@10.10.155.5
```

* **-f**: Cette option signifie "en arrière-plan" (foreground). Cela indique que la commande SSH doit être exécutée en arrière-plan sans afficher les informations de journalisation sur le terminal.
* **-N**: Cette option signifie "ne pas exécuter de commandes distantes." Elle indique que la connexion SSH doit être établie, mais aucune commande distante ne doit être exécutée. C'est couramment utilisé pour établir des tunnels SSH sans exécuter des commandes sur le serveur distant.
* **-D 9050**: Cette option indique la création d'un tunnel SSH dynamique sur le port 9050 de la machine locale. Ce tunnel permettra de faire transiter le trafic réseau via la machine distante. Le port 9050 est le port local qui sera utilisé pour rediriger le trafic.
* **-i pivot**: Cette option spécifie le chemin vers un fichier d'identité à utiliser pour l'authentification. Dans cet exemple, le fichier d'identité s'appelle "pivot." Les fichiers d'identité sont généralement utilisés pour l'authentification SSH, et ils peuvent contenir des clés privées.
* **root@10.10.155.5**: C'est la destination de la connexion SSH. Dans cet exemple, la connexion est établie en tant qu'utilisateur "root" vers l'adresse IP "10.10.155.5."

![Alt text](https://rfc6592.github.io/assets/img/kali-pivot.png)

***En conclusion***, après avoir établi une connexion sur la machine Kali, nous pouvons maintenant faire transiter notre trafic à travers cette machine pour accéder au réseau suivant.

```md
proxychains nmap -p88 10.10.10.225

Or
# TCP connect scan, par opposition à l'exécution d'un scan SYN qui est la méthode par défaut, ne fonctionne parfois pas correctement via ProxyChains. 
proxychains nmap 10.10.10.225 -sT
```

## Source

* (Practical Network Penetration Tester (PNPT), 2023) https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course<br>