---
layout: post
title: LLMNR & NBT-NS Poisoning
subtitle: There's lots to learn!
tags: [CyberSec]
comments: true
---

## Introduction

La résolution de noms (désormais abrégée en NR) est une série de procédures menées
par une machine pour retrouver l'adresse IP d'un hôte par son nom d'hôte. Sur les
machines Windows, la procédure sera en gros la suivante :<br>
1) L'adresse IP du nom d'hôte du partage de fichiers est requise.<br>
2) Le fichier d'hôte local est vérifié pour trouver des enregistrements appropriés.<br>
3) Si aucun enregistrement n'a été trouvé, la machine passe au cache DNS 62local, qui
archive les noms récemment résolus.<br>
4) Aucun enregistrement DNS local trouvé ? Une requête est envoyée au serveur DNS
configuré.<br>
5) Si tout le reste échoue, la machine envoie une requête multicast, demandant aux
autres machines du réseau l'adresse IP du partage de fichiers.<br>

Comme on peut le voir, la dernière solution de repli lors de la résolution de l'adresse
IP d'un nom d'hôte est l'utilisation de « NR multicast ». Ceci est géré par trois
protocoles principaux : **NBT-NS** (NetBIOS Name Service), **LLMNR** (Link-Local
Multicast Name Resolution) et **mDNS** (multicast DNS).
Les trois protocoles sont utilisés de manière adjacente pour deux raisons principales :
le support de l'héritage et la compatibilité. **NBT-NS** a été créé au début des années 80
et est quelque peu inadapté aux normes actuelles. Alors que le protocole tombait en
désuétude, les machines Windows ont commencé à mettre en œuvre le successeur de
NBT-NS, LLMNR (tout en continuant à supporter NBT-NS pour la communication
avec les anciennes machines). D'autre part, la plupart des machines basées sur Linux
ont mis en œuvre mDNS à la place. Finalement, avec la sortie de Windows 10,
Microsoft a ajouté la prise en charge de mDNS pour améliorer la compatibilité globale.


## Voyons ces protocoles en action

Sur une machine Windows 10, nous avons fait une erreur de frappe dans le nom d'un
dossier partagé **(\\\filesahr au lieu de \\\fileshare)**, ce qui entraîne une série de requêtes
NBT-NS et LLMNR. Remarquez que toutes les requêtes sont envoyées aux adresses de
multidiffusion désignées.

![Alt text](https://rfc6592.github.io/assets/img/llmnrpois.PNG)


## Pourquoi est-ce un problème ?

**NBT-NS**, **LLMNR** et **mDNS** diffusent une requête à l'ensemble de l'intranet, mais
aucune mesure n'est prise pour vérifier l'intégrité des réponses. Les attaquants peuvent
exploiter ce mécanisme en écoutant ces requêtes et en usurpant les réponses, incitant
ainsi la victime à faire confiance à des serveurs malveillants. Cette confiance sera
généralement utilisée pour voler des informations d'identification.
De plus, un certain nombre d'outils ont été développés pour automatiser cette
procédure, ce qui fait de cette attaque un jeu d'enfant qui peut être exécuté en un rien
de temps. Pour cet article, nous avons utilisé Responder, basé sur Python, sur une
machine Kali Linux.

## Cas d'abus courants
Il existe de nombreuses occasions dans lesquelles une machine aura recours à la
multidiffusion NR :

• **Erreur de frappe** - si un utilisateur fait une erreur de frappe sur le nom d'un
hôte légitime, aucun enregistrement d'hôte pertinent ne sera trouvé et la
machine aura recours au NR multidiffusion. Il s'agit d'un cas d'utilisation plutôt
faible, car l'attaquant devra attendre une erreur du côté de la victime.<br>
• **Mauvaise configuration** - une mauvaise configuration, que ce soit du côté
du serveur DNS ou du client, peut entraîner des problèmes de NR et obliger le
client à s'appuyer sur des requêtes de noms multicast.<br>
• **Protocole WPAD** - si un navigateur Web est configuré pour détecter
automatiquement les paramètres du proxy, il utilisera le protocole WPAD pour découvrir l'URL d'un fichier de configuration du proxy. Pour découvrir cette URL, WPAD passera en revue une série d'URL et de noms d'hôtes potentiels et s'exposera à l'usurpation à chaque fausse tentative. Google Chrome et Firefox ne déclenchent pas ce comportement par défaut, mais Internet Explorer le fait.<br>
• **Google Chrome** - lorsqu'une chaîne d'un seul mot est tapée dans la barre de
recherche de Chrome, l'application doit pouvoir discerner si la chaîne est une
URL ou un terme de recherche. Chrome traite d'abord la chaîne comme un
terme de recherche et dirige l'utilisateur vers son moteur configuré, tout en
s'assurant simultanément que la chaîne n'est pas un nom d'hôte en essayant de
le résoudre. En outre, pour éviter toute exposition au détournement de DNS,
Chrome essaiera de résoudre plusieurs noms d'hôtes aléatoires au démarrage
pour s'assurer qu'ils ne sont pas résolus - ce qui garantit essentiellement une
certaine action de NR multicast.

## Poisoning avec Responder

Responder est un empoisonneur *LLMNR/NBT-NS/mDNS* open-source basé sur
python qui agit en deux étapes comme décrit ci-dessus :
Tout d'abord, il écoutera les requêtes multicast NR (*LLMNR - UDP/5355, NBT-NS-UDP/137*) et, dans les bonnes conditions, usurpera une réponse - dirigeant la victime vers la machine sur laquelle il est exécuté.<br>
Lorsqu'une victime tente de se connecter à notre machine, Responder exploite la
connexion pour voler des informations d'identification et d'autres données.
Dans cette démonstration, nous utiliserons Responder pour accéder aux informations
d'identification par le biais de l'authentification SMB et WPAD. Nous avons utilisé une
machine Kali Linux, qui a cet outil préinstallé et qui est accessible sous
*/usr/share/responder*.

![Alt text](https://rfc6592.github.io/assets/img/responder.png)

![Alt text](https://rfc6592.github.io/assets/img/intresponder.png)

Nous pouvons voir que les capacités de WPAD sont désactivées par défaut, et pour les
activer nous allons ajouter les « flags » -w et -F (pour forcer le client à s'authentifier
auprès de nous dans le cadre du protocole WPAD). Couplés avec l'indicateur -I (pour
spécifier l'interface à exécuter) et l'indicateur -v (pour avoir une meilleure vue de ce
qui se passe), nous allons exécuter la commande suivante :

![Alt text](https://rfc6592.github.io/assets/img/servicesresponder.png)

Maintenant, tout est configuré et responder attendra les requêtes multicast NR.

## Attaquer la cible

Voilà ce qui se passe quand nous avons fait une erreur de frappe dans le nom d'un
dossier partagé (**\\\filesahr au lieu de \\\fileshare**), ce qui entraîne une série de requêtes
mDNS, LLMNR :

![Alt text](https://rfc6592.github.io/assets/img/nrsmb.png)

Comme vu dans l'introduction, plusieurs requêtes *NBT-NS*, *LLMNR* et *mDNS* ont été
diffusées par notre machine Windows victime, indiquant que l'hôte requis est censé
être un serveur de fichiers. Responder répond par défaut aux requêtes des serveurs de
fichiers (SMB et FTP). La victime a ensuite établi une connexion avec notre serveur
SMB malveillant et nous a remis ses informations d'identification.<br>
La victime a ensuite initié une connexion SMB et s'est authentifiée sur notre serveur,
comme le montrent les deux derniers paquets. Son nom d'utilisateur et le code de
hachage de son mot de passe ont été transférés et sont maintenant visibles pour nous
en clair ("User : limetest"). Le code de hachage complet est dispersé entre plusieurs
champs dans les deux paquets et peut être rassemblé manuellement, mais responder
les rassemble automatiquement produisant le code de hachage complet vu dans le
journal.

## WPAD Credential Access

Lors de notre seconde exécution, une requête pour les hôtes WPAD a été diffusée via
Google Chrome.
Après avoir usurpé une réponse et établi une connexion, la victime a demandé le fichier
wpad.dat Proxy Auto-Config (PAC). Responder a demandé à la victime de
s'authentifier d'abord - en récupérant ses informations d'identification.

![Alt text](https://rfc6592.github.io/assets/img/respondermozilla1.png)
![Alt text](https://rfc6592.github.io/assets/img/respondermozilla2.png)

## Contre-Mesures

Le NR multicast étant un comportement de pair-à-pair, la plupart des méthodes
d'atténuation se concentreront sur la sécurité des points d'extrémité, plutôt que de
s'appuyer sur la seule sécurité du réseau :

• **Désactiver LLMNR** - LLMNR peut être désactivé par l'intermédiaire de
l'éditeur de stratégie de groupe, dans le menu "Policy setting" sous Local
Computer Policy > Computer Configuration > Administrative Templates >
Network > DNS Client.

![Alt text](https://rfc6592.github.io/assets/img/contremesure1.png)
![Alt text](https://rfc6592.github.io/assets/img/contremesure2.png)


## Sources

* (Wikipedia, 2023), https://fr.wikipedia.org/wiki/Domain_Name_System<br>
* (MITRE ATT&CK, 2023), https://attack.mitre.org/techniques/T1557/001/<br>
* (Wikipedia, 2023), https://en.wikipedia.org/wiki/Multicast_DNS<br>
* (Github, 2023), https://github.com/SpiderLabs/Responder<br>
* (Practical Network Penetration Tester (PNPT), 2023) https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course<br>
* (Cynet, 2020), https://www.cynet.com/attack-techniques-hands-on/llmnr-nbt-ns-poisoning-and-credential-access-using-responder/<br>
* (NopSec, 2020), https://www.nopsec.com/blog/responder-beyond-wpad/<br>