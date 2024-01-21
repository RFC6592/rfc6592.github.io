---
layout: post
title: SMB Relay Attack
subtitle: There's lots to learn!
tags: [CyberSec]
comments: true
---

## Introduction

Une attaque par relais SMB consiste pour un attaquant à capturer le hachage **Net-NTLM** [Network NT LAN Manager] d'un utilisateur et à le relayer à une autre machine du réseau. Il se fait passer pour l'utilisateur et s'authentifie auprès de SMB pour obtenir un accès au shell ou aux fichiers.<br/>

## Net-NTLM Vs NTLM
##### Net-NTLM (Network NT LAN Manager)
***Tout d'abord***, Les hachages **Net-NTLM** sont utilisés pour l'authentification en réseau (ils sont dérivés d'un algorithme de 'challenge/response' et sont basés sur le hachage NT de l'utilisateur).<br/><br/> ***Ensuite***, **Net-NTLMv1** et **Net-NTLMv2** sont des variations ou des versions spécifiques des hachages **Net-NTLM** utilisés dans le protocole d'authentification NTLM (NT LAN Manager).<br/><br/> ***Enfin***, **Net-NTLMv1** et **Net-NTLMv2** sont également connus sous les noms : **NTLMv1** et **NTLMv2**.<br/><br/> Voici un exemple de hachage Net-NTLMv2 :

```
admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030 
```

<br/>

##### NTLM (NT LAN Manager)

***Pour ce qui concerne***, **NTLM** **(SANS v1/v2 !)** signifie quelque chose de complètement différent.<br/><br/> ***En effet***, les hachages **NTLM** sont stockés dans la base de données Security Account Manager (SAM) et dans la base de données NTDS.dit du contrôleur de domaine.<br/><br/> Voici un exemple **(LM:NT)** :

```
aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42
```
<br/><br/>

## SMB Signing

La signature SMB vérifie l'origine et l'authenticité des paquets SMB. En fait, cela
empêche les attaques MITM de relais SMB de se produire. Si cette fonction est activée et requise sur une machine, nous ne serons pas en mesure d'effectuer une attaque par relais SMB.<br/>
*Nmap* peut être utilisé pour vérifier les cibles potentielles de relais SMB. Dans
l'exemple ci-dessous, j'ai listé l’ensemble des hôtes dans le réseau TST.

![Alt text](https://rfc6592.github.io/assets/img/smbvuln.PNG)

Si la signature est « *enabled and required* », nous ne serons pas en mesure de réaliser
une attaque par relais SMB. Ceci est vrai par défaut pour toutes les versions de
Windows Server. Cependant, dans notre cas nous avons plusieurs machines dont la
signature est « **enabled and not required** ». Cela signifie que l'attaquant peut
effectuer une attaque de relais en raison de cette non-obligation.

## Relais NTLM

L'authentification NTLM est un protocole basé sur « challenge-response ». Les
protocoles « challenge-response » utilisent un secret communément partagé, dans ce
cas le mot de passe de l'utilisateur, pour authentifier le client.<br/>

Le serveur envoie un défi, et le client répond avec la réponse à ce défi. Si le défi
correspond à celui calculé par le serveur, l'authentification est acceptée.
L'authentification NTLM est un protocole complexe, et la façon dont il est expliqué ici
est une simplification.


## Flux d'authentification NTLM

Il y a 3 étapes dans le protocole d'authentification NTLM :<br/>
• **Négocier l'authentification** : la première étape de l'authentification NTLM
est la négociation du protocole, et des fonctionnalités prises en charge par le
client. Dans cette étape, le client envoie la demande d'authentification au
serveur, y compris les versions de NTLM acceptées par le client.<br/>
• **Défi du serveur** : Le serveur répond avec son propre message, indiquant les
versions de NTLM qu'il accepte et les fonctionnalités qu'il veut utiliser. Ce
message comprend également une valeur "challenge", qui est importante dans
l'authentification.<br/>
• **Réponse d'authentification** : Le client renvoie la réponse basée sur le
challenge, et inclut le nom d'utilisateur et le domaine auquel le mot de passe
appartient.<br/>

Après l'échange des 3 messages, le serveur répond par un message indiquant soit que
l'authentification a réussi, soit qu'elle a échoué. Selon le protocole utilisé, la session
que le client a avec le serveur est maintenant authentifiée. Ce processus est illustré dans
la figure ci-dessous :

![Alt text](https://rfc6592.github.io/assets/img/fluxauthentification.png)

## Utilisation abusive de NTLM

En tant qu'attaquant, ce processus peut être détourné si un client peut être convaincu
de se connecter à un attaquant. La façon dont cela peut être fait est expliquée dans la
section suivante. Une fois qu'un attaquant a un client connecté prêt à s'authentifier, il
peut facilement transmettre les 3 messages au serveur entre le client et le serveur
jusqu'à ce que le cycle défi-réponse soit terminé.<br/>

![Alt text](https://rfc6592.github.io/assets/img/fluxattaquant.png)

Au moment où la connexion est authentifiée, l'attaquant peut simplement envoyer un
message d'erreur au client, ou interrompre la connexion. Ensuite, l'attaquant peut
utiliser la session pour interagir avec le serveur dans le contexte de l'utilisateur à partir
duquel l'authentification a été relayée.

## Relais inter-protocole

L'authentification NTLM est encapsulée dans d'autres protocoles, mais les messages
sont les mêmes, quel que soit le protocole surjacent. Cela permet d'utiliser les messages
NTLM dans d'autres protocoles. Par exemple, un client qui s'authentifie en utilisant
HTTP envoie les messages d'authentification NTLM dans l'en-tête "Authorization".
Un attaquant peut extraire ces messages de l'en-tête HTTP et les utiliser dans d'autres
protocoles, tels que SMB.<br/>
NTLM est supporté par plusieurs protocoles, par exemple SMB, HTTP(S), LDAP,
IMAP, SMTP, POP3 et MSSQL.

## Obtenir du trafic

Un point qui n'a pas encore été expliqué est la façon d'amener les clients à se connecter
avec l'attaquant plutôt qu'avec le vrai serveur. Il existe plusieurs façons d'obtenir du
trafic qui peut être relayé :

• Le trafic vers des hôtes dont l'IP est résolue de manière non sécurisée.<br/>
• Le trafic résultant de l'abus des protocoles d'AutoDiscovery<br/>
• Trafic obtenu par une attaque de type "man-in-the-middle".<br/>


## Utilisation de ntlmrelayx pour relayer à SMB

Le relais vers SMB est l'attaque classique. Le relais vers SMB permet aux attaquants
**d'exécuter des fichiers** sur des hôtes **dont la signature SMB est désactivée** si
l'utilisateur relayé dispose de privilèges administratifs sur la machine. Pour les
utilisateurs non administratifs, ntlmrelayx ajoute l'option de lancer un shell
smbclient, qui permet aux attaquants d'interagir avec les partages, par exemple pour
télécharger ou envoyer des fichiers. Cette attaque peut être faite avec l'option
interactive (-i), qui lancera un shell TCP local, auquel on peut se connecter avec par
exemple netcat.

![Alt text](https://rfc6592.github.io/assets/img/exploitserv.png)
![Alt text](https://rfc6592.github.io/assets/img/pocsmb.PNG)


## Utilisation de SMBExec

SMBExec est un script fourni avec Impacket, il **évite de transférer un binaire**
potentiellement détectable sur le site cible. Au lieu de cela, il vit complètement en
dehors du terrain en exécutant le « shell » de commande locale de Windows. Il permet
ainsi de transférer les commandes de la machine de l’attaquant via SMB dans un fichier
d’entrée spécial, puis créé et exécute une ligne de commande en tant que commande
Windows. Il lance l’interpréteur de commandes natif de Windows, redirige la sortie
vers un autre fichier spécial, puis envoie le fichier de sortie vers la machine de
l’attaquant via SMB.

![Alt text](https://rfc6592.github.io/assets/img/btobtosmb.png)

Du côté de l'attaquant, il y a une expérience de "pseudo-shell" avec des délais entre la
commande envoyée et la sortie reçue. Mais c'est une fonctionnalité suffisante pour
qu'un attaquant - qu'il s'agisse d'un initié ou d'un outsider qui a un pied à terre - puisse
rechercher du contenu intéressant.

![Alt text](https://rfc6592.github.io/assets/img/pocsmbexec.PNG)

## Contre-Mesures

Afin d'atténuer les attaques par relais SMB, l’organisation doit d'abord **activer la
signature SMB** sur tous les appareils, ce qui stoppera complètement l'attaque.<br/>

L'inconvénient est que cela peut entraîner des problèmes de performance lors des
copies de fichiers. L’organisation peut également désactiver l'authentification NTLM
sur le réseau, ce qui mettra également fin à l'attaque. Toutefois, si Kerberos cesse de
fonctionner en tant que méthode d'authentification, Windows reviendra par défaut à
NTLM, ce qui ne constitue pas une sécurité absolue.<br/>

Une autre mesure utile est l'Account Tiering, qui limite les administrateurs de
domaine à des tâches spécifiques. L'Account Tiering signifie que l'administrateur de
domaine se connecte uniquement à ses comptes de domaine et non à ses comptes
d'utilisateur. Toutefois, il n'est pas toujours facile pour une entreprise de faire
appliquer cette politique.<br/>

Enfin, l’organisation doit limiter les administrateurs locaux, ce qui empêchera les
mouvements latéraux. Cependant, il y aura une augmentation potentielle du nombre
de tickets du service d'assistance, car les utilisateurs peuvent se plaindre et vouloir
avoir des droits d'administration.

![Alt text](https://rfc6592.github.io/assets/img/contremesuresmb.png)




## Sources

* (Practical Network Penetration Tester (PNPT), 2023), https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course<br/>
* (Mozilla, 2023), https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Authorization<br/>
* (Fox-It, 2017), https://blog.fox-it.com/2017/05/09 relaying-credentials-everywhere-with-ntlmrelayx/<br/>
* (Github, 2023), https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py<br/>
* (Kali, 2023), https://www.kali.org/tools/impacket/<br/>
* (Akril, 2022), https://akril.net/comprendre-le-tiering-model-de-microsoft-en-francais/<br/>