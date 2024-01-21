---
layout: post
title: Méthode d'évasion d’antivirus (AV)
subtitle: There's lots to learn!
tags: [CyberSec]
comments: true
---

## Introduction

Actuellement, les antivirus (AVs) utilisent différentes méthodes pour vérifier si un
fichier est malveillant ou non, la détection statique, l'analyse dynamique et, pour les
EDRs plus avancés, l'analyse comportementale.

## Détection statique

Au cours d'une analyse, le moteur statique du logiciel antivirus compare les fichiers
existants dans le système d'exploitation à une base de données de signatures, ce qui
permet d'identifier les logiciels malveillants. Toutefois, dans la pratique, il est
impossible d'identifier tous les logiciels malveillants existants à l'aide de signatures
statiques, car toute modification apportée à un fichier malveillant particulier peut
contourner une signature statique particulière, voire contourner complètement le
moteur statique. Il existe plusieurs façons de contourner ce type de détection :<br/>

• **Chiffrement** : Si vous chiffrez le binaire, l’AV n'aura aucun moyen de détecter
votre programme, mais vous aurez besoin d'une sorte de « loader » pour
déchiffrer et exécuter le programme en mémoire.<br/>

• **Obfuscation** : Parfois, il suffit de modifier certaines chaînes de caractères dans
votre binaire ou votre script pour qu'il passe le test AV, mais cette tâche peut
prendre beaucoup de temps selon ce que vous essayez d'obscurcir.<br/>

• **Outils personnalisés** : Si on développe nos propres outils, il n'y aura pas de
mauvaises signatures connues, mais cela demande beaucoup de temps et
d'efforts.

![Alt text](https://rfc6592.github.io/assets/img/staticengine.png)

## Détection dynamique

En utilisant le moteur dynamique, le logiciel antivirus devient un peu plus avancé. Ce
type de moteur peut détecter les logiciels malveillants de manière dynamique (lorsque
le logiciel malveillant est exécuté dans un système. Par exemple, essayer de déchiffrer
et de lire les mots de passe de votre navigateur, effectuer un minidump sur LSASS,
etc.).<br/>

Le moteur dynamique est un peu plus avancé que le moteur statique, et son rôle est de
**vérifier le fichier au moment de l'exécution**, par le biais de plusieurs méthodes.
La première méthode est la surveillance des API - L'objectif de la surveillance des APIs
est d'intercepter les appels API dans les hooks du système d'exploitation. La deuxième
méthode est le sandboxing.<br/>

Un « sandbox » est un environnement virtuel séparé de la mémoire de l'ordinateur
hôte physique. Cela permet de détecter et d'analyser les logiciels malveillants en les
exécutant dans un environnement virtuel, et non directement sur la mémoire de
l'ordinateur physique lui-même.<br/>

Cette partie peut être un peu plus délicate à gérer, mais voici quelques mesures qu’on
peut prendre pour échapper aux sandboxes.<br/>

• **Veille avant exécution** : Selon la façon dont elle est mise en œuvre, cette méthode peut être un excellent moyen de contourner l'analyse dynamique des antivirus. Les antivirus ont un temps très court pour analyser les fichiers afin de ne pas interrompre le flux de travail de l'utilisateur, et l'utilisation de **longues périodes de sommeil peut perturber l'analyse des binaires**. Le problème est que de nombreux « sandbox » d'antivirus peuvent simplement ignorer le sommeil, selon la façon dont il est implémenté.<br/>

• **Vérification des ressources de la machine** : Habituellement, les
« sandbox » ont très peu de ressources pour travailler (par exemple, < 2 Go de
RAM), sinon ils pourraient ralentir la machine de l'utilisateur. Vous pouvez
aussi être très créatif, par exemple en vérifiant la température du CPU ou même
la vitesse des ventilateurs, car tout ne sera pas implémenté dans le bac à sable.<br/>

• **Contrôles spécifiques à la machine** : Si on veut cibler un utilisateur dont
le poste de travail est joint au domaine « TST.grp », on peut effectuer un
contrôle sur le domaine de l'ordinateur pour voir s'il correspond à celui que vous
avez spécifié, si ce n'est pas le cas, vous pouvez faire sortir votre programme.

![Alt text](https://rfc6592.github.io/assets/img/dynamicengine.png)

## Analyse heuristique


Grâce à un moteur heuristique, les logiciels antivirus deviennent encore plus
performants. Ce type de moteur détermine un score pour chaque fichier en effectuant
une analyse statistique qui combine les méthodologies du moteur statique et du moteur
dynamique.<br/>

La détection heuristique est une méthode qui, sur la base de règles comportementales
prédéfinies, permet de détecter les comportements potentiellement malveillants des
processus en cours d'exécution. Voici quelques exemples de ces règles :<br/>

• Si un processus tente d'interagir avec le processus LSASS.exe qui contient les
hachages NTLM des utilisateurs, les tickets Kerberos, etc.<br/>

• Si un processus qui n'est pas signé par un fournisseur réputé tente de s'inscrire
lui-même dans un emplacement persistant.<br/>

• Si un processus ouvre un port d'écoute et attend de recevoir des commandes
d'un serveur de Commande et de Contrôle (C2).<br/>

Le principal inconvénient du moteur heuristique est qu'il **peut entraîner un grand nombre de fausses détections positives**. En effectuant plusieurs tests simples par essais et erreurs, il est également possible d'apprendre comment fonctionne le moteur et de le contourner.

![Alt text](https://rfc6592.github.io/assets/img/heuristicengine.png)

## Unpacker

Un autre type de moteur largement utilisé par les logiciels antivirus est le moteur de
décompactage. L'un des principaux inconvénients des logiciels antivirus avancés
d'aujourd'hui réside dans leur utilisation d'unpackers, des outils utilisés par les
moteurs antivirus pour récupérer les charges utiles de logiciels malveillants qui ont
subi un "packing", ou une compression, pour cacher un modèle malveillant et ainsi
déjouer la détection basée sur les signatures.<br/>

Le problème est qu'il existe aujourd'hui un grand nombre d'empaqueteurs pour
lesquels les logiciels antivirus ne disposent pas de décompacteurs. Pour créer un
logiciel de décompactage automatisé, les chercheurs en sécurité de l'éditeur du logiciel
antivirus doivent d'abord procéder à un décompactage manuel - et ce n'est qu'ensuite
qu'ils peuvent créer un processus automatisé pour le décompacter et l'ajouter à l'un de
leurs moteurs antivirus.

![Alt text](https://rfc6592.github.io/assets/img/unpacker.png)

## Source

* Yehoshua, N., & Kosayev, U. (2021). Antivirus Bypass Techniques. Birmingham: Packt Publishing Ltd.
