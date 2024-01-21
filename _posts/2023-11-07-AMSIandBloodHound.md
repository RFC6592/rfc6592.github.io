---
layout: post
title: Bypass AMSI / BloodHound
subtitle: There's lots to learn!
tags: [CyberSec]
comments: true
---

## Qu'est-ce que AMSI ?

Depuis l'introduction de Windows 10, un nouveau mécanisme de défense appelé
"AMSI" (Anti-Malware Scan Interface) a été mis en place. Son objectif est de
contrecarrer certaines techniques d'obfuscation utilisées pour échapper aux signatures
antivirus lors de l'utilisation de scripts tels que Powershell, VBS, VBA et WSH, ainsi
que des programmes en C#. L'AMSI **analyse le code chargé dynamiquement** en
mémoire afin de détecter d'éventuelles activités suspectes.<br/>

En pratique, l'AMSI permet aux antivirus de s'enregistrer en tant que fournisseurs
"AMSI" et de mettre à disposition leur capacité d'analyse pour examiner le contenu
identifié comme étant suspect. Lorsqu'un binaire malveillant est téléchargé (par
exemple, Mimikatz.exe), il est normalement détecté directement par la solution
antivirus et supprimé. Cependant, dans le cas du chargement d'un script malveillant
directement en mémoire, il ne sera pas supprimé immédiatement. L'AMSI intervient
lors de l'exécution du script, en appelant l'antivirus pour analyser le contenu et
déterminer s'il est malveillant ou non, afin de bloquer son exécution.
Une vulnérabilité dans l'AMSI crée donc un point faible, d'autant plus que de
nombreux outils offensifs sont basés sur PowerShell de nos jours.

![Alt text](https://rfc6592.github.io/assets/img/amsi.png)

Comme on le voit ici, plusieurs fonctions sont exposées pour être utilisées par des
applications tierces. Par exemple, les moteurs antivirus peuvent appeler des fonctions
telles que *AmaiScanBuffer()* et *AmaiScanString()* pour analyser le contenu
malveillant de chaque fichier et filtrer les logiciels malveillants basés sur des scripts
avant que l’exécution n’ait lieu. Si AMSI détecte que le script est malveillant à l’aide de
ses fonctions, il interrompt l’exécution.

## BloodHound

BloodHound est une application web JavaScript à page unique, construite au-dessus
de Linkurious, compilée avec Electron, avec une base de données Neo4j alimentée
par un collecteur de données C#. BloodHound utilise la théorie des graphes pour
révéler les relations cachées et souvent involontaires dans un environnement Active
Directory.<br/>

Les attaquants peuvent utiliser BloodHound pour identifier facilement des
chemins d'attaque très complexes qui seraient autrement impossibles à identifier
rapidement. Les défenseurs peuvent utiliser BloodHound pour identifier et éliminer
ces mêmes chemins d'attaque.<br/>

Les équipes bleues et rouges peuvent utiliser BloodHound pour acquérir facilement
une meilleure compréhension des relations de privilèges dans un environnement
Active Directory.<br/>

Bloodhound fonctionne en exécutant un ingestor sur un système victime, puis en
interrogeant l’AD pour trouver des utilisateurs, des groupes et des hôtes. L'ingestor
tente alors de se connecter à chaque système pour énumérer les utilisateurs connectés,
les sessions et les autorisations. Bien sûr, cela va faire beaucoup de bruit sur le réseau.
Pour une organisation de taille moyenne à grande, avec la configuration par défaut (qui
peut être modifiée), cela peut prendre moins de 10 minutes pour se connecter à chaque
système hôte et interroger les informations en utilisant SharpHound. Notez que,
comme cette opération concerne tous les systèmes reliés à un domaine sur le réseau,
vous risquez d'être pris en flagrant délit. Il existe une option Stealth dans BloodHound
qui interroge uniquement Active Directory et ne se connecte pas à chaque système
hôte, mais les résultats sont assez limités.

## AMSI Bypass

Comme expliqué avant, lors de l’exécution d’un script malveillant PowerShell celui-ci
devrait être bloqué grâce à l’AMSI et votre Antivirus :<br/>

![Alt text](https://rfc6592.github.io/assets/img/scriptpowershellexec.png)

Lorsque vous exécutez le fichier SharpHound.ps1 («. .\Invoke-BloodHound)
directement dans PowerShell, ESET l'empêche de s'exécuter :

![Alt text](https://rfc6592.github.io/assets/img/scriptexec.PNG)

Comme ce script est connu comme une charge utile (« payload ») malveillante, ESET a sa signature et l'a empêché de s'exécuter.<br/>

De ce fait, j'ai fragmenté ce script et exécuté chaque partie séparément et directement dans PowerShell. En effet, l'AMSI ne peut pas détecter notre contournement avec une signature si nous l'exécutons ligne par ligne. Chaque fois que PowerShell est invoqué pour exécuter une commande/script, l'AMSI est sollicité pour déterminer s'il est malveillant. En exécutant le script ligne par ligne, nous le divisons efficacement en scripts différents, pour lesquels l'AMSI n'a aucune signature.<br/>

Enfin, je voulais découvrir quelles parties de la charge utile malveillante peuvent être détectées exactement. De fait, l'AMSI ne peut pas détecter la valeur de ce paramètre :
'$EncodedCompressedFile'. C'est la partie principale du code malveillant.

![Alt text](https://rfc6592.github.io/assets/img/sharphoundcode.png)

On peut contourner l’AMSI en encodant et en compressant la charge utile malveillante.
Pour enfin l’exécuter et obtenir nos résultats qui vont alimenter BloodHound.

![Alt text](https://rfc6592.github.io/assets/img/mappagebloodhound.png)

![Alt text](https://rfc6592.github.io/assets/img/mappageblound.PNG)

## Conclusion

Le concept est simple, diviser un script détecté en plusieurs blocs qui sont exécutés dans l'ordre pour éviter qu'il ne soit détecté. La seule limite peut-être est qu'il faut une session interactive pour pouvoir copier et coller un script PowerShell ligne par ligne. C'est bien pour de nombreux scénarios de test de pénétration, mais cela pose problème si nous essayons d'exécuter des commandes dans un environnement non interactif, comme l'exploitation d'une vulnérabilité RCE dans une application web.



## Sources

* Yehoshua, N., & Kosayev, U. (2021). Antivirus Bypass Techniques. Birmingham: Packt Publishing Ltd.
* (Puckiestyle, 2023) https://www.puckiestyle.nl/amsi-bypass/
* (Github, 2023), https://github.com/BloodHoundAD/SharpHound
* (Github, 2023), https://github.com/BloodHoundAD/BloodHound
* (Synetis, 2020), https://www.synetis.com/amsi-antivirus/
* Naserifard, A. (2020, 11 5). Bypass AMSI in PowerShell — A Nice Case Study. Récupéré sur
* Infosecwriteups: https://infosecwriteups.com/bypass-amsi-in-powershell-a-nice-case-study-f3c0c7bed24d
