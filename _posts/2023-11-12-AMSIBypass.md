---
layout: post
title: Patch AMSI
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

## AMSI Bypass

**amsi.dll** est chargée dans chaque processus powershell.exe, fournissant des fonctions d'exportation telles que AmsiInitialize(), AmsiOpenSession(), AmsiScanBuffer(), etc. Le contenu du script est transmis à AmsiScanBuffer() en tant qu'argument. Avant l'exécution, il sera déterminé si le script est malveillant.

Nous allons utiliser x64dbg pour s'attacher au processus powershell. Nous allons nous rendre à l'adresse de la méthode **AmsiOpenSession()** afin de récupérer un pattern et qui va nous permettre de réaliser un patching dynamique.


![Alt text](https://rfc6592.github.io/assets/img/AmisiOpenSessionBytes.PNG)

```c++
HRESULT AmsiOpenSession(
  [in]  HAMSICONTEXT amsiContext,
  [out] HAMSISESSION *amsiSession
);
```

Avant l'appel de la fonction **AmsiOpenSession()**, plusieurs étapes préliminaires sont généralement effectuées dans le contexte de l'Antimalware Scan Interface (AMSI) :

![Alt text](https://rfc6592.github.io/assets/img/amsicalls.png)


1. Chargement de amsi.dll :
amsi.dll, contient les fonctionnalités de l'AMSI, est généralement chargée dans le processus. Cela se fait au moment du démarrage ou lorsqu'une application nécessite l'utilisation de l'AMSI.

2. Initialisation avec AmsiInitialize() :
La fonction AmsiInitialize() est appelée pour initialiser le contexte de l'AMSI. Cette fonction retourne un handle appelé amsiContext, qui représente le contexte global de l'AMSI. Ce handle est souvent utilisé comme point de départ pour les opérations ultérieures de l'AMSI.

3. Chargement du script PowerShell :
Le script PowerShell, qui doit être analysé pour détecter toute activité malveillante, est chargé ou préparé. Ce script sera évalué plus tard par l'AMSI pour déterminer sa nature.

4. Transmission du script à AmsiScanBuffer() :
Le contenu du script PowerShell est ensuite transmis à la fonction AmsiScanBuffer() en tant qu'argument. Cette fonction est responsable de l'analyse du contenu du script pour détecter d'éventuelles menaces ou activités malveillantes.


![Alt text](https://rfc6592.github.io/assets/img/AmisiOpenSessionBytesPatched2.PNG)


Ce code effectue des vérifications sur les arguments de la fonction AmsiOpenSession(), avec des sauts conditionnels vers une adresse spécifique en cas de conditions d'erreur. Si ces conditions ne sont pas rencontrées, la fonction se termine en plaçant potentiellement un code d'erreur dans le registre `eax`.


4. `jmp amsi.7FF8D5AC382C` : Le programme saute à l'adresse 0x7FF8D5AC382C, pour sortir de la fonction.

Nous sommes maintenant en mesure de lancer, par exemple, ```Mimikatz```.

![Alt text](https://rfc6592.github.io/assets/img/AmisiOpenSessionBytesPatched.PNG)


## Sources

* Yehoshua, N., & Kosayev, U. (2021). Antivirus Bypass Techniques. Birmingham: Packt Publishing Ltd.
* (Puckiestyle, 2023) https://www.puckiestyle.nl/amsi-bypass/
* (Hackmag, 2023), https://hackmag.com/security/fck-amsi/
* (Github, 2023) https://github.com/ZeroMemoryEx/Amsi-Killer

