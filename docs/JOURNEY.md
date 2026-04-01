# LoL Private Server - Journal de Reverse Engineering

## Objectif
Créer un serveur privé League of Legends compatible avec le client moderne (patch 16.6) pour jouer en local.

---

## Jour 1 — 31 Mars 2026

### Phase 1 : Capture du trafic réseau

**Tentative 1 : NetHook DLL (version.dll proxy)**
- On a déployé notre `version.dll` hook dans le client privé (`client-private/`)
- Le hook intercepte `sendto`/`WSASendTo`/`recvfrom`/`WSARecvFrom` dans `ws2_32.dll`
- Résultat : le client envoie des paquets de **519 bytes** fixes, tous chiffrés
- Notre serveur répond avec des VERIFY_CONNECT ENet standard, mais le client les rejette

**Erreur commise : Déploiement dans le client officiel**
- On a copié `version.dll` dans le dossier du LoL officiel → la partie ranked n'a pas pu se lancer
- Leçon apprise : **JAMAIS toucher au LoL officiel**

**Tentative 2 : pktmon (Windows packet monitor)**
- Lancé pour capturer le trafic réseau
- Résultat : Vanguard l'a détecté → erreur **VAN 193**
- Leçon : les outils de capture réseau kernel-level sont détectés par Vanguard

**Succès : Lecture des logs du client officiel**
- Les logs dans `Logs/LeagueClient Logs/` contiennent les arguments de lancement
- Découvert : `Game args: 162.249.72.5 7350 K4gyS9t7q4RaFM0VLUJFJg== 3722132733011200`
- On a la **clé Blowfish**, l'**IP du serveur**, le **port**, et le **Player ID**

**Succès : Lecture du r3dlog**
- Le fichier `r3dlog.txt` contient les détails du protocole :
  ```
  Encryption=true Compression=true CompressionLevel=3
  MTU=996 WindowSize=32768 ChannelCount=32
  Resends=20 Timeout=8
  ```
- Séquence découverte : Hard Connect → Game Info → Clock Sync → StartSpawn → Game Start
- Le vrai serveur Riot établit la connexion en **0.213 secondes**

### Phase 2 : Capture Wireshark d'une vraie partie

**Installation de Wireshark + Npcap**
- Wireshark installé via winget, Npcap manuellement
- Pas de VAN 193 cette fois (Npcap est différent de pktmon)

**Capture réussie : 67 MB de trafic réel**
- Fichier : `riot_game_capture.pcapng`
- Serveur Riot : `162.249.72.5:7342`
- Clé Blowfish : `jNdWPAc3Vb5AyjoYdkar/g==`
- 33,000+ paquets capturés pendant une partie de ~21 minutes

**Découvertes du protocole :**
| Direction | Taille | Description |
|-----------|--------|-------------|
| C→S | 519B | CONNECT |
| S→C | 111B | VERIFY_CONNECT |
| C→S | 65B | KeyCheck |
| C→S | 34B | Handshake suite |
| S→C | 125B | Session Info |
| S→C | 701B | Game Info |
| S→C | 500B+ | Spawn Data |

### Phase 3 : Analyse du format des paquets

**Découverte du LNPBlob**
- Le paramètre `-LNPBlob=N6oAFLLMbKo=` passé au client
- Décodé : `37-AA-00-14-B2-CC-6C-AA` = **magic (4B) + SessionID (4B)**
- C'est les 8 premiers bytes de chaque paquet client !
- Le client privé envoyait des zéros car on ne passait pas le LNPBlob

**Structure identifiée :**
```
Client: [8B LNPBlob][constant per session][nonce][encrypted payload][footer]
Server: [8B header][encrypted payload][footer]
```

**Footer = compteur de séquence**
- Les derniers bytes sont des compteurs qui incrémentent/décrémentent
- Le footer contient aussi `Encrypt(zeros)[1:0]` inversé

### Phase 4 : Tentatives de déchiffrement

**Fausse piste : Blowfish ECB**
- Le dissecteur `packet-lol` (Wireshark) utilise Blowfish ECB pour les anciennes versions
- Testé sur nos paquets : **ça ne marche PAS** pour le client moderne
- Les deux VERIFY du serveur donnent des résultats ECB complètement différents → pas ECB

**Test de tous les modes Blowfish :**
- CBC avec ~40 IVs différents (zeros, clé, header, nonce, sessionID...) → aucun match
- OFB avec IV=zeros → le premier byte donne `0x83` (VERIFY_CONNECT!) mais les suivants sont faux
- CFB avec IV=zeros → même résultat partiel
- CTR → rien

**Le `0x83` était probablement une coïncidence** (1 chance sur 16)

### Phase 5 : Analyse LENet (ENet library)

**Décompilation de LENet (NuGet package)**
- Toutes les classes décompilées : Version.cs, ProtocolHeader.cs, Protocol.cs, Buffer.cs, Host.cs
- Découverte cruciale : **tout est big-endian** dans LENet
- Season 12 : MaxPeerID=32767, ChecksumSend=0, ChecksumRecv=0, HeaderBase=8
- Season 8 : asymétrique (client send=8B checksum, server send=0B)
- LENet **ne gère PAS le chiffrement** — il réserve juste l'espace pour les checksums

**LeagueSandbox analysis**
- Le serveur LeagueSandbox utilise **Blowfish ECB** pour les game data (SEND_RELIABLE)
- Mais c'est pour **patch 4.20** (Season 4, 2014) — pas applicable au client moderne
- Le chiffrement Blowfish est au niveau APPLICATION, pas au niveau transport

---

## Jour 1 (suite) — Analyse du binaire

### Phase 6 : x64dbg + ScyllaHide

**Tentative de debug avec x64dbg**
- ScyllaHide installé avec profil VMProtect x86/x64
- Résultat : `stub.dll` détecte quand même le debugger → crash "critical error"
- Le client refuse de tourner sous un debugger, même avec ScyllaHide

### Phase 7 : Frida (instrumentation dynamique)

- Frida installé via pip
- Tentative de spawn + attach sur LoLPrivate.exe
- Résultat : `ProcessNotRespondingError` — le processus refuse l'injection de frida-agent
- `stub.dll` bloque aussi Frida

### Phase 8 : Hook GetProcAddress

- Tentative de hooker `GetProcAddress` dans `kernel32.dll` pour intercepter `WSASendTo`
- Résultat : crash immédiat — `stub.dll` vérifie l'intégrité de kernel32

### Phase 9 : Hook des fonctions crypto dans LoLPrivate.exe

**Tentative de NOP BF_cfb64_encrypt**
- On connaît l'adresse (offset 0x10f2ce0)
- Tentative de remplacement par `memcpy` ou `RET`
- Résultat : crash — `stub.dll` protège les zones mémoire de LoLPrivate.exe avec des guard pages

### Phase 10 : EVP Hook (scan mémoire)

**evp_hook.c — scan sans thread séparé**
- Scan des P-box directement dans le hook sendto (pas de thread)
- Résultat : **fonctionne !** 420+ paquets capturés, P-box trouvées
- Les P-box statiques ne sont PAS modifiées au moment du sendto → Blowfish pas initialisé pour le handshake

**evp_hook2.c — scan heap pour BF_KEY**
- Thread séparé qui scanne le heap pour des P-box modifiées
- Résultat : crash DirectX ("Impossible d'initialiser le dispositif d'affichage")
- Le scan heap trop lourd interfère avec l'initialisation DirectX

---

## Jour 1 (fin) & Jour 2 — Ghidra deep analysis

### Phase 11 : Ghidra sur LoLPrivate.exe

**P-box xrefs**
- Trouvé `BF_set_key` (FUN_1410ec460) via les P-box
- Call chain : FUN_140601920 → FUN_14058b8d0 → BF_set_key
- FUN_14058b8d0 initialise l'IV (confirmé : **IV = zéro**)

**BF_cfb64_encrypt (FUN_1410f2ce0)**
- 5 paramètres : key, input, output, length, encrypt_flag
- IV stocké à key+8, feedback CFB classique
- **4 callers** — TOUS pour le **spectateur/replay** (URLs `/observer-mode/...`)
- Le Blowfish CFB n'est **PAS utilisé pour le game UDP**

### Phase 12 : Strings dans le binaire

**LoLPrivate.exe contient :**
- `BF-CBC`, `BF-CFB`, `BF-ECB`, `BF-OFB` (modes Blowfish OpenSSL)
- `EVP_CipherInit_ex`, `EVP_EncryptUpdate` (API OpenSSL)
- `EncryptThenMac` (pattern Encrypt-then-MAC)
- `blowfish` (string)

**stub.dll contient :**
- `aesenc`, `aesdec` (instructions AES-NI) — probablement pour sa propre protection
- `cbc`, `ctr` (strings)
- PAS de P-box Blowfish, PAS de strings OpenSSL

**RiotGamesApi.dll contient :**
- `AESGCM` → c'est un nom de classe/message, PAS l'algo de chiffrement
- `BCryptGenRandom` → pour les nombres aléatoires
- Import de `WS2_32.dll` (fonctions réseau par ordinal)
- Import de `bcrypt.dll`, `CRYPT32.dll`
- Gère TCP/WebSocket/REST, PAS le game UDP

### Phase 13 : Localisation du sendto

**Hook call stack**
- Ajout de `__builtin_return_address(0)` dans le hook sendto
- Résultat : `LoLPrivate.exe +0x58ECBB` appelle sendto
- Stack : seulement 2 niveaux (LoLPrivate.exe → ntdll thread entry)
- Pas de RiotGamesApi.dll dans la stack → le game UDP est dans LoLPrivate.exe

**Ghidra disassembly autour du sendto**
- `0x58EC8A` : CALL [import] (probablement connect/getsockname)
- `0x58ECB5` : CALL [import] (sendto)
- `0x58ECBB` : TEST EAX, EAX (check return value)
- Avant le sendto : copie de données depuis RSI (queue buffer) vers la stack
- CALL FUN_140596260 (dequeue) retire un paquet de la queue
- Les données dans la queue sont DÉJÀ chiffrées

---

## Résumé des découvertes

### Ce qui est CONFIRMÉ :
1. Le client envoie des paquets UDP de 519 bytes, tous chiffrés
2. Le serveur Riot répond avec des paquets de tailles variables (111B pour VERIFY)
3. Le chiffrement du handshake n'est PAS du Blowfish (les fonctions BF sont pour le spectateur)
4. Le code réseau UDP est dans LoLPrivate.exe (offset +0x58ECBB pour sendto)
5. Les paquets passent par une queue (buffer circulaire) avant l'envoi
6. Le chiffrement se fait quand le paquet est mis dans la queue (enqueue), pas au sendto
7. `stub.dll` protège contre : debugger, Frida, hook kernel32, modification mémoire des fonctions crypto
8. Notre `version.dll` proxy avec hooks ws2_32 fonctionne sans être détecté

### Ce qui reste INCONNU :
1. L'algorithme exact de chiffrement du handshake UDP
2. La dérivation de la clé de chiffrement
3. La fonction "enqueue" qui chiffre les paquets avant de les mettre dans la queue

### Statistiques :
- ~30 scripts Ghidra écrits et exécutés
- ~10 variantes du hook DLL compilées et testées
- ~40 combinaisons IV/mode crypto testées
- 67 MB de trafic réel capturé via Wireshark
- 420+ paquets capturés via nethook
- 7199 lignes de code ajoutées

---

## Prochaines étapes

1. **Analyse Ghidra complète** (en cours, ~30 min sur 33MB)
   - Avec l'analyse complète, Ghidra reconnaîtra les fonctions autour du sendto
   - On pourra décompiler la vraie fonction réseau et trouver l'enqueue

2. **Hooker l'enqueue**
   - Une fois l'adresse trouvée, hooker la fonction qui met les paquets dans la queue
   - Capturer le plaintext AVANT le chiffrement

3. **Implémenter le chiffrement dans notre serveur**
   - Une fois l'algo connu, l'implémenter en C#
   - Le serveur pourra chiffrer/déchiffrer correctement

4. **Compléter le handshake**
   - CONNECT → VERIFY_CONNECT → KeyCheck → Game Info → Spawn → Start
   - Le gameplay (165 champions, 138 items) est déjà codé et attend la connexion
