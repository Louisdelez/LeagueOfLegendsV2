# LoL Private Server - Journal de Reverse Engineering

## Objectif
Créer un serveur privé League of Legends compatible avec le client moderne (patch 16.6) pour jouer en local.

---

## Jour 1 — 31 Mars 2026

### Phase 1 : Capture du trafic réseau

**NetHook DLL (version.dll proxy)**
- Déployé `version.dll` hook dans `client-private/` (copie privée du client)
- Hook intercepte `sendto`/`WSASendTo`/`recvfrom`/`WSARecvFrom` dans `ws2_32.dll`
- Le client envoie des paquets de **519 bytes**, tous chiffrés
- Leçon : **JAMAIS toucher au LoL officiel ni à Vanguard**

**Capture Wireshark réussie : 67 MB de trafic réel**
- Serveur Riot : `162.249.72.5:7342`
- Clé Blowfish : `jNdWPAc3Vb5AyjoYdkar/g==`
- 33,000+ paquets capturés pendant ~21 minutes

**Découvertes clés :**
- LNPBlob = `[4B magic 0x37AA0014][4B SessionID]` → premiers 8 bytes de chaque paquet client
- Structure des paquets identifiée (header, payload chiffré, footer)

### Phase 2 : Tentatives de déchiffrement (TOUTES ÉCHOUÉES)

| Tentative | Résultat |
|-----------|----------|
| Blowfish ECB | Pas de match |
| Blowfish CBC (~40 IVs) | Pas de match |
| Blowfish OFB/CFB (IV=0) | Premier byte OK (0x83) mais suite fausse |
| AES-GCM/CTR | Rien |

### Phase 3 : Analyse du binaire

- **x64dbg + ScyllaHide** : stub.dll détecte le debugger → crash
- **Frida** : `ProcessNotRespondingError` — stub.dll bloque l'injection
- **Hook kernel32** : crash immédiat — stub.dll vérifie l'intégrité
- **NOP BF_cfb64_encrypt** : crash — guard pages sur .text

### Phase 4 : Ghidra — Analyse statique

- P-box xrefs → `BF_set_key` (FUN_1410ec460)
- Call chain : FUN_140601920 → FUN_14058b8d0 → BF_set_key
- IV initialisé à 0 dans FUN_14058b8d0 ✅
- **BF_cfb64_encrypt** (FUN_1410f2ce0) : 4 callers, TOUS pour spectateur/replay
- Le sendto est à LoLPrivate.exe +0x58ECBB, pas dans RiotGamesApi.dll

---

## Jour 2 — 1er Avril 2026

### Phase 5 : PERCÉE — Double CFB découvert

**Découverte majeure via Ghidra :**
- FUN_1410f2a10 : Double CFB decrypt → CFB_decrypt → reverse ALL bytes → CFB_decrypt
- FUN_1410f41e0 : Double CFB encrypt → CFB_encrypt → reverse ALL bytes → CFB_encrypt
- Clé = `17BLOhi6KZsTtldTsizvHg==` de gameconfig.json (pas la clé Riot !)
- IV = 0 pour chaque paquet (frais)

**Vérification :**
- P-box + S-box capturés depuis la mémoire du process → match byte-for-byte
- Double CFB roundtrip sur données client réelles → **PARFAIT**

### Phase 6 : Echo handshake fonctionne

- Serveur renvoie les propres données du client (bytes 8-518)
- Le client accepte via un bypass memcmp (ring buffer)
- Séquence echo : 519 → 119 → 64 → 34 → 27 → 19B
- Client atteint l'état **"Hard Connect"** ✅

### Phase 7 : CRC nonce — Le dernier obstacle

**Problème :** Les paquets non-echo sont rejetés par FUN_1405725f0 (CRC check)

**Analyse Ghidra de la chaîne CRC :**
- FUN_140588f70 : construit un struct sur la stack
- FUN_1405725f0 : appelle FUN_140577f10(param_1) pour calculer le CRC attendu
- Comparaison : `iVar20 == FUN_140577f10(param_1)` → si faux, paquet rejeté

### Phase 8 : Tentatives de bypass CRC — TOUTES BLOQUÉES

| Méthode | Résultat |
|---------|----------|
| VirtualProtect sur .text | err=5, ACCESS_DENIED (guard pages) |
| Hardware breakpoints (DR0/DR7) | GetThreadContext retourne FALSE pour les DR |
| TF trap flag + VEH | stub.dll VEH intercepte SINGLE_STEP avant nous |
| RaiseException custom | VEH pas déclenché |
| Frida attach/spawn | "refused to load frida-agent" |
| WriteProcessMemory externe | VirtualProtectEx échoue |
| Fake stub.dll | Integrity check → crash instant |
| Patch binaire sur disque | Hash check → "Crash Dump" |
| **Cheat Engine kernel driver** | **Bloqué par Windows driver blocklist** |

### Phase 9 : Calcul du CRC nonce correct

**Struct CRC sur la stack de FUN_140588f70 :**

| Offset | Variable | Valeur |
|--------|----------|--------|
| 0x00 | local_c8 | `*(conn+0x138)` = 1 |
| 0x08 | local_c0 | 0 |
| 0x18 | local_b0 | 0xFFFFFFFFFFFFFFFF |
| 0x48 | local_80 | NULL (pas de payload) |
| 0x52 | — | 0 (payload length) |

**Ordre de traitement :** byte[8], byte[9], byte[0..7], local_res10[0..7]

**Nonce calculé = `~crc = 0x8DFE1964`** ✅

Le serveur a été mis à jour avec ce nonce correct.

### Phase 10 : Préparation CE kernel driver

- Registre Windows modifié : `VulnerableDriverBlocklistEnable = 0`
- Script Lua prêt : `ce_kernel_patch.lua`
- **REBOOT NÉCESSAIRE** pour que la modification prenne effet

---

## Jour 2 (suite) — 2 Avril 2026

### Phase 11 : Client launch corrigé

**Découverte :** Le client nécessite des arguments complets pour fonctionner :
```
-Product=LoL -PlayerID=1 -GameID=1 -LNPBlob=N6oAFO++rd4=
-GameBaseDir=D:\LeagueOfLegendsV2\client-private -Region=EUW
-Locale=fr_FR -SkipBuild -EnableCrashpad=false
```
Sans ces args → "Failed to extract information from command line string" → exit immédiat.

**Découverte :** Le serveur doit être lancé avec `--rawudp` (pas le mode LENet auto-detect qui cycle les protocoles et rate les paquets client).

### Phase 12 : Nettoyage git + push

- Fichiers massifs retirés de l'historique (client-private/ = 3.3 Go, ghidra_project/ = 2+ Go)
- .gitignore mis à jour pour exclure client-private/, ghidra_project/, ghidra/, jdk*, mingw64/, *.zip
- Push réussi sur GitHub

---

## Résumé — État actuel

### RÉSOLU ✅
1. Client lance et charge les assets
2. Encryption Blowfish Double CFB crackée et vérifiée
3. Echo handshake fonctionne → "Hard Connect"
4. CRC nonce calculé correctement (0x8DFE1964)
5. Format complet des paquets reverse-engineered
6. Toutes les fonctions Ghidra clés identifiées

### EN COURS ⏳
7. CRC bypass via CE kernel driver (après reboot)

### À FAIRE ❌
8. Paquets de game init (KeyCheck, StartGame)
9. Loading screen
10. Gameplay (165 champions, 138 items déjà codés)

---

## Jour 3 — 2 Avril 2026

### Phase 1 : Tentatives CRC bypass (TOUTES échouées)
- CE kernel patch : VulnerableDriverBlocklist désactivé, reboot OK, mais Vanguard kernel bloque les écritures même via CE
- NtProtectVirtualMemory direct syscall (0x50 lu depuis ntdll sur disque) : STATUS 0xC000004E (Vanguard intercepte au kernel)
- NtWriteVirtualMemory direct syscall : STATUS_PARTIAL_COPY
- Hardware breakpoints : stub.dll intercepte GetThreadContext/SetThreadContext
- Verdict : **AUCUNE méthode ring-3 ne peut patcher le CRC check**

### Phase 2 : PERCÉE — Echo-all via recvfrom hook
- Idée : au lieu de patcher le CRC, contourner en renvoyant les propres données du client
- Le hook version_proxy.c capture chaque sendto et le retourne via recvfrom (strip 8B LNPBlob header)
- Résultat : **handshake complet !** 519B→119B→64B→34B→27B→19B
- Le client atteint l'état **CONNECTED** et maintient avec des pings 19B/27B

### Phase 3 : Tracing du pipeline complet
- Installé Ghidra 11.3.2 complet + Java JDK 21 + MSYS2/MinGW
- Trouvé le VRAI host struct par scan de la stack (matching *(ptr+0x38)==socket)
- plVar15 = *(host+0x20) — l'objet handler NON-NULL !
- vtable[0x28] = RVA 0x573160 (FUN_140573160) — le handler CRC confirmé
- **Pipeline tracé de bout en bout** :
  1. recvfrom → FUN_140588f70 (CRC/decrypt)
  2. → FUN_140573160 (vtable handler, enqueue)
  3. → FUN_140589a90 (producer: ring buffer)
  4. → FUN_1405883d0 (consumer: dequeue loop)
  5. → dispatch: CALL [RAX+0x10] via *(plVar15+0x128)

### Phase 4 : KeyCheck injection (ne marche pas encore)
- P[0]=0xBBCD2876 confirmé (match client)
- CRC nonce computation confirmée via FUN_140577f10 du client
- Queue slot montre cmd=6 (SEND_RELIABLE) à l'offset correct +0x1B
- KeyCheck injecté (encrypted + raw) : le client ne réagit pas
- Direct dispatch call → crash initial (double déréférencement vtable)

### Phase 5 : Consumer dispatch deep dive
- Consumer FUN_1405883d0 déqueue et dispatch via CALL [RAX+0x10]
- +0x128 et +0x168 : **STUBS** (GetDefaultSettings=return, return 1)
- **VRAI handler** trouvé à +0x160 : FUN_14057dce0 (RVA 0x57DCE0)
- Fix vtable read : *(plVar15+0x160) EST directement le vtable (pas double deref)
- **Direct dispatch RÉUSSI** : fn(plVar15, &key=0) → returned OK, pas de crash !
- FUN_14056e310 = std::map insert dans plVar15+0x150
- +0x128 vtable INCHANGÉ après l'appel (stubs permanents)
- **Prochaine étape** : trouver qui lit le std::map à +0x150 (game logic consumer)

### Phase 6 : TLS cert pinning (le dernier mur)
- Découverte : `-RiotClientPort` et `-RiotClientAuthToken` nécessaires pour le LCU
- Le client contacte le FakeLCU mais TLS échoue (UnknownCA)
- 35 certs DER trouvés dans le binaire (DigiCert + Riot CA à 0x19EEBD0)
- BoringSSL embarqué statiquement (pas de secur32.dll/OpenSSL externe)
- Patch mémoire (.rdata) bloqué par Vanguard, patch disque bloqué par stub.dll
- CertVerifyCertificateChainPolicy patché → non utilisé par le client
- **PERCÉE** : `FUN_14168a4f0` parse les certs DER en handles heap
- `FUN_1410fbdc0` construit un `std::vector<handle>` = trust store
- Handles obtenus pour notre cert ET le Riot CA
- **Prochaine étape** : scanner le heap pour le trust vector, push_back notre handle

### Statistiques mises à jour
- ~80 scripts Ghidra écrits et exécutés
- ~25 variantes du hook DLL compilées et testées
- ~40 combinaisons IV/mode crypto testées
- 12+ méthodes de bypass CRC tentées (TOUTES échouées, contourné par echo)
- 67 MB de trafic réel capturé
- Double CFB + CRC nonce + pipeline complet reverse-engineered
- Client CONNECTED via echo-all ✓
- Real handler trouvé et appelé ✓
- 35 certs DER identifiés, cert handles obtenus sur le heap ✓
- **CRC algorithm FULLY REVERSED** — non-standard byte mixing ✓
- **Blowfish + CRC in hook DLL** — self-contained, P[0] verified ✓
- **Hybrid echo+fixup** — handshake via echo, server data via CRC fixup ✓

---

## Jour 3 (suite) — 2 Avril 2026 (session 2)

### Phase 12 : PERCÉE MAJEURE — Algorithme CRC cracké

**Découverte via Ghidra headless + decompilation de FUN_140577f10 :**

L'algorithme CRC-32 de LoL utilise un mélange de bytes **NON STANDARD** :
```
crc = ((crc << 8) | byte) ^ table[crc >> 24]
```
Au lieu du standard CRC-32/MPEG-2 : `crc = (crc << 8) ^ table[(crc >> 24) ^ byte]`

- Table à `DAT_141947e80`, polynôme `0x04C11DB7`, entry[1]=`0x04C11DB7`
- Init : `(peerLo | 0xFFFFFF00) ^ 0xB1F740B4`
- Ordre : peerHi, local_c8[0..7]={1,0,...}, local_b0[0..7]={FF,...}, puis payload
- Nonce vérifié : peerID=0, no payload → `~crc = 0x8DFE1964` ✅

### Phase 13 : Blowfish + CRC implémentés dans le hook DLL

- Implémentation complète de Blowfish en C (P-array, S-boxes, CFB encrypt/decrypt)
- Clé : `17BLOhi6KZsTtldTsizvHg==` = `D7B04B3A18BA299B13B65753B22CEF1E`
- P[0] = `0xBBCD2876` vérifié au runtime ✅
- enc(zeros) = `F9ED26C0F22A52B4` vérifié ✅
- Double CFB : encrypt→reverse→encrypt / decrypt→reverse→decrypt
- CRC fixup : decrypt packet → compute nonce → patch bytes[2..5] → re-encrypt

### Phase 14 : Mode hybride echo + CRC fixup

- **Echo phase** (50 paquets) → handshake complet → Hard Connect ✅
- **CRC fixup phase** → paquets serveur déchiffrés, nonce corrigé, re-chiffrés ✅
- Le client reçoit les paquets serveur avec CRC correct
- **MAIS** : le serveur n'envoie pas de paquets ENet valides (mauvais format)
- Le client reste connecté mais ne progresse pas (pas de VERIFY_CONNECT valide)

### Prochaine étape
Résoudre le TLS cert pinning pour que le FakeLCU fonctionne.

---

## Jour 4 — 3 Avril 2026

### Phase 15 : CFB block-based corrigé

**Découverte via Ghidra :** le Double-CFB ne traite que les blocs complets de 8 bytes.
Les bytes restants (`len % 8`) passent en clair dans les deux sens.
- Corrigé dans le serveur C# ET le hook C
- Roundtrip vérifié : `192D3AFE7205F4DB` match Python ↔ C ✅

### Phase 16 : Utilisation du BF context du jeu

- Trouvé le BF_KEY context via `connStructAddr + 0x120` (std::map lookup, key=1)
- IV = 0 confirmé au runtime (`*(bfCtx+8) = 0, *(bfCtx+0xC) = 0`)
- CRC nonce calculé par `FUN_140577f10` du jeu (exact match garanti)
- Packets chiffrés par `FUN_1410f41e0` du jeu (mode 2 = CFB encrypt)

### Phase 17 : Découverte du header 4B non-chiffré

**`conn+0x144 = 4`** → le jeu lit 4 bytes de header non-chiffré AVANT le Double-CFB decrypt.
- Format réel : `[4B header][Double-CFB encrypted: [4B nonce][1B flags][body]]`
- Le header contient le connection token (capturé depuis le premier paquet 519B)
- La partie chiffrée est paddée à un multiple de 8 bytes

### Phase 18 : Dispatcher de paquets game (agent Ghidra)

- Dispatcher principal : `FUN_140955c20` (5284 bytes, switch géant)
- **Opcodes sur 16 bits** (pas 8 bits !) — lu à `*(ushort*)(param_2 + 0x08)`
- ~81 opcodes uniques de 0x000A à 0x0479
- Jump table à `0x140957120` (250 entries)
- Le KeyCheck est géré au niveau ENet, AVANT ce dispatcher
- Les données game passent par un batch framing (`0x02` marker + length + `0x18` terminator)

### Phase 19 : PERCÉE — Cause racine identifiée

**Sortie stdout du client :**
```
CONN| Hard Connect at LocalSimTime(0.000)
FLOW| Timeout waiting to connect to: FLOW
```

**Le bloqueur n'est PAS le KeyCheck** — c'est la connexion LCU WebSocket (TLS) !
1. Le client se connecte via WebSocket Secure au FakeLCU (RiotClientPort)
2. BoringSSL rejette notre certificat → `certificate verify failed`
3. Le client ne reçoit pas les données de session (roster, map, etc.)
4. La state machine FLOW timeout → "Connexion impossible"

Le pipeline UDP fonctionne à 100%, mais le jeu attend le LCU AVANT de démarrer.

### Statistiques mises à jour
- Pipeline UDP complet : echo → CAFE → CRC fixup → game's BF → client ACK ✅
- Double-CFB : vérifié byte-pour-byte entre Python, C et C# ✅
- CRC : calculé par la fonction du jeu, nonce exact ✅
- Fenêtre de jeu rendue, pas de crash ✅
- ~90 scripts Ghidra écrits et exécutés
- ~30 variantes du hook DLL compilées et testées
- 81 opcodes game identifiés
- **Prochain objectif : TLS cert injection dans le trust store BoringSSL**

---

## Jour 4 — 3 Avril 2026 (suite)

### Phase 20 : Protocole client-driven (recherche)

Recherche approfondie du protocole LoL via LeagueSandbox (open source, Season 4) :
- Le protocole est **CLIENT-DRIVEN** : le client envoie des requêtes, le serveur répond
- Séquence d'init : KeyCheck → QueryStatusAns → SynchVersionS2C → CharSelected → TeamRosterUpdate → StartSpawn → CreateHero → StartGame
- Opcodes Season 4 : QueryStatusReq=0x14, QueryStatusAns=0x88, SynchVersion=0xBD/0x54
- Format GamePacket : `[1B opcode][4B netID][body]` ou extended `[0xFE][4B netID][2B opcode][body]`
- **Les opcodes modernes (16.6) sont différents** — 81 opcodes de 0x000A à 0x0479

### Phase 21 : Fix du parsing client côté serveur

Bug critique trouvé : le serveur ne skipait pas le header 4B non-chiffré avant le decrypt.
- Corrigé : `Array.Copy(data, 8 + headerSkip, encPayload, 0, encLen)` (skip 4B conn token)
- Ajouté parsing batch (cmd=2) et reliable (cmd=6) des paquets client
- Ajouté extraction d'opcodes game depuis les records batch
- **Mais** : le BF du serveur C# ne match pas le BF du jeu → decrypt client incorrect
- Le hook (utilisant le BF du jeu) donne les bons résultats

### Phase 22 : PERCÉE MAJEURE — Le heap scan crashait le jeu !

**Le "timer de 17 secondes" n'existait pas.** C'était le heap scan du CertThread qui corrompait la mémoire du jeu.

Test diagnostic :
1. ❌ Avec heap scan : jeu meurt après ~15 secondes
2. ✅ Sans heap scan : **jeu tourne indéfiniment** (2+ minutes confirmé)
3. ✅ Avec données game (ACK, VERIFY_CONNECT, opcodes) : pas de crash

Le heap scan itérait `VirtualQuery()` sur TOUTES les pages mémoire du processus, cherchant le trust store BoringSSL. Cette itération massive corrompait les structures internes du jeu.

### Phase 23 : FLOW timeout = warning, pas fatal

```
000000.786| ALWAYS|  CONN| Hard Connect at LocalSimTime(0.000)
000030.743| ALWAYS|  FLOW| Timeout waiting to connect to: FLOW
000060.736|  ERROR| ClientWebSocketTransport: certificate verify failed
000120.745|  ERROR| ClientWebSocketTransport: certificate verify failed
```

- `flowPtr+8 = 1` patch fonctionne (val passe de 0 à 1)
- Le timeout FLOW à 30s est un **warning**, le jeu continue
- Le client retente la connexion LCU toutes les 60 secondes
- Le processus game reste actif avec 192-208 MB de mémoire

### Phase 24 : Paquets game envoyés — CRC PASS, pas de crash

Envoyé via CAFE (cmd=0x02, game data path) :
- QueryStatusAns (opcode 0x88, format Season 4)
- SynchVersionS2C (opcode 0x54, 512B)
- Extended opcodes (0xFE prefix) : 0x0088, 0x0054, 0x005C, 0x0062, 0x0011, 0x00C1
- StartGame (opcode 0x5C), KeyCheck response (32B)
- **Tous CRC PASS, aucun crash** — mais pas de réaction visible (opcodes modernes différents)

### Phase 25 : Tentatives de bypass TLS (Vanguard bloque)

Le dernier bloqueur : BoringSSL rejette notre certificat TLS pour le FakeLCU.

**Tentative 1 : Patch .text (VirtualProtect)**
- 13 sites `MOV EDX, 0x86` (SSL_R_CERTIFICATE_VERIFY_FAILED) trouvés
- 3 avec JNZ/JZ en amont : RVA 0x16EEA0E, 0x172E3CA, 0x1848C99
- ❌ `VirtualProtect` retourne ERROR_ACCESS_DENIED (err=5) — Vanguard protège .text

**Tentative 2 : Hardware breakpoints via SetThreadContext**
- ❌ 0/66 threads modifiés — Vanguard bloque aussi les registres debug

**Tentative 3 : Hardware breakpoints via VEH (CrcBypassVEH pattern)**
- DR1/DR2 ajoutés dans le handler VEH existant (même pattern que CRC bypass)
- Mais le TLS se passe AVANT que les breakpoints soient installés (0.1s vs 4s)

**Tentative 4 : DLL_THREAD_ATTACH avec TF flag**
- ❌ Le TF flag dans DllMain crashe les threads

### Analyse des paquets client 37B périodiques

Le client envoie un paquet de 37B (25B chiffrés) toutes les 2 secondes :
```
[2B seq LE][4B CRC nonce][1B cmd][body]
  bytes 8-9:   00 04 (constant)
  bytes 10-11: compteur incrémental
  bytes 12-14: FE 2C A6 (constant — possible extended opcode marker)
  byte 17:     A3 (constant)
```

### État actuel — Progression 9.8/11

| Étape | État | Détails |
|-------|------|---------|
| 1. Client launch | ✅ | Assets chargés, fenêtre game rendue |
| 2. Blowfish Double-CFB | ✅ | Block-based, game functions |
| 3. CRC reversed | ✅ | Poly 0x04C11DB7, non-standard byte mixing |
| 4. CRC fixup via CAFE | ✅ | Game's own CRC function + BF context |
| 5. Client CONNECTED | ✅ | Echo handshake, Hard Connect |
| 6. CAFE delivery | ✅ | Server packets delivered via hook |
| 7. Packet format | ✅ | [4B hdr][DoubleCFB: [4B nonce][1B flags][body]] |
| 8. FLOW bypass | ✅ | flowPtr+8=1, timeout non-fatal |
| 9. Game data delivery | ✅ | 20+ opcodes envoyés, CRC PASS, 0 crash |
| 9.5 Heap scan fix | ✅ | Jeu tourne 2+ minutes (crash résolu) |
| 10. TLS cert bypass | ⏳ | **Vanguard bloque — approche alternative requise** |
| 11. Loading screen | ⏳ | Packets envoyés mais framing incorrect |

### Statistiques Jour 4
- ~100 variantes du hook DLL compilées et testées
- ~100 scripts Ghidra
- 13 sites cert verify identifiés dans le binaire
- 4 approches TLS bypass tentées (toutes bloquées par Vanguard)
- Jeu stable en mode echo + CAFE ACK (2+ minutes)

---

## Jour 5 — TLS exhaustif + Opcode table + Packet framing (2026-04-04)

### Phase 26 : TLS cert verify — 15 approches testées
Objectif : contourner la vérification TLS de BoringSSL pour la connexion FakeLCU.

**Résultat : ÉCHEC sur toutes les approches. Vanguard est impénétrable.**

| # | Approche | Résultat |
|---|----------|----------|
| 1 | VirtualProtect .rdata | err=5 (ACCESS_DENIED) |
| 2 | NtProtectVirtualMemory syscall | 0xC000004E |
| 3 | NtWriteVirtualMemory syscall | 0x8000000D |
| 4 | VirtualProtect .text | err=5 |
| 5 | Hardware breakpoints (DR0-DR3) | SetThreadContext bloqué |
| 6 | DLL_THREAD_ATTACH + TF flag | Crash threads |
| 7 | Heap CRYPTO_BUFFER DER swap | Trouve stack temps, pas trust store |
| 8 | Heap X509 pointer swap | Swap nos propres objets, pas ceux du jeu |
| 9 | verify_mode brute-force | 1587 faux positifs |
| 10 | SSL_CTX ciblé (method=0x199D218) | Objet trouvé mais pas SSL_CTX (contient "shaders") |
| 11 | CertVerifyCertificateChainPolicy | Patché mais BoringSSL ne l'utilise pas |
| 12 | InitializeSecurityContextW | secur32 jamais chargé |
| 13 | SSL_CERT_FILE env var | BoringSSL l'ignore |
| 14 | AddCA via ParseCert (RVA 0x168A4F0) | Appel réussit mais n'ajoute pas au trust store |
| 15 | PatchRiotCA (.rdata cert) | Page protégée par Vanguard |

**Découvertes TLS :**
- Page .rdata : protect=0x02 (PAGE_READONLY) mais VirtualProtect refuse
- Erreur client : `error:1416F086:SSL routines:tls_process_server_certificate:certificate verify failed`
- Premier essai TLS à 83ms (avant que notre DLL ne s'exécute)
- BoringSSL statiquement linké, erreurs "OpenSSL" sont des messages de compatibilité

### Phase 27 : Certificats régénérés
- **myCA.crt** : CA:TRUE, CN="LoL Private CA", keyCertSign (807B DER)
- **server_tls.crt** : signé par myCA, SAN=localhost+127.0.0.1
- **server_tls.pfx** : bundle complet pour FakeLCU
- Chaîne vérifiée : `openssl verify -CAfile myCA.crt server_tls.crt → OK`

### Phase 28 : Table d'opcodes extraite du binaire
Dump de la jump table du dispatcher (RVA 0x955C20) au runtime via version.dll :
- Byte index table : RVA 0x957120 (250 entrées, opcodes 0x0A-0x103)
- Dword offset table : RVA 0x9570C4
- **22 opcodes primaires gérés** : 0x0A, 0x0C, 0x16, 0x19, 0x2A, 0x33, 0x38, 0x4F, 0x56, 0x71, 0x86, 0x8B, 0xAA, 0xAD, 0xAE, 0xB4, 0xC7, 0xCB, 0xD4, 0xD5, 0xE5, 0x103
- ~40 opcodes secondaires (0x10A-0x0479) dans des sous-switches

### Phase 29 : Parsing ENet + KeyCheck
- Correction du masque flags byte : `& 0x0F` pour le type de commande
- Scan KeyCheck dans tous les body ≥ 32 bytes
- Le client envoie 64+ opcodes uniques en unreliable
- Ajout de SendReliableOnChannel pour envoyer sur des canaux ENet spécifiques
- Le client envoie opcode 0x2C (pas dans la table dispatcher → pas un game opcode)

### Phase 30 : Brute-force SynchVersion + framing multiple
- Envoi de SynchVersionS2C avec les 22 opcodes gérés → aucun effet
- Envoi via 3 méthodes (raw cmd=2, batch cmd=2, reliable channel 3) → aucun effet
- **Diagnostic : les paquets n'atteignent pas le dispatcher du client**
- Le consumer décompilé attend des records de 56 bytes avec opcode à byte 50
- Notre format batch ne correspond pas au framing interne du client

### Bilan Jour 5

| Étape | Statut | Détail |
|-------|--------|--------|
| 10. TLS cert verify | ❌ | 15 approches épuisées, Vanguard bloquetout |
| 11. Loading screen | ⏳ | Framing incorrect, packets n'atteignent pas le dispatcher |

### Statistiques Jour 5
- 15 approches TLS testées et documentées
- Certs TLS régénérés (CA + server signé, chaîne valide)
- Table d'opcodes complète extraite (22 + 40 opcodes)
- Parsing ENet amélioré (flags, reliable, unreliable)
- Consumer décompilé : 56-byte records, opcode at byte 50
- 3800+ paquets échangés par session, jeu stable 2+ minutes
- **Prochain objectif : capturer un vrai échange Riot pour reverse le framing exact**
