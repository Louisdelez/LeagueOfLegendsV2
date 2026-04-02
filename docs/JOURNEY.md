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

### Statistiques
- ~50 scripts Ghidra écrits et exécutés
- ~15 variantes du hook DLL compilées et testées
- ~40 combinaisons IV/mode crypto testées
- 8+ méthodes de bypass CRC tentées
- 67 MB de trafic réel capturé
- Double CFB + CRC nonce reverse-engineered depuis le binaire
