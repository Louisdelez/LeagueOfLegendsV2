# League of Legends 4.20 Launcher - Documentation Complète

## Table des matières

1. [Architecture](#architecture)
2. [Technologies](#technologies)
3. [Écrans et fonctionnalités](#écrans-et-fonctionnalités)
4. [Flow utilisateur](#flow-utilisateur)
5. [Protocoles réseau](#protocoles-réseau)
6. [Design visuel](#design-visuel)
7. [Configuration technique](#configuration-technique)
8. [Projets communautaires](#projets-communautaires)
9. [Spécifications pour recréation](#spécifications-pour-recréation)

---

## Architecture

### Le modèle à 3 processus

Le système LoL 4.20 (fin 2014, Season 4/5) utilisait 3 applications séparées :

#### 1. LoLLauncher.exe / LoLPatcher.exe (Patcher)
- **Rôle** : Télécharger les mises à jour, vérifier l'intégrité des fichiers
- **Technologie** : Application native Win32
- **Système** : RADS (Riot Application Distribution System)
- **Emplacement** : `RADS/projects/lol_launcher/releases/*/deploy/`
- **Fonction** : Affiche une barre de progression, télécharge les patches, puis lance le client PVP.net

#### 2. PVP.net Client (lol_air_client)
- **Rôle** : Lobby, matchmaking, champion select, chat, store, profil
- **Technologie** : Adobe AIR (runtime Flash/ActionScript pour desktop)
- **Langage** : ActionScript 3 + MXML pour les layouts UI
- **Emplacement** : `RADS/projects/lol_air_client/releases/*/deploy/`
- **Runtime** : Adobe AIR bundlé avec l'installation
- **Fenêtre** : 1280x720 par défaut, non-redimensionnable
- **Réputation** : Lent, fuites mémoire, crashs fréquents (limitations du runtime Flash)

#### 3. League of Legends.exe (Game Client)
- **Rôle** : Rendu 3D, gameplay, loading screen, HUD in-game
- **Technologie** : C++ natif, DirectX 9
- **Architecture** : 32-bit (limite 2047MB de RAM virtuelle)
- **Emplacement** : `RADS/solutions/lol_game_client_sln/releases/0.0.1.68/deploy/`
- **Réseau** : ENet UDP modifié (LENet) + chiffrement Blowfish ECB

### Communication inter-processus

```
LoLLauncher ──lance──> PVP.net Client ──lance──> League of Legends.exe
                            │                         │
                            │ RTMP/XMPP/HTTP          │ ENet/Blowfish
                            │                         │
                       Serveurs Riot            Serveur de jeu
                    (plateforme/chat)           (GameServer)
```

Le PVP.net Client lance le Game Client via ligne de commande :
```
"League of Legends.exe" "8394" "LoLLauncher.exe" "" "IP PORT BLOWFISH_KEY PLAYER_ID"
```

---

## Technologies

### PVP.net Client (Launcher)

| Composant | Technologie |
|-----------|------------|
| Runtime | Adobe AIR 3.x |
| Langage | ActionScript 3 (Flash) |
| UI Layout | MXML (XML-based markup) |
| Rendu | Flash Player (vector/bitmap) |
| Réseau jeu | RTMP over TLS (RTMPS) |
| Chat | XMPP (Jabber) over TLS |
| Store/Data | HTTPS REST |
| Sérialisation | AMF (Action Message Format) |

### Game Client

| Composant | Technologie |
|-----------|------------|
| Langage | C++ natif |
| Graphiques | DirectX 9 |
| Réseau | LENet (ENet modifié, UDP) |
| Chiffrement | Blowfish ECB par joueur |
| Audio | FMOD |
| Physique | Custom (pas de middleware) |

### RADS (Riot Application Distribution System)

| Composant | Description |
|-----------|------------|
| lol_launcher | Launcher externe (patcher) |
| lol_patcher | Téléchargement des données |
| lol_air_client | Client PVP.net (Adobe AIR) |
| lol_game_client | Binaire du jeu |
| lol_game_client_sln | Solution complète (exe + assets) |

---

## Écrans et fonctionnalités

### 1. Écran de login

**Description** : Premier écran après le patcher. Fond sombre avec logo LoL animé.

**Éléments** :
- Logo League of Legends centré en haut (animé, particules)
- Champ "Nom d'invocateur" (username)
- Champ "Mot de passe"
- Case "Se souvenir de moi"
- Bouton "Se connecter" (doré)
- Sélecteur de région (dropdown : NA, EUW, EUNE, KR, etc.)
- Numéro de version en bas à gauche
- Liens : "Mot de passe oublié ?", "Créer un compte"
- Indicateur de file d'attente si serveurs surchargés

**Comportement** :
- Authentification RTMPS vers le serveur de plateforme régional
- Connexion XMPP établie après login (pour chat/friends)
- Chargement du profil invocateur depuis le serveur
- Transition vers la page d'accueil après connexion réussie

### 2. Page d'accueil (Home)

**Description** : Hub principal après connexion.

**Layout** :
```
┌─────────────────────────────────────────────────────┐
│ [HOME] [PROFIL] [COLLECTION] [STORE]    IP:3150 RP:0│
│                                                     │
│  ┌─── Bannière news/événements (carousel) ───┐     │
│  │                                            │     │
│  │   NOUVEAU CHAMPION : AZIR                  │     │
│  │   Disponible maintenant !                  │     │
│  └────────────────────────────────────────────┘     │
│                                                     │
│  ┌──────────────────┐  ┌─── Liste d'amis ────┐     │
│  │                  │  │ ● Joueur1 (En jeu)  │     │
│  │  [  JOUER  ]     │  │ ● Joueur2 (En ligne)│     │
│  │                  │  │ ○ Joueur3 (Hors l.) │     │
│  │  Match récent:   │  │                     │     │
│  │  Ezreal 12/3/8   │  │ [Inviter]           │     │
│  └──────────────────┘  └─────────────────────┘     │
│                                                     │
│ [Status: En ligne ▼]              [Version 4.20.315]│
└─────────────────────────────────────────────────────┘
```

**Éléments** :
- Barre de navigation en haut (HOME, PROFIL, COLLECTION, STORE)
- Bannière rotative : news, nouveaux champions, skins, esports
- Bouton JOUER (gros, doré, centré, animation pulsante)
- IP (Influence Points) et RP (Riot Points) affichés en haut à droite
- Nom d'invocateur + icône en haut à droite
- Liste d'amis sur le côté droit (toujours visible)
- Historique de match récent en widget
- Notification de statut serveur

### 3. Sélection du mode de jeu

**Modes disponibles** :
- **Normal (Blind Pick)** : 5v5 Summoner's Rift, picks simultanés
- **Normal (Draft Pick)** : 5v5 SR, bans + picks alternés
- **Ranked Solo/Duo** : classement individuel
- **Ranked Team 3v3** : équipe pré-faite, Twisted Treeline
- **Ranked Team 5v5** : équipe pré-faite, SR
- **ARAM** : All Random All Mid, Howling Abyss
- **Co-op vs IA** : contre bots (Beginner/Intermediate)
- **Partie personnalisée** : créer/rejoindre un lobby custom
- **Mode du moment** : rotatif (URF, One-for-All, Hexakill, etc.)

**Maps disponibles** :
- Summoner's Rift (Map 1 ou Map 11) — 5v5
- Twisted Treeline (Map 10) — 3v3
- Howling Abyss (Map 12) — ARAM
- Crystal Scar (Map 8) — Dominion (retiré plus tard)

### 4. Champion Select

#### Mode Blind Pick
```
┌─────────────────────────────────────────────────────┐
│                CHAMPION SELECT (1:30)                │
│                                                     │
│ ┌─────────────────────────────────────────────┐     │
│ │ [Rechercher champion...]  [Assassin▼][Mage▼]│     │
│ │ ┌──┐┌──┐┌──┐┌──┐┌──┐┌──┐┌──┐┌──┐┌──┐┌──┐ │     │
│ │ │Ah││An││As││Az││Bl││Br││Ca││Co││Da││Dr│ │     │
│ │ └──┘└──┘└──┘└──┘└──┘└──┘└──┘└──┘└──┘└──┘ │     │
│ │ ┌──┐┌──┐┌──┐┌──┐┌──┐┌──┐┌──┐┌──┐┌──┐┌──┐ │     │
│ │ │Ez││Fi││Ga││Gn││He││Ir││Ja││Ji││Ka││Kh│ │     │
│ │ └──┘└──┘└──┘└──┘└──┘└──┘└──┘└──┘└──┘└──┘ │     │
│ └─────────────────────────────────────────────┘     │
│                                                     │
│ ┌─ Votre équipe ─┐          ┌─ Sorts d'invoc. ─┐   │
│ │ 1. [Ezreal]    │          │ [Flash] [Heal]    │   │
│ │ 2. [???]       │          │                   │   │
│ │ 3. [???]       │          │ Page de runes: ▼  │   │
│ │ 4. [???]       │          │ Masteries: ▼      │   │
│ │ 5. [???]       │          │                   │   │
│ └────────────────┘          │ [VERROUILLER]     │   │
│                              └───────────────────┘   │
│ ┌─── Chat ─────────────────────────────────────┐    │
│ │                                               │    │
│ └───────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

#### Mode Draft Pick
- Phase de bans : chaque équipe ban 3 champions (alternés)
- Phase de picks : 1-2-2-2-2-1 (alternés)
- Timer par phase (30s ban, 30s pick)
- Champion verrouillé visible par tous
- Échange possible entre coéquipiers après les picks

**Fonctionnalités** :
- Grille de champions (filtrable par rôle, nom)
- Splash art du champion sélectionné
- Sélecteur de skin (après verrouillage)
- 2 sorts d'invocateur (dropdown)
- Sélecteur de page de runes (dropdown)
- Sélecteur de page de masteries (dropdown)
- Bouton "Verrouiller" (Lock In)
- Chat d'équipe en bas
- Timer countdown visible

### 5. Page de profil

**Sous-onglets** :
- **Résumé** : icône, nom, niveau, stats ranked
- **Champions** : grille des champions possédés
- **Historique** : liste des matchs récents (expandable)
- **Ligues** : classement ranked (Bronze → Challenger)
- **Runes** : pages de runes
- **Masteries** : pages de masteries

**Ranked** :
- Badge du tier (emblème métallique orné)
- LP (League Points)
- W/L (Victoires/Défaites)
- Séries de promotion (Bo3/Bo5)
- Division (I, II, III, IV, V)

### 6. Page de runes

```
┌─────────────────────────────────────────────────────┐
│ PAGE DE RUNES : [AD Standard ▼]    [Sauvegarder]    │
│                                                     │
│ ┌─── Marques (9) ───┐  ┌─── Aperçu stats ────┐    │
│ │ ● ● ● ● ● ● ● ● ●│  │ +8.5 AD             │    │
│ │ AD +0.95 chacune   │  │ +12.7 Armor         │    │
│ └────────────────────┘  │ +12.1 MR            │    │
│ ┌─── Sceaux (9) ────┐  │ +4.3% AS            │    │
│ │ ● ● ● ● ● ● ● ● ●│  └─────────────────────┘    │
│ │ Armor +1.41 chacun │                              │
│ └────────────────────┘                              │
│ ┌─── Glyphes (9) ───┐                              │
│ │ ● ● ● ● ● ● ● ● ●│                              │
│ │ MR +1.34 chacun    │                              │
│ └────────────────────┘                              │
│ ┌─── Quintessences (3)──┐                           │
│ │ ◆ ◆ ◆                 │                           │
│ │ AS +1.42% chacune     │                           │
│ └────────────────────────┘                           │
└─────────────────────────────────────────────────────┘
```

**Système** :
- 2 pages de runes par défaut (achetable jusqu'à 20)
- 9 Marques (rouges) — offensif (AD, armor pen, magic pen)
- 9 Sceaux (jaunes) — défensif (armor, HP, HP/level)
- 9 Glyphes (bleus) — magique (MR, AP, CDR)
- 3 Quintessences (violettes) — polyvalent (AD, AP, AS, MS)
- Tier 1, 2, 3 (seul Tier 3 utilisé en ranked)
- Aperçu des stats cumulées à droite

**IDs de runes (GameInfo.json)** :
- Slots 1-9 : Marques
- Slots 10-18 : Sceaux
- Slots 19-27 : Glyphes
- Slots 28-30 : Quintessences
- Exemple : 5245 (AD Mark), 5317 (Armor Seal), 5289 (MR Glyph), 5335 (AS Quint)

### 7. Page de masteries

```
┌─────────────────────────────────────────────────────┐
│ MASTERIES : [AD Carry ▼]  Points: 21/9/0            │
│                                                     │
│  OFFENSE (21)    DEFENSE (9)     UTILITY (0)        │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐       │
│  │ [2]Fury  │   │ [2]Block │   │ [ ]Fleet │       │
│  │ [2]Sorc  │   │ [2]Recov │   │ [ ]Medit │       │
│  │ [1]Brute │   │ [1]Tough │   │ [ ]Scout │       │
│  │ [3]Spell │   │ [3]Veter │   │          │       │
│  │ [1]Arcane│   │ [1]Jugge │   │          │       │
│  │ [3]Warlor│   │          │   │          │       │
│  │ [1]Havoc │   │          │   │          │       │
│  │ ...      │   │          │   │          │       │
│  └──────────┘   └──────────┘   └──────────┘       │
│                                                     │
│ [Sauvegarder]  [Réinitialiser]                     │
└─────────────────────────────────────────────────────┘
```

**Système** :
- 30 points à distribuer
- 3 arbres : Offense, Defense, Utility
- Chaque arbre : ~6 rangées de talents
- Points dans une rangée débloquent la rangée suivante
- Masteries notables Season 4 : Warlord, Havoc, Juggernaut, Runic Shield
- Multiples pages sauvegardables

**IDs de masteries (GameInfo.json)** :
- Format : `4XYZ` où X=arbre (1=offense, 2=defense, 3=utility), YZ=position
- Exemple : 4111 (Fury), 4112 (Sorcery), 4114 (Brute Force)

### 8. Store

**Sections** :
- Champions (achat IP ou RP)
- Skins (RP uniquement)
- Wards (RP)
- Boosts (XP/IP)
- Bundles (packs)
- Promotions (rotation 3 jours)

**Prix champions** :
- 450 IP / 260 RP (très anciens)
- 1350 IP / 585 RP
- 3150 IP / 790 RP
- 4800 IP / 880 RP
- 6300 IP / 975 RP (récents)

### 9. Loading Screen

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐     │
│  │Splash│ │Splash│ │Splash│ │Splash│ │Splash│     │
│  │ Art  │ │ Art  │ │ Art  │ │ Art  │ │ Art  │     │
│  │  J1  │ │  J2  │ │  J3  │ │  J4  │ │  J5  │     │
│  ├──────┤ ├──────┤ ├──────┤ ├──────┤ ├──────┤     │
│  │ Nom  │ │ Nom  │ │ Nom  │ │ Nom  │ │ Nom  │     │
│  │██85%█│ │█100%█│ │██72%█│ │█100%█│ │██90%█│     │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘     │
│                                                     │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐     │
│  │Splash│ │Splash│ │Splash│ │Splash│ │Splash│     │
│  │ Art  │ │ Art  │ │ Art  │ │ Art  │ │ Art  │     │
│  │  E1  │ │  E2  │ │  E3  │ │  E4  │ │  E5  │     │
│  ├──────┤ ├──────┤ ├──────┤ ├──────┤ ├──────┤     │
│  │ Nom  │ │ Nom  │ │ Nom  │ │ Nom  │ │ Nom  │     │
│  │█100%█│ │██95%█│ │█100%█│ │██88%█│ │█100%█│     │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘     │
│                                                     │
│  Astuce: Appuyez sur Tab pour voir le scoreboard    │
│                                  Version 4.20.0.315 │
└─────────────────────────────────────────────────────┘
```

**Éléments** :
- 5 joueurs par équipe, alignés horizontalement
- Splash art du champion (skin sélectionné)
- Nom d'invocateur sous le splash
- Barre de chargement individuelle (0-100%)
- Icône de rang (Bronze→Challenger) à côté du nom
- Astuce aléatoire en bas
- Version du jeu en bas à droite
- Fond : thème de la map (SR=vert/bleu, TT=sombre/violet)

### 10. Post-game

**Onglets** :
- **Résumé** : KDA, CS, gold, level de chaque joueur
- **Graphiques** : dégâts infligés, gold par temps, etc.
- **Avancé** : stats détaillées (dégâts aux tourettes, vision, CC)

**Actions** :
- Honorer un adversaire (Honorable Opponent)
- Honorer un coéquipier (Friendly, Helpful, Teamwork)
- Signaler un joueur
- Ajouter en ami
- Rejouer / Quitter

---

## Flow utilisateur complet

```
1. Lancer LoLLauncher.exe
   │
2. Patcher vérifie les mises à jour
   │ (barre de progression)
   │
3. PVP.net Client se lance (Adobe AIR)
   │
4. Écran de login
   │ (RTMPS auth → serveur plateforme)
   │ (XMPP connect → serveur chat)
   │
5. Page d'accueil
   │
6. Clic sur [JOUER]
   │
7. Sélection du mode de jeu
   │ (Normal/Ranked/ARAM/Custom/Co-op)
   │
8. File d'attente (matchmaking)
   │ (temps d'attente estimé)
   │
9. "Match trouvé !" → [Accepter] / [Refuser]
   │ (10 secondes pour accepter)
   │
10. Champion Select
    │ (bans si draft, puis picks)
    │ (choix sorts, runes, masteries)
    │ (verrouillage du champion)
    │
11. PVP.net lance League of Legends.exe
    │ args: "8394" "LoLLauncher.exe" "" "IP PORT KEY ID"
    │
12. Loading Screen
    │ (ENet handshake, Blowfish auth)
    │ (chargement assets, splash arts)
    │
13. In-Game
    │ (gameplay 20-60 minutes)
    │
14. Nexus détruit / Surrender
    │
15. Post-game stats
    │ (honneur, report, stats)
    │
16. Retour au PVP.net Client (étape 5)
```

---

## Protocoles réseau

### RTMP/RTMPS (PVP.net → Riot Platform)

**Protocole** : Real-Time Messaging Protocol over TLS
**Port** : 2099 (RTMPS)
**Sérialisation** : AMF3 (Action Message Format)

**Services exposés** :
| Service | Fonction |
|---------|----------|
| `loginService` | Authentification |
| `summonerService` | Profil invocateur |
| `gameService` | Création/gestion de partie |
| `matchmakerService` | File d'attente matchmaking |
| `inventoryService` | Champions/skins possédés |
| `masteryBookService` | Pages de masteries |
| `spellBookService` | Sorts d'invocateur |
| `summonerRuneService` | Pages de runes |
| `statisticsService` | Stats de match |
| `leaguesService` | Classement ranked |

**Endpoints par région** :
- NA: `prod.na1.lol.riotgames.com:2099`
- EUW: `prod.euw1.lol.riotgames.com:2099`
- EUNE: `prod.eun1.lol.riotgames.com:2099`
- KR: `prod.kr.lol.riotgames.com:2099`

### XMPP (Chat/Friends)

**Protocole** : XMPP (Jabber) over TLS
**Port** : 5223
**Fonctions** :
- Liste d'amis (roster)
- Statut en ligne/hors-ligne/en jeu
- Messages privés
- Invitations de jeu
- Groupes d'amis

### ENet/LENet (Game Client → Game Server)

**Protocole** : UDP modifié (ENet avec patches Riot = LENet)
**Port** : 5119 (configurable)
**Chiffrement** : Blowfish ECB par joueur

**Version 4.20 LENet** :
- MaxPeerID: 0x7F (127 peers max)
- Checksum: CRC32 (4 bytes send, 4 bytes receive)
- MaxHeaderSize: 4 bytes base

**Canaux** :
| Canal | Nom | Usage |
|-------|-----|-------|
| 0 | CHL_HANDSHAKE | Authentification KeyCheck |
| 1 | CHL_C2S | Client → Serveur (inputs) |
| 2 | CHL_GAMEPLAY | Synchro horloge |
| 3 | CHL_S2C | Serveur → Client (état jeu) |
| 4 | CHL_LOW_PRIORITY | Non-critique |
| 5 | CHL_COMMUNICATION | Chat in-game |
| 6 | CHL_QUICK_CHAT | Pings/signaux |
| 7 | CHL_LOADING_SCREEN | Données loading screen |

**Handshake** :
```
1. Client → Serveur : ENet CONNECT
2. Serveur → Client : ENet VERIFY_CONNECT
3. Client → Serveur : KeyCheck packet (canal 0)
   - Action (1B) + padding (3B)
   - ClientID (4B, int32)
   - PlayerID (8B, int64)
   - VersionNumber (4B, uint32)
   - CheckSum (8B, uint64) — chiffré Blowfish
4. Serveur → Client : KeyCheck response
5. Client → Serveur : SpawnRequest
6. Serveur → Client : Map spawn + CreateHero + TimeSync
7. Client → Serveur : StartGame
8. Gameplay commence
```

---

## Design visuel

### Palette de couleurs

| Élément | Couleur | Hex |
|---------|---------|-----|
| Fond principal | Bleu-noir très foncé | #0A1428 |
| Fond secondaire | Bleu marine | #010A13 |
| Or principal | Or chaud | #C8AA6E |
| Or foncé | Bronze | #785A28 |
| Texte principal | Beige clair | #F0E6D2 |
| Texte secondaire | Gris-beige | #A09B8C |
| Accent bleu | Teal | #0397AB |
| Bouton hover | Or lumineux | #F0C75E |
| Erreur/ennemi | Rouge | #C6443E |
| Succès/allié | Bleu clair | #4488FF |
| Fond carte | Gris foncé | #1E2328 |

### Typographie

- **Titres** : Police serif ornée (style "Beaufort" ou précurseur)
- **Corps** : Sans-serif clean (style "Spiegel" ou précurseur)
- **Taille titre** : 18-24px
- **Taille corps** : 12-14px
- **Couleur titre** : Or (#C8AA6E)
- **Couleur corps** : Beige (#F0E6D2)

### Éléments visuels

- **Bordures** : Filigrane doré, ornements aux coins
- **Boutons** : Rectangle arrondi, bordure dorée, fond dégradé sombre
- **Hover** : Effet de lueur dorée
- **Scrollbars** : Rail doré fin
- **Fonds** : Textures subtiles (hexagones, cuir, métal brossé)
- **Ombres** : Drop shadows sur les panneaux flottants
- **Séparateurs** : Lignes dorées fines horizontales
- **Icônes** : Style dessiné à la main, palette sombre avec accents or

### Différences avec le client moderne (post-2016)

| Ancien (4.20) | Moderne |
|---------------|---------|
| Adobe AIR / Flash | Electron / Chromium |
| 1280x720 fixe | Redimensionnable |
| Or/bronze thème | Bleu/blanc thème |
| Animations simples | Animations 3D champions |
| Pas de loot/hextech | Hextech crafting |
| Pas de practice tool | Practice tool |
| Pas de Clash | Clash |
| Runes achetables | Runes gratuites (rework S8) |
| 30 masteries points | Runes Reforged |
| 3 bans par équipe | 5 bans par équipe |

---

## Configuration technique

### GameInfo.json (configuration de partie)

```json
{
    "players": [
        {
            "playerId": 1,
            "blowfishKey": "17BLOhi6KZsTtldTsizvHg==",
            "rank": "DIAMOND",
            "name": "Player1",
            "champion": "Ezreal",
            "team": "BLUE",
            "skin": 0,
            "summoner1": "SummonerFlash",
            "summoner2": "SummonerHeal",
            "ribbon": 2,
            "icon": 0,
            "runes": {
                "1": 5245, "2": 5245, "3": 5245,
                "4": 5245, "5": 5245, "6": 5245,
                "7": 5245, "8": 5245, "9": 5245,
                "10": 5317, "11": 5317, "12": 5317,
                "13": 5317, "14": 5317, "15": 5317,
                "16": 5317, "17": 5317, "18": 5317,
                "19": 5289, "20": 5289, "21": 5289,
                "22": 5289, "23": 5289, "24": 5289,
                "25": 5289, "26": 5289, "27": 5289,
                "28": 5335, "29": 5335, "30": 5335
            },
            "talents": {
                "4111": 1, "4112": 3, "4114": 1,
                "4122": 3, "4124": 1, "4132": 1,
                "4134": 3, "4142": 3, "4151": 1,
                "4152": 1, "4162": 1,
                "4211": 2, "4212": 2, "4213": 2,
                "4221": 1, "4222": 1
            }
        }
    ],
    "gameInfo": {
        "GAME_ID": 1,
        "GAME_NAME": "LeagueSandbox",
        "GAME_TYPE": "CUSTOM_GAME",
        "GAME_MAP": "SummonersRift",
        "GAME_MODE": "CLASSIC",
        "GAME_MUTATORS": "",
        "NONENTITY_HERO_MODE": false
    },
    "game": {
        "map": 11,
        "dataPackage": "LeagueSandbox-Default",
        "MANACOSTS_ENABLED": true,
        "COOLDOWNS_ENABLED": true,
        "CHEATS_ENABLED": false,
        "MINION_SPAWNS_ENABLED": true,
        "forcedStart": 5
    }
}
```

### Maps disponibles

| ID | Nom | Mode | Joueurs |
|----|-----|------|---------|
| 1 | Summoner's Rift (ancien) | Classic | 5v5 |
| 8 | Crystal Scar | Dominion | 5v5 |
| 10 | Twisted Treeline | Classic | 3v3 |
| 11 | Summoner's Rift (nouveau) | Classic | 5v5 |
| 12 | Howling Abyss | ARAM | 5v5 |

### Sorts d'invocateur

| Nom interne | Nom FR | Cooldown |
|-------------|--------|----------|
| SummonerFlash | Flash | 300s |
| SummonerHeal | Soin | 240s |
| SummonerBarrier | Barrière | 210s |
| SummonerDot | Ignition | 210s |
| SummonerExhaust | Épuisement | 210s |
| SummonerHaste | Fantôme | 210s |
| SummonerSmite | Châtiment | 60s |
| SummonerTeleport | Téléportation | 300s |
| SummonerBoost | Purification | 210s |
| SummonerRevive | Résurrection | 540s |
| SummonerClairvoyance | Clairvoyance | 60s |
| SummonerMana | Clarté | 180s |

### Champions (liste partielle Season 4)

120+ champions disponibles en patch 4.20, incluant :
Ahri, Akali, Alistar, Amumu, Anivia, Annie, Ashe, Azir, Blitzcrank, Brand, Braum, Caitlyn, Cassiopeia, Cho'Gath, Corki, Darius, Diana, Dr. Mundo, Draven, Elise, Evelynn, Ezreal, Fiddlesticks, Fiora, Fizz, Galio, Gangplank, Garen, Gnar, Gragas, Graves, Hecarim, Heimerdinger, Irelia, Janna, Jarvan IV, Jax, Jayce, Jinx, Kalista, Karma, Karthus, Kassadin, Katarina, Kayle, Kennen, Kha'Zix, Kog'Maw, LeBlanc, Lee Sin, Leona, Lissandra, Lucian, Lulu, Lux, Malphite, Malzahar, Maokai, Master Yi, Miss Fortune, Mordekaiser, Morgana, Nami, Nasus, Nautilus, Nidalee, Nocturne, Nunu, Olaf, Orianna, Pantheon, Poppy, Quinn, Rammus, Rek'Sai, Renekton, Rengar, Riven, Rumble, Ryze, Sejuani, Shaco, Shen, Shyvana, Singed, Sion, Sivir, Skarner, Sona, Soraka, Swain, Syndra, Talon, Taric, Teemo, Thresh, Tristana, Trundle, Tryndamere, Twisted Fate, Twitch, Udyr, Urgot, Varus, Vayne, Veigar, Vel'Koz, Vi, Viktor, Vladimir, Volibear, Warwick, Wukong, Xerath, Xin Zhao, Yasuo, Yorick, Zac, Zed, Ziggs, Zilean, Zyra

---

## Projets communautaires

### Wintermint (2013-2014)
- Créé par **Astralfoxy**
- Remplacement complet du client PVP.net
- Technologie : C# + WPF (Windows Presentation Foundation)
- Interface ultra-rapide comparée à l'AIR client
- Riot a embauché Astralfoxy et fermé le projet
- Code jamais open-sourcé
- Inspiré le développement du nouveau client (League Client Update)

### LeagueSandbox
- Serveur de jeu 4.20 open-source
- C# + .NET
- Implémente le protocole ENet/Blowfish
- Pas de launcher inclus — lancement via ligne de commande
- Repository : github.com/LeagueSandbox/GameServer

### Bibliothèques RTMP communautaires
- **LoLRTMPSClient** (Java) — client RTMP reverse-engineered
- **lol-rtmp-lib** — implémentations dans divers langages
- Permettent de simuler les appels du PVP.net client

### CommunityDragon
- Archive d'assets du client LoL (images, sons, données)
- Contient des captures du vieux client AIR
- Utile pour récupérer les textures/icônes

---

## Spécifications pour recréation en Rust

### Ce que le launcher doit faire

1. **Interface utilisateur** : thème bleu/or LoL
2. **Configuration** :
   - Choix du champion (dropdown avec portraits)
   - Choix de la map (SR, TT, ARAM)
   - Choix de l'équipe (Blue/Red)
   - Choix des sorts d'invocateur
   - Configuration des runes (optionnel)
   - Configuration des masteries (optionnel)
3. **Gestion** :
   - Générer le GameInfo.json
   - Lancer le serveur (GameServerConsole.dll)
   - Lancer le client (League of Legends.exe avec args)
4. **Multi-joueur** (futur) :
   - Lobby réseau local
   - Chat XMPP simplifié
   - Matchmaking basique

### Stack technique suggéré

```
Rust
├── egui ou iced (UI native)
├── serde_json (GameInfo.json)
├── std::process::Command (lancement serveur/client)
├── base64 (clé Blowfish)
├── image (portraits champions)
└── tokio (async pour multi-joueur futur)
```

### Structure du projet

```
launcher/
├── src/
│   ├── main.rs
│   ├── ui/
│   │   ├── login.rs
│   │   ├── home.rs
│   │   ├── champion_select.rs
│   │   └── theme.rs
│   ├── config/
│   │   ├── game_info.rs
│   │   └── champions.rs
│   └── launcher/
│       ├── server.rs
│       └── client.rs
├── assets/
│   ├── champions/ (portraits)
│   ├── icons/ (sorts, items)
│   └── fonts/
├── Cargo.toml
└── README.md
```
