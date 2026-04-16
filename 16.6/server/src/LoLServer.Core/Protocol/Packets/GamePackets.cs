using System;
using LoLServer.Core.Config;
using LoLServer.Core.Game.Combat;
using LoLServer.Core.Game.Entities;

namespace LoLServer.Core.Protocol.Packets;

/// <summary>
/// Factory for building all S2C game packets with proper binary layout.
/// </summary>
public static class GamePackets
{
    // ========== SPAWN PACKETS ==========

    /// <summary>
    /// CreateHeroS2C - Spawns a champion for a player.
    /// Sent during spawn sequence so the client creates the champion object.
    /// </summary>
    public static byte[] CreateHero(Champion champ, int playerNo)
    {
        var w = PacketWriter.CreateWithSender(GamePacketId.CreateHeroS2C, champ.Id);
        w.WriteUInt32(champ.Id);           // netId
        w.WriteUInt32((uint)playerNo);     // clientId / player number
        w.WriteByte(0);                    // netNodeID
        w.WriteByte(0);                    // skillLevel (0 = start)
        w.WriteBool(playerNo == 0);        // isBot (false for real players -- first player is you)
        w.WriteByte(0);                    // botRank
        w.WriteByte(0);                    // spawnPosIndex
        w.WriteInt32(champ.SkinId);        // skinID
        w.WriteFixedString(champ.SummonerName, 128);  // playerName
        w.WriteFixedString(champ.ChampionName, 40);    // championName
        w.WriteFloat(0);                   // deathDurationRemaining
        w.WriteFloat(0);                   // timeSinceDeath
        w.WriteUInt32(0);                  // flags
        // Summoner spells
        w.WriteUInt32(GetSummonerSpellHash(champ.SummonerSpell1));
        w.WriteUInt32(GetSummonerSpellHash(champ.SummonerSpell2));
        // Team
        w.WriteUInt32((uint)champ.Team);
        // Position
        w.WritePosition(champ.Position.X, champ.Position.Y, champ.Position.Z);
        return w.ToArray();
    }

    /// <summary>
    /// CreateTurretS2C - Spawns a turret.
    /// </summary>
    public static byte[] CreateTurret(Turret turret)
    {
        var w = PacketWriter.CreateWithSender(GamePacketId.CreateTurretS2C, turret.Id);
        w.WriteUInt32(turret.Id);
        w.WriteFixedString(turret.Name, 64);
        w.WriteUInt32((uint)turret.Team);
        w.WriteFloat(turret.Position.X);
        w.WriteFloat(turret.Position.Y);
        w.WriteFloat(turret.Position.Z);
        w.WriteFloat(turret.MaxHealth);
        w.WriteFloat(turret.Health);
        w.WriteFloat(turret.AttackDamage);
        w.WriteFloat(turret.AttackRange);
        w.WriteBool(turret.IsTargetable);
        return w.ToArray();
    }

    /// <summary>
    /// CreateMinionS2C - Spawns a minion.
    /// </summary>
    public static byte[] CreateMinion(Minion minion)
    {
        var w = PacketWriter.CreateWithSender(GamePacketId.CreateMinionS2C, minion.Id);
        w.WriteUInt32(minion.Id);
        w.WriteUInt32((uint)minion.Team);
        w.WriteByte((byte)minion.MinionType);
        w.WriteFixedString(minion.GetMinionName(), 64);
        w.WriteFloat(minion.Position.X);
        w.WriteFloat(minion.Position.Y);
        w.WriteFloat(minion.Position.Z);
        w.WriteFloat(minion.MaxHealth);
        w.WriteFloat(minion.Health);
        return w.ToArray();
    }

    // ========== MOVEMENT PACKETS ==========

    /// <summary>
    /// MovementS2C - Broadcasts an entity's movement/waypoint to all clients.
    /// </summary>
    public static byte[] Movement(uint netId, float x, float y, float z, float speed, MovementType moveType = MovementType.Waypoint)
    {
        var w = PacketWriter.CreateWithSender(GamePacketId.MovementS2C, netId);
        w.WriteByte((byte)moveType);
        w.WriteFloat(speed);
        w.WriteFloat(x);
        w.WriteFloat(y);
        w.WriteFloat(z);
        return w.ToArray();
    }

    /// <summary>
    /// WaypointListS2C - Send multiple waypoints for an entity.
    /// </summary>
    public static byte[] WaypointList(uint netId, float speed, Vector3[] waypoints)
    {
        var w = PacketWriter.CreateWithSender(GamePacketId.WaypointListS2C, netId);
        w.WriteFloat(speed);
        w.WriteInt32(waypoints.Length);
        foreach (var wp in waypoints)
        {
            w.WriteFloat(wp.X);
            w.WriteFloat(wp.Y);
            w.WriteFloat(wp.Z);
        }
        return w.ToArray();
    }

    // ========== COMBAT PACKETS ==========

    /// <summary>
    /// DamageDoneS2C - Notify clients that damage was dealt.
    /// </summary>
    public static byte[] DamageDone(uint sourceNetId, uint targetNetId, float amount, DamageType type)
    {
        var w = PacketWriter.CreateWithSender(GamePacketId.DamageDoneS2C, targetNetId);
        w.WriteUInt32(sourceNetId);
        w.WriteFloat(amount);
        w.WriteByte((byte)type);
        return w.ToArray();
    }

    /// <summary>
    /// SetHealthS2C - Update an entity's HP/MaxHP on clients.
    /// </summary>
    public static byte[] SetHealth(uint netId, float currentHp, float maxHp)
    {
        var w = PacketWriter.CreateWithSender(GamePacketId.SetHealthS2C, netId);
        w.WriteFloat(currentHp);
        w.WriteFloat(maxHp);
        return w.ToArray();
    }

    /// <summary>
    /// NpcDieS2C - Notify clients that an entity died.
    /// </summary>
    public static byte[] NpcDie(uint deadNetId, uint killerNetId)
    {
        var w = PacketWriter.CreateWithSender(GamePacketId.NpcDieS2C, deadNetId);
        w.WriteUInt32(killerNetId);
        w.WriteFloat(0); // deathTimer (filled in by client for champions)
        return w.ToArray();
    }

    /// <summary>
    /// NpcRespawnS2C - Champion respawned.
    /// </summary>
    public static byte[] NpcRespawn(uint netId, float x, float y, float z)
    {
        var w = PacketWriter.CreateWithSender(GamePacketId.NpcRespawnS2C, netId);
        w.WriteFloat(x);
        w.WriteFloat(y);
        w.WriteFloat(z);
        return w.ToArray();
    }

    // ========== STATS / ECONOMY ==========

    /// <summary>
    /// StatsUpdateS2C - Full stats sync for a champion.
    /// </summary>
    public static byte[] StatsUpdate(Champion champ)
    {
        var w = PacketWriter.CreateWithSender(GamePacketId.StatsUpdateS2C, champ.Id);
        w.WriteFloat(champ.Health);
        w.WriteFloat(champ.MaxHealth);
        w.WriteFloat(champ.Mana);
        w.WriteFloat(champ.MaxMana);
        w.WriteFloat(champ.AttackDamage);
        w.WriteFloat(champ.AbilityPower);
        w.WriteFloat(champ.Armor);
        w.WriteFloat(champ.MagicResist);
        w.WriteFloat(champ.AttackSpeed);
        w.WriteFloat(champ.MoveSpeed);
        w.WriteFloat(champ.CritChance);
        w.WriteFloat(champ.AbilityHaste);
        w.WriteFloat(champ.Lethality);
        w.WriteFloat(champ.ArmorPenPercent);
        w.WriteFloat(champ.MagicPenFlat);
        w.WriteFloat(champ.MagicPenPercent);
        w.WriteFloat(champ.Lifesteal);
        w.WriteFloat(champ.Omnivamp);
        w.WriteFloat(champ.Tenacity);
        w.WriteFloat(champ.Shield);
        w.WriteFloat(champ.HealthRegen);
        w.WriteFloat(champ.ManaRegen);
        w.WriteFloat(champ.AttackRange);
        w.WriteInt32(champ.Level);
        w.WriteFloat(champ.Experience);
        return w.ToArray();
    }

    /// <summary>
    /// LevelUpS2C - Champion leveled up.
    /// </summary>
    public static byte[] LevelUp(uint netId, int level, int skillPoints)
    {
        var w = PacketWriter.CreateWithSender(GamePacketId.LevelUpS2C, netId);
        w.WriteInt32(level);
        w.WriteInt32(skillPoints);
        return w.ToArray();
    }

    /// <summary>
    /// GoldUpdateS2C - Sync gold amount.
    /// </summary>
    public static byte[] GoldUpdate(uint netId, float gold)
    {
        var w = PacketWriter.CreateWithSender(GamePacketId.GoldUpdateS2C, netId);
        w.WriteFloat(gold);
        return w.ToArray();
    }

    /// <summary>
    /// ScoreboardUpdateS2C - Update KDA/CS for a champion.
    /// </summary>
    public static byte[] ScoreboardUpdate(Champion champ)
    {
        var w = PacketWriter.CreateWithSender(GamePacketId.ScoreboardUpdateS2C, champ.Id);
        w.WriteInt32(champ.Kills);
        w.WriteInt32(champ.Deaths);
        w.WriteInt32(champ.Assists);
        w.WriteInt32(champ.CreepScore);
        w.WriteFloat(champ.Gold);
        w.WriteInt32(champ.Level);
        return w.ToArray();
    }

    // ========== ITEMS ==========

    /// <summary>
    /// ItemBuyS2C - Confirm item purchase.
    /// </summary>
    public static byte[] ItemBuy(uint netId, int itemId, int slot, int stackCount)
    {
        var w = PacketWriter.CreateWithSender(GamePacketId.ItemBuyS2C, netId);
        w.WriteInt32(itemId);
        w.WriteByte((byte)slot);
        w.WriteByte((byte)stackCount);
        return w.ToArray();
    }

    /// <summary>
    /// InventoryUpdateS2C - Full inventory sync.
    /// </summary>
    public static byte[] InventoryUpdate(uint netId, int[] items)
    {
        var w = PacketWriter.CreateWithSender(GamePacketId.InventoryUpdateS2C, netId);
        for (int i = 0; i < 6; i++)
        {
            w.WriteInt32(i < items.Length ? items[i] : 0);
        }
        return w.ToArray();
    }

    // ========== ABILITIES ==========

    /// <summary>
    /// CastSpellS2C - Broadcast spell cast to clients.
    /// </summary>
    public static byte[] CastSpell(uint casterNetId, byte slot, float x, float y, float z, uint targetNetId)
    {
        var w = PacketWriter.CreateWithSender(GamePacketId.CastSpellS2C, casterNetId);
        w.WriteByte(slot);
        w.WriteFloat(x);
        w.WriteFloat(y);
        w.WriteFloat(z);
        w.WriteUInt32(targetNetId);
        return w.ToArray();
    }

    /// <summary>
    /// LevelUpSpellS2C - Confirm ability level up.
    /// </summary>
    public static byte[] LevelUpSpell(uint netId, byte slot, byte level)
    {
        var w = PacketWriter.CreateWithSender(GamePacketId.LevelUpSpellS2C, netId);
        w.WriteByte(slot);
        w.WriteByte(level);
        return w.ToArray();
    }

    /// <summary>
    /// SetCooldownS2C - Set ability cooldown on client.
    /// </summary>
    public static byte[] SetCooldown(uint netId, byte slot, float currentCd, float totalCd)
    {
        var w = PacketWriter.CreateWithSender(GamePacketId.SetCooldownS2C, netId);
        w.WriteByte(slot);
        w.WriteFloat(currentCd);
        w.WriteFloat(totalCd);
        return w.ToArray();
    }

    // ========== ANNOUNCEMENTS ==========

    /// <summary>
    /// AnnounceS2C - Send an announcement event.
    /// </summary>
    public static byte[] Announce(AnnounceEvent eventType, uint relatedNetId = 0, uint relatedNetId2 = 0)
    {
        var w = PacketWriter.Create(GamePacketId.AnnounceS2C);
        w.WriteByte((byte)eventType);
        w.WriteUInt32(relatedNetId);
        w.WriteUInt32(relatedNetId2);
        return w.ToArray();
    }

    // ========== PING ==========

    /// <summary>
    /// PingS2C - Broadcast a map ping to clients.
    /// </summary>
    public static byte[] Ping(uint senderNetId, float x, float y, byte pingType)
    {
        var w = PacketWriter.CreateWithSender(GamePacketId.PingS2C, senderNetId);
        w.WriteFloat(x);
        w.WriteFloat(y);
        w.WriteByte(pingType);
        return w.ToArray();
    }

    // ========== TIME SYNC ==========

    /// <summary>
    /// SyncClockS2C - Respond to client clock sync.
    /// </summary>
    public static byte[] SyncClock(float gameTime, uint clientSyncId)
    {
        var w = PacketWriter.Create(GamePacketId.SyncClockS2C);
        w.WriteFloat(gameTime);
        w.WriteUInt32(clientSyncId);
        return w.ToArray();
    }

    // ========== HELPERS ==========

    /// <summary>
    /// Hash a summoner spell name to its ID used in packets.
    /// </summary>
    public static uint GetSummonerSpellHash(string spellName)
    {
        return spellName switch
        {
            "SummonerFlash" => 0x04,
            "SummonerIgnite" => 0x0E,
            "SummonerHeal" => 0x07,
            "SummonerBarrier" => 0x15,
            "SummonerTeleport" => 0x0C,
            "SummonerSmite" => 0x0B,
            "SummonerExhaust" => 0x03,
            "SummonerCleanse" => 0x01,
            "SummonerGhost" => 0x06,
            _ => 0x00
        };
    }
}
