using System;
using LoLServer.Core.Game.Entities;

namespace LoLServer.Core.Game.Combat;

public enum DamageType
{
    Physical,
    Magic,
    True
}

/// <summary>
/// Calculates damage with armor/magic resist reduction.
/// Uses the standard LoL formula: damage * 100 / (100 + resistance)
/// </summary>
public static class DamageCalculator
{
    public static float CalculateDamage(float rawDamage, DamageType type, GameEntity target)
    {
        float resistance = 0;

        if (target is Champion champ)
        {
            resistance = type switch
            {
                DamageType.Physical => champ.Armor,
                DamageType.Magic => champ.MagicResist,
                DamageType.True => 0,
                _ => 0
            };
        }

        if (resistance >= 0)
        {
            // Positive resistance: damage reduction
            return rawDamage * 100f / (100f + resistance);
        }
        else
        {
            // Negative resistance: damage amplification
            return rawDamage * (2f - 100f / (100f - resistance));
        }
    }

    /// <summary>
    /// Apply auto-attack damage from attacker to target.
    /// </summary>
    public static float ApplyAutoAttack(GameEntity attacker, GameEntity target)
    {
        float ad = 0;
        if (attacker is IAttacker a) ad = a.AttackDamage;
        if (attacker is Champion c) ad = c.AttackDamage;
        if (attacker is Turret t) ad = t.AttackDamage;
        if (attacker is Minion m) ad = m.AttackDamage;

        float damage = CalculateDamage(ad, DamageType.Physical, target);

        if (target is IKillable killable)
        {
            killable.Health = MathF.Max(0, killable.Health - damage);
        }

        return damage;
    }
}
