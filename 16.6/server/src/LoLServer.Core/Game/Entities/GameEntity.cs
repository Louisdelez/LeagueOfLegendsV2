using System;
using LoLServer.Core.Config;

namespace LoLServer.Core.Game.Entities;

/// <summary>
/// Base class for all game entities (champions, minions, turrets, etc.)
/// </summary>
public abstract class GameEntity
{
    public uint Id { get; set; }
    public string Name { get; set; } = "";
    public TeamId Team { get; set; }
    public Vector3 Position { get; set; }
    public bool MarkedForRemoval { get; set; }
    public bool IsTargetable { get; set; } = true;

    public virtual void Update(float deltaTime, GameLoop game) { }
}

public interface IKillable
{
    float Health { get; set; }
    float MaxHealth { get; set; }
}

public interface IAttacker
{
    float AttackDamage { get; set; }
    float AttackRange { get; set; }
    float AttackSpeed { get; set; }
    float AttackCooldown { get; set; }
}

public interface IMovable
{
    float MoveSpeed { get; set; }
    Vector3? MoveTarget { get; set; }
}

/// <summary>
/// Simple 3D vector for positions.
/// </summary>
public struct Vector3
{
    public float X, Y, Z;

    public Vector3(float x, float y, float z)
    {
        X = x; Y = y; Z = z;
    }

    public float DistanceTo(Vector3 other)
    {
        var dx = X - other.X;
        var dy = Y - other.Y;
        var dz = Z - other.Z;
        return MathF.Sqrt(dx * dx + dy * dy + dz * dz);
    }

    public float Distance2D(Vector3 other)
    {
        var dx = X - other.X;
        var dz = Z - other.Z;
        return MathF.Sqrt(dx * dx + dz * dz);
    }

    public Vector3 DirectionTo(Vector3 target)
    {
        var dx = target.X - X;
        var dz = target.Z - Z;
        var len = MathF.Sqrt(dx * dx + dz * dz);
        if (len < 0.001f) return new Vector3(0, 0, 0);
        return new Vector3(dx / len, 0, dz / len);
    }

    public override string ToString() => $"({X:F1}, {Y:F1}, {Z:F1})";
}
