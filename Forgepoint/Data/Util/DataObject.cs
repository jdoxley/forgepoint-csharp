namespace Forgepoint.Data.Util;

using Forgepoint.Data.Util.Interfaces;

public abstract class DataObject
{
    public DateTime LastEdit { get; set; }
}

public abstract class DataObject<T> : DataObject,
    IKeyable<T>,
    IComparable,
    IComparable<DataObject<T>>,
    IEquatable<DataObject<T>>
    where T : unmanaged, IComparable, IEquatable<T>
{
    public T Key { get; set; }
    public T GetKey()
        => Key;

    public override int GetHashCode()
        => Key.GetHashCode();

    public int CompareTo(object? obj)
        => CompareTo(obj as DataObject<T>);

    public int CompareTo(DataObject<T>? other)
        => Key.CompareTo(other?.Key);

    public bool Equals(DataObject<T>? other)
        => Key.Equals(other?.Key);

    public override bool Equals(object? obj)
    {
        if (ReferenceEquals(this, obj))
        {
            return true;
        }

        if (obj is null)
        {
            return false;
        }

        return Equals((DataObject<T>)obj);
    }

    public static bool operator ==(DataObject<T>? left, DataObject<T>? right)
    {
        if (left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }

    public static bool operator !=(DataObject<T>? left, DataObject<T>? right)
    {
        return !(left == right);
    }

    public static bool operator <(DataObject<T>? left, DataObject<T>? right)
    {
        return left is null ? right is not null : left.CompareTo(right) < 0;
    }

    public static bool operator <=(DataObject<T>? left, DataObject<T>? right)
    {
        return left is null || left.CompareTo(right) <= 0;
    }

    public static bool operator >(DataObject<T>? left, DataObject<T>? right)
    {
        return left is not null && left.CompareTo(right) > 0;
    }

    public static bool operator >=(DataObject<T>? left, DataObject<T>? right)
    {
        return left is null ? right is null : left.CompareTo(right) >= 0;
    }
}