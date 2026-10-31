using System;

namespace JsILNET.Fixture;

[AttributeUsage(AttributeTargets.Class)]
public sealed class MarkerAttribute(string value) : Attribute
{
    public string Value { get; } = value;
}

[Marker("sample")]
public class Sample<T> : IDisposable where T : class, new()
{
    public event EventHandler? Changed;
    public int Value { get; set; }

    public static string Greeting() => "hello";
    public static string Farewell() => "goodbye";
    public static int Answer() => 42;
    public static int SmallConstant() => 2;
    public static int AddOne(int value) => value + 1;
    public int Finally(int value)
    {
        try { return value + 1; }
        finally { Value = value; }
    }

    public void Dispose() => Changed?.Invoke(this, EventArgs.Empty);
}
