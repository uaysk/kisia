using System;
using System.Text.Json;
using UemAgent.Collectors;

class Program
{
    static void Main()
    {
        var collector = new OsInfoCollector();
        var snap = collector.Collect();

        var json = JsonSerializer.Serialize(snap, new JsonSerializerOptions { WriteIndented = true });
        Console.WriteLine(json);
        Console.WriteLine("\n완료. 아무키나 누르면 종료합니다.");
        Console.ReadKey();
    }
}
