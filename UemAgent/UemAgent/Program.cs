using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using UemAgent.Collectors;

class Program
{
    static void Main()
    {
        var collector = new OsInfoCollector();
        var snap = collector.Collect();

        //Virtual machine ��ȣ ����
        snap.Vm = VmDetector.Detect();

        //���� ���α׷� ��ȣ ����
        snap.Av = AvDetector.Detect();

        if(snap.Av?.Products != null)
        {
            foreach (var p in snap.Av.Products)
            {
                switch (p.VendorGuess)
                {
                    case "alyac": p.Name = "Alyac"; break;
                    case "v3": p.Name = "AnhLab_V3"; break;
                    case "microsoft-defender": p.Name="MS_Defender"; break;
                }
            }
        }
        var json = JsonSerializer.Serialize(snap, new JsonSerializerOptions { WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        });

        Console.WriteLine(json);
        Console.WriteLine("\n�Ϸ�. �ƹ�Ű�� ������ �����մϴ�.");
        Console.ReadKey();
    }
}
