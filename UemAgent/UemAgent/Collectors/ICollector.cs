namespace UemAgent.Collectors
{
    public interface ICollector<TModle>
    {
        // 데이터 수집기 모델 반환
        string Name { get; } // os, vm, av
        TModle Collect(); // 
    }
}
