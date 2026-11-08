using NovaProtect.UI.Services;

foreach (var path in args)
{
    var result = FunctionScanner.Scan(path);
    Console.WriteLine($"=== {Path.GetFileName(path)}");
    if (!result.Success) { Console.WriteLine($"  FAILED: {result.Error}"); continue; }
    var fns = result.Functions;
    Console.WriteLine($"  total={fns.Count} src={result.Source}");
    Console.WriteLine($"  distinctName={fns.Select(f=>f.Name).Distinct().Count()} distinctRva={fns.Select(f=>f.Rva).Distinct().Count()} distinctRange={fns.Select(f=>f.AddressRange).Distinct().Count()}");
    Console.WriteLine($"  exported={fns.Count(f=>f.IsExported)} zeroSize={fns.Count(f=>f.Size==0)} feasible={fns.Count(f=>f.VmFeasible)}");
    var dupName = fns.GroupBy(f => f.Name).Where(g => g.Count() > 1).OrderByDescending(g => g.Count()).ToList();
    if (dupName.Count > 0) {
        Console.WriteLine($"  !! dupNameGroups={dupName.Count}");
        foreach (var g in dupName.Take(3))
            Console.WriteLine($"     x{g.Count()}: '{g.Key}' rvAs=[{string.Join(",", g.Take(4).Select(x=>$"0x{x.Rva:X}"))}]");
    }
    Console.WriteLine($"  first6: {string.Join(" | ", fns.Take(6).Select(f => $"{f.Name}@{f.Rva:X}/{f.Size}"))}");
}
