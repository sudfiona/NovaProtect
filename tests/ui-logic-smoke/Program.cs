// UI logic smoke test.
//
// Checks the behaviour of the scanned-function model that the protection page
// relies on.  The function list shows a protection type per row next to the
// checkbox; the two are two views of the same decision, so they have to move
// together:
//
//   * choosing a protection type checks the row,
//   * choosing "not protected" unchecks it - a checked row that is not
//     protected would look protected in the list while the packer would leave
//     the function alone,
//   * re-checking a skipped row restores a protection type.
//
// The real model sources are compiled into this project, so the check
// exercises the shipped code.
using NovaProtect.UI.Models;
using NovaProtect.UI.Services;

var failures = 0;

void Check(bool condition, string what)
{
    if (condition) Console.WriteLine($"[ OK ] {what}");
    else { Console.WriteLine($"[FAIL] {what}"); failures++; }
}

static ScannedFunction Sample(uint rva = 0x1000) =>
    new(rva, 512, ".text", "SampleFunction", false, false, "4889E5");

// 1. Choosing a protection type checks the row.
var item = new FunctionItem(Sample());
item.IsSelected = false;
item.Mode = MarkerProtectionMode.Mutation;
Check(item.IsSelected, "choosing a protection type checks the row");

// 2. Choosing "not protected" unchecks the row.
var skip = new FunctionItem(Sample());
skip.IsSelected = true;
skip.Mode = MarkerProtectionMode.Skip;
Check(!skip.IsSelected, "choosing 'not protected' unchecks the row");

// 3. Re-checking a row that was skipped restores a protection type.
var restored = new FunctionItem(Sample());
restored.Mode = MarkerProtectionMode.Skip;
restored.IsSelected = true;
Check(restored.Mode != MarkerProtectionMode.Skip,
      "re-checking a skipped row restores a protection type");
Check(restored.IsSelected, "re-checking a skipped row keeps it checked");

// 4. The protection type list offers the same four choices as the reference
//    product: none, virtualization, mutation, ultra.
var labels = FunctionItem.AllModeOptions.Select(o => o.Label).ToArray();
Check(labels.Length == 4, $"the protection type list has four entries (got {labels.Length})");
Check(labels.Contains("不保护") && labels.Contains("虚拟化") &&
      labels.Contains("变异") && labels.Contains("虚拟化+变异"),
      "the protection type list covers none / virtualization / mutation / ultra");

// 5. Every protection type maps to a packer rule that carries the choice.
foreach (var option in FunctionItem.AllModeOptions)
{
    var row = new FunctionItem(Sample());
    row.IsSelected = false;
    row.Mode = option.Mode;
    var rule = row.ToRule();
    Check(rule.Mode == option.Mode, $"the rule keeps the protection type '{option.Label}'");
}

// 6. The rule carries the per-function parameters.
var tuned = new FunctionItem(Sample(0x2000));
tuned.VmComplexity = 9;
tuned.MutationStrength = 3;
tuned.LockToActivation = true;
tuned.Mode = MarkerProtectionMode.Ultra;
var tunedRule = tuned.ToRule();
Check(tunedRule.StartRva == 0x2000 && tunedRule.EndRva == 0x2000 + 512,
      "the rule carries the function range");
Check(tunedRule.VmComplexity == 9 && tunedRule.MutationStrength == 3,
      "the rule carries the per-function VM and mutation strength");
Check(tunedRule.LockToActivation, "the rule carries the activation lock");

Console.WriteLine(failures == 0 ? "UI-LOGIC-OK" : $"UI-LOGIC-FAIL ({failures})");
return failures == 0 ? 0 : 1;
