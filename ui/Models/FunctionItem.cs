using System.ComponentModel;
using System.Runtime.CompilerServices;
using NovaProtect.UI.Models;
using NovaProtect.UI.Services;

namespace NovaProtect.UI.Models;

// One entry of the per-function protection type list.  The label is what the
// user reads; the value is what the packer receives.  The Chinese source is kept
// in the record and translated on read, because this list is static: translating
// at construction would freeze the language that happened to be active when the
// type was first touched.
public sealed record ProtectionModeOption(MarkerProtectionMode Mode, string LabelSource)
{
    public string Label => Localizer.T(LabelSource);

    public override string ToString() => Label;
}

// UI-side wrapper around a scanned function. IsSelected drives the list
// checkboxes; ToRule converts a checked row into the packer rule that
// ProtectorService passes as -func.
public sealed class FunctionItem : INotifyPropertyChanged
{
    // The protection types a function can be given. Inherit comes first because
    // it is the "follow the global mode" choice the batch box already offered —
    // without it here the per-row box had no way to show that state back, and it
    // silently fell back to 不保护.
    public static readonly IReadOnlyList<ProtectionModeOption> AllModeOptions =
    [
        new(MarkerProtectionMode.Inherit, "继承全局模式"),
        new(MarkerProtectionMode.Skip, "不保护"),
        new(MarkerProtectionMode.Virtualization, "虚拟化"),
        new(MarkerProtectionMode.Mutation, "变异"),
        new(MarkerProtectionMode.Ultra, "虚拟化+变异")
    ];

    private bool _isSelected;

    public FunctionItem(ScannedFunction function)
    {
        Function = function;
        _vmComplexity = 6;
        _mutationStrength = 2;
    }

    public ScannedFunction Function { get; }
    public uint Rva => Function.Rva;
    public IReadOnlyList<ProtectionModeOption> ModeOptions => AllModeOptions;
    public uint Size => Function.Size;
    public uint EndRva => Function.EndRva;
    public string Name => Function.Name;
    public string Section => Function.Section;
    public bool IsExported => Function.IsExported;
    public bool HasStackFrame => Function.HasStackFrame;
    public string AddressRange => Function.AddressRange;
    public string PrologueHex => Function.PrologueHex;
    public string Feasibility => Function.Feasibility;
    public bool VmFeasible => Function.VmFeasible;

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected == value) return;
            _isSelected = value;
            OnPropertyChanged();
            // Checking a row turns the protection back on: a row that was
            // skipped and is checked again must not stay skipped.
            if (value && _mode == MarkerProtectionMode.Skip)
            {
                _mode = MarkerProtectionMode.Virtualization;
                OnPropertyChanged(nameof(Mode));
            }
        }
    }

    private MarkerProtectionMode _mode = MarkerProtectionMode.Virtualization;

    // The row combo box binds to SelectedOption rather than to Mode directly:
    // the list holds ProtectionModeOption items, so the selection has to be
    // the item itself for the two-way binding to work.
    public ProtectionModeOption SelectedOption
    {
        get => AllModeOptions.FirstOrDefault(o => o.Mode == _mode) ?? AllModeOptions[0];
        set
        {
            if (value is not null) Mode = value.Mode;
        }
    }

    public MarkerProtectionMode Mode
    {
        get => _mode;
        set
        {
            if (_mode == value) return;
            _mode = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(SelectedOption));
            // The checkbox and the protection type are two views of one
            // decision, so they move together:
            //   * picking a protection type checks the row,
            //   * picking "not protected" unchecks it - a checked row that
            //     is not protected would look protected in the list while the
            //     packer would leave the function alone.
            if (value == MarkerProtectionMode.Skip)
            {
                if (_isSelected)
                {
                    _isSelected = false;
                    OnPropertyChanged(nameof(IsSelected));
                }
            }
            else if (!_isSelected)
            {
                // Inherit included: the rule is only handed to the packer when
                // the row is checked, so leaving an inherited row unchecked made
                // 继承全局模式 a no-op.
                _isSelected = true;
                OnPropertyChanged(nameof(IsSelected));
            }
        }
    }

    private int _vmComplexity;
    public int VmComplexity
    {
        get => _vmComplexity;
        set { _vmComplexity = Math.Clamp(value, 0, 10); OnPropertyChanged(); }
    }

    private int _mutationStrength;
    public int MutationStrength
    {
        get => _mutationStrength;
        set { _mutationStrength = Math.Clamp(value, 0, 3); OnPropertyChanged(); }
    }

    private bool _lockToActivation;
    public bool LockToActivation
    {
        get => _lockToActivation;
        set { _lockToActivation = value; OnPropertyChanged(); }
    }

    public ProtectionObjectRule ToRule() => new()
    {
        Id = $"func-{Rva:X8}",
        Name = Name,
        Source = ProductInfo.FunctionSource,
        DetectorVersion = ProductInfo.FunctionDetectorVersion,
        MarkerRva = Rva,
        StartRva = Rva,
        EndRva = EndRva,
        Mode = Mode,
        VmComplexity = VmComplexity,
        MutationStrength = MutationStrength,
        LockToActivation = LockToActivation
    };

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
