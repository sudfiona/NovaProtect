using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Windows.System;

namespace NovaProtect.UI.Controls;

/// <summary>
/// Glass card shell: gradient border, ThemeShadow, spring hover lift.
/// </summary>
public sealed partial class GlassCardHoverHost : UserControl
{
    private static readonly PropertyChangedCallback MetaCallback =
        (d, e) => ((GlassCardHoverHost)d).ApplyChrome();

    private static readonly DependencyPropertyChangedCallback RegisterCallback =
        (d, e) => ((GlassCardHoverHost)d).ApplyChrome();

    private CompositeTransform? _transform;
    private bool _pressed;

    public GlassCardHoverHost()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        RegisterPropertyChangedCallback(CornerRadiusProperty, RegisterCallback);
        RegisterPropertyChangedCallback(CardPaddingProperty, RegisterCallback);
        RegisterPropertyChangedCallback(EnableHoverProperty, RegisterCallback);
    }

    // new hides Control.CornerRadius: we apply radius to the inner Border.
    public new static readonly DependencyProperty CornerRadiusProperty = DependencyProperty.Register(
        nameof(CornerRadius), typeof(CornerRadius), typeof(GlassCardHoverHost),
        new PropertyMetadata(new CornerRadius(20), MetaCallback));

    public new CornerRadius CornerRadius
    {
        get => (CornerRadius)GetValue(CornerRadiusProperty);
        set => SetValue(CornerRadiusProperty, value);
    }

    public static readonly DependencyProperty CardPaddingProperty = DependencyProperty.Register(
        nameof(CardPadding), typeof(Thickness), typeof(GlassCardHoverHost),
        new PropertyMetadata(new Thickness(22, 18, 22, 18), MetaCallback));

    public Thickness CardPadding
    {
        get => (Thickness)GetValue(CardPaddingProperty);
        set => SetValue(CardPaddingProperty, value);
    }

    public static readonly DependencyProperty EnableHoverProperty = DependencyProperty.Register(
        nameof(EnableHover), typeof(bool), typeof(GlassCardHoverHost),
        new PropertyMetadata(true, MetaCallback));

    public bool EnableHover
    {
        get => (bool)GetValue(EnableHoverProperty);
        set => SetValue(EnableHoverProperty, value);
    }

    private void ApplyChrome()
    {
        if (BorderHost is null) return;
        BorderHost.CornerRadius = CornerRadius;
        BorderHost.Padding = CardPadding;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        _transform = BorderHost.RenderTransform as CompositeTransform;
        if (_transform is null)
        {
            _transform = new CompositeTransform();
            BorderHost.RenderTransform = _transform;
        }

        ApplyChrome();
        PointerEntered += OnPointerEntered;
        PointerExited += OnPointerExited;
        PointerPressed += OnPointerPressed;
        PointerReleased += OnPointerReleased;
        PointerCanceled += OnPointerCanceled;
        KeyDown += OnKeyDown;
        KeyUp += OnKeyUp;
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        PointerEntered -= OnPointerEntered;
        PointerExited -= OnPointerExited;
        PointerPressed -= OnPointerPressed;
        PointerReleased -= OnPointerReleased;
        PointerCanceled -= OnPointerCanceled;
        KeyDown -= OnKeyDown;
        KeyUp -= OnKeyUp;
    }

    private void OnPointerEntered(object sender, PointerRoutedEventArgs e)
    {
        if (!EnableHover || _pressed) return;
        AnimateLift(translateY: -2, scale: 1.006, borderHover: true, ms: 220);
    }

    private void OnPointerExited(object sender, PointerRoutedEventArgs e)
    {
        if (!EnableHover) return;
        _pressed = false;
        AnimateLift(translateY: 0, scale: 1.0, borderHover: false, ms: 220);
    }

    private void OnPointerPressed(object sender, PointerRoutedEventArgs e)
    {
        if (!EnableHover) return;
        _pressed = true;
        AnimateLift(translateY: 0, scale: 0.97, borderHover: true, ms: 60);
    }

    private void OnPointerReleased(object sender, PointerRoutedEventArgs e)
    {
        if (!EnableHover) return;
        _pressed = false;
        AnimateLift(translateY: -2, scale: 1.006, borderHover: true, ms: 180);
    }

    private void OnPointerCanceled(object sender, PointerRoutedEventArgs e)
    {
        _pressed = false;
        if (!EnableHover) return;
        AnimateLift(translateY: 0, scale: 1.0, borderHover: false, ms: 160);
    }

    private void OnKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (!EnableHover || e.Key is not (VirtualKey.Space or VirtualKey.Enter)) return;
        _pressed = true;
        AnimateLift(translateY: 0, scale: 0.97, borderHover: true, ms: 60);
    }

    private void OnKeyUp(object sender, KeyRoutedEventArgs e)
    {
        if (!EnableHover || e.Key is not (VirtualKey.Space or VirtualKey.Enter)) return;
        _pressed = false;
        AnimateLift(translateY: -2, scale: 1.006, borderHover: true, ms: 180);
    }

    private void AnimateLift(double translateY, double scale, bool borderHover, int ms)
    {
        if (_transform is null || BorderHost is null) return;

        var duration = new Duration(TimeSpan.FromMilliseconds(ms));
        var ease = new CubicEase { EasingMode = EasingMode.EaseOut };

        AnimateDouble(_transform, CompositeTransform.TranslateYProperty, translateY, duration, ease);
        AnimateDouble(_transform, CompositeTransform.ScaleXProperty, scale, duration, ease);
        AnimateDouble(_transform, CompositeTransform.ScaleYProperty, scale, duration, ease);

        var key = borderHover ? "NovaGlassCardHoverBorderBrush" : "NovaGlassCardBorderBrush";
        Brush? brush = null;
        if (Application.Current?.Resources.TryGetValue(key, out var appRes) == true)
            brush = appRes as Brush;
        if (brush is null && Resources.TryGetValue(key, out var local))
            brush = local as Brush;
        if (brush is not null) BorderHost.BorderBrush = brush;
    }

    private static string PropertyName(DependencyProperty property) =>
        property == CompositeTransform.TranslateYProperty ? "TranslateY" :
        property == CompositeTransform.ScaleXProperty ? "ScaleX" :
        property == CompositeTransform.ScaleYProperty ? "ScaleY" : "Opacity";

    private static void AnimateDouble(DependencyObject target, DependencyProperty property,
        double to, Duration duration, EasingFunctionBase ease)
    {
        var anim = new DoubleAnimation { To = to, Duration = duration, EasingFunction = ease };
        var sb = new Storyboard();
        sb.Children.Add(anim);
        Storyboard.SetTarget(anim, target);
        Storyboard.SetTargetProperty(anim, PropertyName(property));
        sb.Begin();
    }
}
