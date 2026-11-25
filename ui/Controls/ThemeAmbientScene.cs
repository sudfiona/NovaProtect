using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.UI;

namespace NovaProtect.UI.Controls;

// Header ornament. Only the current scene is visible and updated.
public sealed class ThemeAmbientScene : Grid
{
    private readonly Canvas _glass = new() { Width = 168, Height = 56 };
    private readonly Canvas _pop = new() { Width = 168, Height = 56 };
    private readonly Canvas _lab = new() { Width = 168, Height = 56 };
    private readonly CompositeTransform[] _glassDrift = [new(), new(), new()];
    private readonly CompositeTransform[] _popBounce = [new(), new(), new()];
    private readonly TranslateTransform _labCursor = new();
    private string? _theme;

    public ThemeAmbientScene()
    {
        IsHitTestVisible = false;
        Children.Add(new Viewbox { Child = _glass, Stretch = Stretch.Uniform });
        Children.Add(new Viewbox { Child = _pop, Stretch = Stretch.Uniform });
        Children.Add(new Viewbox { Child = _lab, Stretch = Stretch.Uniform });

        Color[] glassColors = [Color.FromArgb(185, 112, 227, 255), Color.FromArgb(170, 163, 144, 255), Color.FromArgb(220, 231, 248, 255)];
        for (int i = 0; i < glassColors.Length; i++)
        {
            var ribbon = new Ellipse
            {
                Width = 133 - i * 13, Height = 25 - i * 4,
                Stroke = new SolidColorBrush(glassColors[i]), StrokeThickness = 2,
                RenderTransform = _glassDrift[i], RenderTransformOrigin = new(0.5, 0.5),
            };
            Place(_glass, ribbon, 14 + i * 7, 14 + i * 4);
        }

        Color[] popColors = [Color.FromArgb(255, 255, 97, 115), Color.FromArgb(255, 255, 232, 104), Color.FromArgb(255, 255, 102, 182)];
        for (int i = 0; i < popColors.Length; i++)
        {
            var tile = new Rectangle
            {
                Width = 31, Height = 31, RadiusX = 7, RadiusY = 7,
                Fill = new SolidColorBrush(popColors[i]),
                Stroke = new SolidColorBrush(Color.FromArgb(255, 71, 31, 44)), StrokeThickness = 1.5,
                RenderTransform = _popBounce[i], RenderTransformOrigin = new(0.5, 0.5),
            };
            Place(_pop, tile, 29 + i * 40, 15);
        }

        var muted = new SolidColorBrush(Color.FromArgb(140, 155, 128, 230));
        var phosphor = new SolidColorBrush(Color.FromArgb(255, 177, 255, 101));
        for (int i = 0; i < 17; i++)
        {
            double height = 5 + (i * 17 % 24);
            Place(_lab, new Rectangle { Width = 2, Height = height, Fill = muted }, 12 + i * 9, 28 - height / 2);
        }
        Place(_lab, new Rectangle { Width = 146, Height = 1, Fill = muted }, 12, 28);
        Place(_lab, new Rectangle { Width = 4, Height = 34, Fill = phosphor, RenderTransform = _labCursor }, 10, 11);
    }

    internal void SetTheme(string theme)
    {
        _theme = theme;
        Children[0].Visibility = theme == NovaTheme.Glass ? Visibility.Visible : Visibility.Collapsed;
        Children[1].Visibility = theme == NovaTheme.Pop ? Visibility.Visible : Visibility.Collapsed;
        Children[2].Visibility = theme == NovaTheme.Lab ? Visibility.Visible : Visibility.Collapsed;
        Visibility = theme == NovaTheme.BlackHole ? Visibility.Collapsed : Visibility.Visible;
        RenderFrame(0);
    }

    internal void RenderFrame(double seconds)
    {
        switch (_theme)
        {
            case NovaTheme.Glass:
                for (int i = 0; i < _glassDrift.Length; i++)
                {
                    double phase = seconds * Math.Tau / (6 + i) + i;
                    _glassDrift[i].Rotation = 12 * Math.Sin(phase);
                    _glassDrift[i].TranslateX = 12 * Math.Cos(phase);
                    _glassDrift[i].TranslateY = 5 * Math.Sin(phase);
                }
                break;
            case NovaTheme.Pop:
                for (int i = 0; i < _popBounce.Length; i++)
                {
                    double phase = seconds * Math.Tau / 2.4 + i * 1.9;
                    double rise = Math.Pow(Math.Max(0, Math.Sin(phase)), 2);
                    _popBounce[i].TranslateY = 8 - 18 * rise;
                    _popBounce[i].Rotation = (i - 1) * 14 + 15 * Math.Sin(phase);
                }
                break;
            case NovaTheme.Lab:
                double pass = seconds % 4 / 2;
                _labCursor.X = 144 * (pass < 1 ? pass : 2 - pass);
                break;
        }
    }

    private static void Place(Canvas canvas, FrameworkElement element, double x, double y)
    {
        Canvas.SetLeft(element, x);
        Canvas.SetTop(element, y);
        canvas.Children.Add(element);
    }
}
