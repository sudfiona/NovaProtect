using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.Foundation;
using Windows.UI;
using ScenePath = Microsoft.UI.Xaml.Shapes.Path;

namespace NovaProtect.UI.Controls;

public sealed class BlackHoleScene : Grid
{
    private const double SceneWidth = 480;
    private const double SceneHeight = 240;
    private const double CenterX = SceneWidth / 2;
    private const double CenterY = SceneHeight / 2;
    private readonly ScenePath _hotFilament;
    private readonly Ellipse _corona;
    private readonly RotateTransform _diskRotation;
    private readonly RotateTransform _innerRotation;
    private readonly ScenePath _outerRim;

    public BlackHoleScene()
    {
        IsHitTestVisible = false;
        var sky = new Canvas { Width = SceneWidth, Height = SceneHeight };
        Children.Add(new Viewbox { Child = sky, Stretch = Stretch.Uniform });
        AddStars(sky);

        _diskRotation = new RotateTransform { CenterX = CenterX, CenterY = CenterY };
        var disk = new Canvas
        {
            Width = SceneWidth, Height = SceneHeight,
            RenderTransform = _diskRotation,
        };
        sky.Children.Add(disk);

        var silver = Spectrum((0, "00838A90"), (0.13, "697E858B"), (0.38, "FFDCE1E3"),
            (0.58, "FFB4BABD"), (0.82, "AB73797D"), (1, "006E7478"));
        var glint = Spectrum((0, "00CFB38A"), (0.22, "57CFB38A"), (0.38, "FFF1DDC0"),
            (0.49, "BFECEDEE"), (0.72, "00929799"), (1, "00929799"));

        AddEllipse(disk, 454, 67, Glow((0, "778C9092"), (0.54, "426E7478"), (1, "006E7478")));
        // The far side rises into a lensed arch; the opaque shadow masks its inner edge.
        AddCurve(disk, new(23, 128), new(140, 128), new(160, 103), new(176, 76), silver, 2);
        AddEllipse(disk, 170, 169, Glow((0, "00000000"), (0.74, "0075797B"),
            (0.84, "B3A7A9A7"), (0.9, "6D93989B"), (1, "0075797B")));
        AddEllipse(disk, 424, 33, null, silver, 1.8);
        _corona = AddEllipse(disk, 152, 152, Glow((0, "00000000"), (0.85, "54494E50"),
            (0.92, "D8D6D5D0"), (1, "007C8082")));
        AddEllipse(disk, 139, 139, Solid("FF000000"), silver, 1.6);

        // Two unequal arcs orbit the shadow. Rotate about the scene centre, not the path bounds.
        var ring = new Canvas { Width = SceneWidth, Height = SceneHeight };
        _innerRotation = new RotateTransform { CenterX = CenterX, CenterY = CenterY };
        ring.RenderTransform = _innerRotation;
        disk.Children.Add(ring);
        var rimLight = Spectrum((0, "00D1BA96"), (0.44, "FFF4DDB8"), (1, "48C0C5CA"));
        _outerRim = AddCurve(ring, new(177, 78), new(190, 57), new(213, 45), new(238, 44), rimLight, 5);
        AddCurve(ring, new(310, 139), new(308, 151), new(299, 166), new(285, 176), silver, 3);

        // Broad, low-opacity light beneath progressively finer foreground filaments.
        AddCurve(disk, new(18, 122), new(106, 151), new(345, 150), new(462, 117), silver, 8).Opacity = 0.22;
        AddCurve(disk, new(18, 122), new(111, 148), new(349, 147), new(462, 117), silver, 3.6);
        AddCurve(disk, new(31, 125), new(124, 157), new(355, 144), new(451, 119), silver, 1.4);
        _hotFilament = AddCurve(disk, new(22, 120), new(110, 144), new(334, 144), new(452, 118), glint, 2.2);
        RenderFrame(0);
    }

    private static void AddStars(Canvas sky)
    {
        var star = Solid("FFCFD3D5");
        (double X, double Y, double Size)[] stars =
        [
            (23, 71, 1.2), (61, 159, 2.1), (73, 46, 1.4), (109, 98, 1.1),
            (153, 31, 2.3), (167, 206, 1.4), (206, 222, 1.1), (285, 18, 1.5),
            (328, 204, 1.7), (365, 48, 1.1), (393, 169, 2.2), (429, 124, 1.3),
            (452, 54, 1.5), (87, 211, 1.2),
        ];
        foreach (var (x, y, size) in stars)
            Place(sky, new Ellipse { Width = size, Height = size, Fill = star, Opacity = size / 3 }, x, y);
    }

    private static ScenePath AddCurve(Canvas layer, Point start, Point control1, Point control2, Point end, Brush brush, double width)
    {
        var figure = new PathFigure { StartPoint = start };
        figure.Segments.Add(new BezierSegment { Point1 = control1, Point2 = control2, Point3 = end });
        var geometry = new PathGeometry();
        geometry.Figures.Add(figure);
        var curve = new ScenePath { Width = SceneWidth, Height = SceneHeight, Stretch = Stretch.None,
            Data = geometry, Stroke = brush, StrokeThickness = width };
        layer.Children.Add(curve);
        return curve;
    }

    internal void RenderFrame(double seconds)
    {
        double wave = Math.Sin(Math.Tau * seconds / 5.4);
        _innerRotation.Angle = (seconds % 6.0) * 60.0;
        _diskRotation.Angle = -16 + 3 * Math.Sin(Math.Tau * seconds / 11.0);
        _outerRim.Opacity = 0.88 + 0.12 * wave;
        _hotFilament.Opacity = 0.72 + 0.26 * wave;
        _corona.Opacity = 0.86 + 0.13 * Math.Sin(Math.Tau * seconds / 5.4 - 0.8);
    }

    private static Ellipse AddEllipse(Canvas canvas, double width, double height, Brush? fill, Brush? stroke = null, double thickness = 0)
    {
        var ellipse = new Ellipse { Width = width, Height = height, Fill = fill, Stroke = stroke, StrokeThickness = thickness };
        Place(canvas, ellipse, CenterX - width / 2, CenterY - height / 2);
        return ellipse;
    }

    private static void Place(Canvas canvas, FrameworkElement element, double x, double y)
    {
        Canvas.SetLeft(element, x);
        Canvas.SetTop(element, y);
        canvas.Children.Add(element);
    }

    private static RadialGradientBrush Glow(params (double Offset, string Color)[] stops)
    {
        var brush = new RadialGradientBrush { Center = new(0.5, 0.5), GradientOrigin = new(0.5, 0.5), RadiusX = 0.5, RadiusY = 0.5 };
        AddStops(brush.GradientStops.Add, stops);
        return brush;
    }

    private static LinearGradientBrush Spectrum(params (double Offset, string Color)[] stops)
    {
        var brush = new LinearGradientBrush { StartPoint = new(0, 0.5), EndPoint = new(1, 0.5) };
        AddStops(brush.GradientStops.Add, stops);
        return brush;
    }

    private static void AddStops(Action<GradientStop> add, (double Offset, string Color)[] stops)
    {
        foreach (var (offset, color) in stops)
            add(new GradientStop { Offset = offset, Color = Parse(color) });
    }

    private static SolidColorBrush Solid(string hex) => new(Parse(hex));

    private static Color Parse(string hex)
    {
        uint argb = Convert.ToUInt32(hex, 16);
        return Color.FromArgb((byte)(argb >> 24), (byte)(argb >> 16), (byte)(argb >> 8), (byte)argb);
    }
}
