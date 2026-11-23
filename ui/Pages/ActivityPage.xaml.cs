using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Navigation;
using System.Collections.Specialized;
using NovaProtect.UI.Models;
using NovaProtect.UI.Services;

namespace NovaProtect.UI.Pages;

public sealed partial class ActivityPage : Page
{
    public ActivityPage()
    {
        InitializeComponent();
        ActivityList.ItemsSource = ActivityStore.Items;
        ActivityStore.Items.CollectionChanged += Items_CollectionChanged;
        UpdateEmptyState();
        // The rows are model objects whose text is computed, so a language change
        // needs the item containers rebuilt rather than re-walked.
        Localizer.Attach(this, RebuildList);
    }

    /// <summary>
    /// Re-create the rows. <see cref="ActivityItem.TitleText"/> and
    /// <see cref="ActivityItem.DetailText"/> are computed properties and raise no
    /// change notification, so the ListView has to be handed its source again for
    /// the bindings to be read a second time.
    /// </summary>
    private void RebuildList()
    {
        ActivityList.ItemsSource = null;
        ActivityList.ItemsSource = ActivityStore.Items;
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        ActivityStore.Items.CollectionChanged -= Items_CollectionChanged;
        base.OnNavigatedFrom(e);
    }

    private void Items_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e) => UpdateEmptyState();

    private void UpdateEmptyState()
    {
        EmptyState.Visibility = ActivityStore.Items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        ClearButton.IsEnabled = ActivityStore.Items.Count > 0;
    }

    private void DeleteItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: ActivityItem item }) ActivityStore.Remove(item);
    }

    private async void ClearButton_Click(object sender, RoutedEventArgs e)
    {
        if (ActivityStore.Items.Count == 0) return;

        // Built here rather than through DialogService, so the copy is resolved
        // at the same place the dialog is constructed.
        var dialog = new ContentDialog
        {
            Title = Localizer.T("清空运行记录？"),
            Content = Localizer.T("已保存的保护成功、失败和取消记录都会删除。"),
            PrimaryButtonText = Localizer.T("清空"),
            CloseButtonText = Localizer.T("取消"),
            XamlRoot = XamlRoot
        };
        if (await dialog.ShowAsync() == ContentDialogResult.Primary) ActivityStore.Clear();
    }
}
