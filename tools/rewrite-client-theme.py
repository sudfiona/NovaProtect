# -*- coding: utf-8 -*-
"""
Rewrite client design system to match website standard:
  HyperOS glass + Apple fluid + Emil polish.
- Theme.xaml: motion tokens, press scale 0.97, spring bounce, theme shapes
- GlassCardHoverHost: lift/scale like website cards
- MainWindow: entrance rise like hero
"""
from pathlib import Path
import re

UI = Path(r"D:\工作区\NovaProtect\NovaProtect-main\ui")

# ---------------------------------------------------------------- Theme.xaml
theme = r'''<ResourceDictionary
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">

    <!--
      NovaProtect client · same design standard as website
      HyperOS soft-light glass + Apple fluid motion + Emil polish
      Themes: glass (default) | pop | lab
    -->

    <ResourceDictionary.ThemeDictionaries>
        <ResourceDictionary x:Key="Light">
            <SolidColorBrush x:Key="NovaVeilBrush" Color="#B3E9F1FF" />
            <Color x:Key="NovaPageWashColor">#F3F7FF</Color>
            <SolidColorBrush x:Key="NovaGlassCardBrush" Color="#8CFFFFFF" />
            <LinearGradientBrush x:Key="NovaGlassCardBorderBrush" StartPoint="0,0" EndPoint="1,1">
                <GradientStop Color="#FFFFFF" Offset="0.0" />
                <GradientStop Color="#DCE8FC" Offset="0.45" />
                <GradientStop Color="#A8C2F0" Offset="1.0" />
            </LinearGradientBrush>
            <LinearGradientBrush x:Key="NovaGlassCardHoverBorderBrush" StartPoint="0,0" EndPoint="1,1">
                <GradientStop Color="#FFFFFF" Offset="0.0" />
                <GradientStop Color="#C8DDFF" Offset="0.4" />
                <GradientStop Color="#B8A8FF" Offset="1.0" />
            </LinearGradientBrush>
            <SolidColorBrush x:Key="NovaGlassInputBrush" Color="#CCE9EEF5" />
            <SolidColorBrush x:Key="NovaGlassInputBorderBrush" Color="#7A8496A8" />
            <SolidColorBrush x:Key="NovaBadgeBrush" Color="#332E7CF6" />
            <SolidColorBrush x:Key="NovaBadgeBorderBrush" Color="#4D2E7CF6" />
            <SolidColorBrush x:Key="NovaBadgeSuccessBrush" Color="#1F16A34A" />
            <SolidColorBrush x:Key="NovaBadgeSuccessBorderBrush" Color="#3316A34A" />
            <SolidColorBrush x:Key="NovaBadgeMutedBrush" Color="#1F7488B2" />
            <SolidColorBrush x:Key="NovaBadgeMutedBorderBrush" Color="#337488B2" />
            <SolidColorBrush x:Key="NovaTitleDividerBrush" Color="#14000000" />
            <Color x:Key="NovaGlowBlueCoreColor">#B34A8CFF</Color>
            <Color x:Key="NovaGlowBlueEdgeColor">#003B82E8</Color>
            <Color x:Key="NovaGlowCyanCoreColor">#9938C6D9</Color>
            <Color x:Key="NovaGlowCyanEdgeColor">#002BB8CC</Color>
            <Color x:Key="NovaGlowVioletCoreColor">#B37C5CFF</Color>
            <Color x:Key="NovaGlowVioletEdgeColor">#006A4FE8</Color>
            <Color x:Key="NovaGlowRoseCoreColor">#80FF8FB0</Color>
            <Color x:Key="NovaGlowRoseEdgeColor">#00FF8FB0</Color>
            <SolidColorBrush x:Key="ControlFillColorDefaultBrush" Color="#66F2F6FB" />
            <SolidColorBrush x:Key="ControlFillColorSecondaryBrush" Color="#99FFFFFF" />
            <SolidColorBrush x:Key="ControlFillColorTertiaryBrush" Color="#662E7CF6" />
            <SolidColorBrush x:Key="ControlStrokeColorDefaultBrush" Color="#596B7F8A" />
            <SolidColorBrush x:Key="CardBackgroundFillColorDefaultBrush" Color="#B3FFFFFF" />
            <SolidColorBrush x:Key="CardStrokeColorDefaultBrush" Color="#66FFFFFF" />
            <SolidColorBrush x:Key="AccentFillColorDefaultBrush" Color="#2E7CF6" />
            <SolidColorBrush x:Key="AccentFillColorSecondaryBrush" Color="#402E7CF6" />
            <SolidColorBrush x:Key="AccentFillColorTertiaryBrush" Color="#662E7CF6" />
            <SolidColorBrush x:Key="SystemFillColorAttentionBackgroundBrush" Color="#1F2E7CF6" />
            <SolidColorBrush x:Key="SystemFillColorSuccessBackgroundBrush" Color="#1F16A34A" />
            <SolidColorBrush x:Key="SystemFillColorCautionBackgroundBrush" Color="#1FF59E0B" />
            <SolidColorBrush x:Key="SystemFillColorCriticalBackgroundBrush" Color="#1FFEE2E2" />
            <SolidColorBrush x:Key="NovaThemeChipTrackBrush" Color="#227488B2" />
            <SolidColorBrush x:Key="NovaThemeChipOnBrush" Color="#2E7CF6" />
            <SolidColorBrush x:Key="NovaThemeChipOnFgBrush" Color="#FFFFFFFF" />
            <SolidColorBrush x:Key="NovaThemeChipOffFgBrush" Color="#FF7C869B" />
            <SolidColorBrush x:Key="NovaThemeChipOffBgBrush" Color="#00000000" />
            <SolidColorBrush x:Key="NovaThemeChipOffBorderBrush" Color="#337488B2" />
            <SolidColorBrush x:Key="NovaPageBgBrush" Color="#F3F7FF" />
            <SolidColorBrush x:Key="NovaConsoleBrush" Color="#8CFFFFFF" />
            <SolidColorBrush x:Key="NovaConsoleStrokeBrush" Color="#66FFFFFF" />
            <SolidColorBrush x:Key="NovaConsoleTextBrush" Color="#171C28" />
        </ResourceDictionary>

        <ResourceDictionary x:Key="Dark">
            <SolidColorBrush x:Key="NovaVeilBrush" Color="#B30B0F1A" />
            <Color x:Key="NovaPageWashColor">#0B0F1A</Color>
            <SolidColorBrush x:Key="NovaGlassCardBrush" Color="#C7111827" />
            <LinearGradientBrush x:Key="NovaGlassCardBorderBrush" StartPoint="0,0" EndPoint="1,1">
                <GradientStop Color="#33FFFFFF" Offset="0.0" />
                <GradientStop Color="#2222D3EE" Offset="0.55" />
                <GradientStop Color="#1A5B9CFF" Offset="1.0" />
            </LinearGradientBrush>
            <LinearGradientBrush x:Key="NovaGlassCardHoverBorderBrush" StartPoint="0,0" EndPoint="1,1">
                <GradientStop Color="#4DFFFFFF" Offset="0.0" />
                <GradientStop Color="#4422D3EE" Offset="0.5" />
                <GradientStop Color="#2A6B9CFF" Offset="1.0" />
            </LinearGradientBrush>
            <SolidColorBrush x:Key="NovaGlassInputBrush" Color="#1AFFFFFF" />
            <SolidColorBrush x:Key="NovaGlassInputBorderBrush" Color="#3394A3B8" />
            <SolidColorBrush x:Key="NovaBadgeBrush" Color="#2222D3EE" />
            <SolidColorBrush x:Key="NovaBadgeBorderBrush" Color="#4022D3EE" />
            <SolidColorBrush x:Key="NovaBadgeSuccessBrush" Color="#224ADE80" />
            <SolidColorBrush x:Key="NovaBadgeSuccessBorderBrush" Color="#404ADE80" />
            <SolidColorBrush x:Key="NovaBadgeMutedBrush" Color="#2264748B" />
            <SolidColorBrush x:Key="NovaBadgeMutedBorderBrush" Color="#3364748B" />
            <SolidColorBrush x:Key="NovaTitleDividerBrush" Color="#2294A3B8" />
            <Color x:Key="NovaGlowBlueCoreColor">#6622D3EE</Color>
            <Color x:Key="NovaGlowBlueEdgeColor">#0022D3EE</Color>
            <Color x:Key="NovaGlowCyanCoreColor">#55A78BFA</Color>
            <Color x:Key="NovaGlowCyanEdgeColor">#00A78BFA</Color>
            <Color x:Key="NovaGlowVioletCoreColor">#552E7CF6</Color>
            <Color x:Key="NovaGlowVioletEdgeColor">#002E7CF6</Color>
            <Color x:Key="NovaGlowRoseCoreColor">#334ADE80</Color>
            <Color x:Key="NovaGlowRoseEdgeColor">#004ADE80</Color>
            <SolidColorBrush x:Key="ControlFillColorDefaultBrush" Color="#1494A3B8" />
            <SolidColorBrush x:Key="ControlFillColorSecondaryBrush" Color="#2294A3B8" />
            <SolidColorBrush x:Key="ControlFillColorTertiaryBrush" Color="#3322D3EE" />
            <SolidColorBrush x:Key="ControlStrokeColorDefaultBrush" Color="#3394A3B8" />
            <SolidColorBrush x:Key="CardBackgroundFillColorDefaultBrush" Color="#C7111827" />
            <SolidColorBrush x:Key="CardStrokeColorDefaultBrush" Color="#3394A3B8" />
            <SolidColorBrush x:Key="AccentFillColorDefaultBrush" Color="#22D3EE" />
            <SolidColorBrush x:Key="AccentFillColorSecondaryBrush" Color="#3322D3EE" />
            <SolidColorBrush x:Key="AccentFillColorTertiaryBrush" Color="#4D22D3EE" />
            <SolidColorBrush x:Key="SystemFillColorAttentionBackgroundBrush" Color="#3322D3EE" />
            <SolidColorBrush x:Key="SystemFillColorSuccessBackgroundBrush" Color="#334ADE80" />
            <SolidColorBrush x:Key="SystemFillColorCautionBackgroundBrush" Color="#33FBBF24" />
            <SolidColorBrush x:Key="SystemFillColorCriticalBackgroundBrush" Color="#33F87171" />
            <SolidColorBrush x:Key="NovaThemeChipTrackBrush" Color="#2222D3EE" />
            <SolidColorBrush x:Key="NovaThemeChipOnBrush" Color="#22D3EE" />
            <SolidColorBrush x:Key="NovaThemeChipOnFgBrush" Color="#FF0B0F1A" />
            <SolidColorBrush x:Key="NovaThemeChipOffFgBrush" Color="#FF64748B" />
            <SolidColorBrush x:Key="NovaThemeChipOffBgBrush" Color="#141B2B" />
            <SolidColorBrush x:Key="NovaThemeChipOffBorderBrush" Color="#2A3A55" />
            <SolidColorBrush x:Key="NovaPageBgBrush" Color="#0B0F1A" />
            <SolidColorBrush x:Key="NovaConsoleBrush" Color="#EB0B0F1A" />
            <SolidColorBrush x:Key="NovaConsoleStrokeBrush" Color="#3322D3EE" />
            <SolidColorBrush x:Key="NovaConsoleTextBrush" Color="#4ADE80" />
        </ResourceDictionary>
    </ResourceDictionary.ThemeDictionaries>

    <!-- Brand gradient (website --grad) -->
    <LinearGradientBrush x:Key="NovaAccentGradientBrush" StartPoint="0,0" EndPoint="1,1">
        <GradientStop Color="#5AA9FF" Offset="0.0" />
        <GradientStop Color="#2E7CF6" Offset="0.55" />
        <GradientStop Color="#7B61FF" Offset="1.0" />
    </LinearGradientBrush>
    <LinearGradientBrush x:Key="NovaGradTextBrush" StartPoint="0,0" EndPoint="1,0">
        <GradientStop Color="#22D3EE" Offset="0.0" />
        <GradientStop Color="#2E7CF6" Offset="0.45" />
        <GradientStop Color="#7B61FF" Offset="1.0" />
    </LinearGradientBrush>
    <SolidColorBrush x:Key="NovaAccentHoverOverlayBrush" Color="#29FFFFFF" />
    <SolidColorBrush x:Key="NovaAccentPressedOverlayBrush" Color="#33000000" />

    <!-- Emil: strong ease-out ≈ cubic-bezier(0.23,1,0.32,1); backOut for springy press -->
    <CubicEase x:Key="NovaEaseOut" EasingMode="EaseOut" />
    <CubicEase x:Key="NovaEaseInOut" EasingMode="EaseInOut" />
    <BackEase x:Key="NovaSpringBounce" EasingMode="EaseOut" Amplitude="0.35" />
    <QuadraticEase x:Key="NovaSoftEase" EasingMode="EaseOut" />

    <Thickness x:Key="PagePadding">28,22,28,30</Thickness>
    <CornerRadius x:Key="CardCornerRadius">24</CornerRadius>
    <CornerRadius x:Key="ControlCornerRadius">12</CornerRadius>
    <CornerRadius x:Key="ButtonCornerRadius">18</CornerRadius>
    <CornerRadius x:Key="PillCornerRadius">18</CornerRadius>
    <CornerRadius x:Key="ChipCornerRadius">12</CornerRadius>
    <ThemeShadow x:Key="NovaCardShadow" />

    <!-- Typography (website: tight tracking on display, readable body) -->
    <Style x:Key="PageTitleStyle" TargetType="TextBlock">
        <Setter Property="FontFamily" Value="Segoe UI Variable Display" />
        <Setter Property="FontSize" Value="30" />
        <Setter Property="FontWeight" Value="Bold" />
        <Setter Property="Foreground" Value="{ThemeResource TextFillColorPrimaryBrush}" />
    </Style>
    <Style x:Key="HeroNumberStyle" TargetType="TextBlock">
        <Setter Property="FontFamily" Value="Segoe UI Variable Display" />
        <Setter Property="FontSize" Value="34" />
        <Setter Property="FontWeight" Value="Bold" />
        <Setter Property="Foreground" Value="{StaticResource NovaGradTextBrush}" />
    </Style>
    <Style x:Key="SectionTitleStyle" TargetType="TextBlock">
        <Setter Property="FontFamily" Value="Segoe UI Variable Display" />
        <Setter Property="FontSize" Value="15.5" />
        <Setter Property="FontWeight" Value="SemiBold" />
        <Setter Property="Foreground" Value="{ThemeResource TextFillColorPrimaryBrush}" />
    </Style>
    <Style x:Key="CardEyebrowStyle" TargetType="TextBlock">
        <Setter Property="FontSize" Value="12" />
        <Setter Property="FontWeight" Value="Bold" />
        <Setter Property="Foreground" Value="{ThemeResource AccentTextFillColorPrimaryBrush}" />
    </Style>
    <Style x:Key="SubtleTextStyle" TargetType="TextBlock">
        <Setter Property="Foreground" Value="{ThemeResource TextFillColorSecondaryBrush}" />
        <Setter Property="TextWrapping" Value="Wrap" />
        <Setter Property="FontFamily" Value="Segoe UI Variable Text" />
        <Setter Property="FontSize" Value="13" />
        <Setter Property="LineHeight" Value="22" />
    </Style>

    <!-- Glass card (website .card) -->
    <Style x:Key="CardStyle" TargetType="Border">
        <Setter Property="Background" Value="{ThemeResource NovaGlassCardBrush}" />
        <Setter Property="BorderBrush" Value="{ThemeResource NovaGlassCardBorderBrush}" />
        <Setter Property="BorderThickness" Value="1" />
        <Setter Property="CornerRadius" Value="{StaticResource CardCornerRadius}" />
        <Setter Property="Padding" Value="22,18" />
        <Setter Property="HorizontalAlignment" Value="Stretch" />
        <Setter Property="RenderTransformOrigin" Value="0.5,0.5" />
    </Style>
    <Style x:Key="CardCompactStyle" TargetType="Border" BasedOn="{StaticResource CardStyle}">
        <Setter Property="Padding" Value="16,12" />
        <Setter Property="CornerRadius" Value="14" />
    </Style>
    <Style x:Key="ConsoleSurfaceStyle" TargetType="Border">
        <Setter Property="Background" Value="{ThemeResource NovaConsoleBrush}" />
        <Setter Property="BorderBrush" Value="{ThemeResource NovaConsoleStrokeBrush}" />
        <Setter Property="BorderThickness" Value="1" />
        <Setter Property="CornerRadius" Value="14" />
        <Setter Property="Padding" Value="16,12" />
    </Style>

    <!-- Secondary glass button: hover lift via template, press scale 0.97 (Emil) -->
    <Style x:Key="RoundedButtonStyle" TargetType="Button">
        <Setter Property="FontFamily" Value="Segoe UI Variable Text" />
        <Setter Property="FontSize" Value="13" />
        <Setter Property="FontWeight" Value="SemiBold" />
        <Setter Property="MinHeight" Value="36" />
        <Setter Property="MinWidth" Value="36" />
        <Setter Property="Padding" Value="14,6" />
        <Setter Property="CornerRadius" Value="12" />
        <Setter Property="Background" Value="{ThemeResource ControlFillColorDefaultBrush}" />
        <Setter Property="BorderBrush" Value="{ThemeResource ControlStrokeColorDefaultBrush}" />
        <Setter Property="BorderThickness" Value="1" />
        <Setter Property="Foreground" Value="{ThemeResource TextFillColorPrimaryBrush}" />
        <Setter Property="UseSystemFocusVisuals" Value="True" />
        <Setter Property="HorizontalAlignment" Value="Left" />
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="Button">
                    <Grid x:Name="Root" RenderTransformOrigin="0.5,0.5">
                        <Grid.RenderTransform>
                            <CompositeTransform x:Name="T" />
                        </Grid.RenderTransform>
                        <Border x:Name="B"
                                Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="{TemplateBinding CornerRadius}" />
                        <Border x:Name="Overlay" Background="Transparent"
                                CornerRadius="{TemplateBinding CornerRadius}" IsHitTestVisible="False" />
                        <ContentPresenter x:Name="CP"
                                          Content="{TemplateBinding Content}"
                                          ContentTemplate="{TemplateBinding ContentTemplate}"
                                          Padding="{TemplateBinding Padding}"
                                          HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}"
                                          VerticalAlignment="{TemplateBinding VerticalContentAlignment}" />
                        <VisualStateManager.VisualStateGroups>
                            <VisualStateGroup x:Name="CommonStates">
                                <VisualState x:Name="Normal" />
                                <VisualState x:Name="PointerOver">
                                    <Storyboard>
                                        <DoubleAnimation Storyboard.TargetName="T" Storyboard.TargetProperty="TranslateY"
                                                         To="-1" Duration="0:0:0.16">
                                            <DoubleAnimation.EasingFunction><CubicEase EasingMode="EaseOut" /></DoubleAnimation.EasingFunction>
                                        </DoubleAnimation>
                                        <DoubleAnimation Storyboard.TargetName="T" Storyboard.TargetProperty="ScaleX"
                                                         To="1.02" Duration="0:0:0.18">
                                            <DoubleAnimation.EasingFunction><CubicEase EasingMode="EaseOut" /></DoubleAnimation.EasingFunction>
                                        </DoubleAnimation>
                                        <DoubleAnimation Storyboard.TargetName="T" Storyboard.TargetProperty="ScaleY"
                                                         To="1.02" Duration="0:0:0.18">
                                            <DoubleAnimation.EasingFunction><CubicEase EasingMode="EaseOut" /></DoubleAnimation.EasingFunction>
                                        </DoubleAnimation>
                                        <ObjectAnimationUsingKeyFrames Storyboard.TargetName="Overlay" Storyboard.TargetProperty="Background">
                                            <DiscreteObjectKeyFrame KeyTime="0" Value="{StaticResource NovaAccentHoverOverlayBrush}" />
                                        </ObjectAnimationUsingKeyFrames>
                                    </Storyboard>
                                </VisualState>
                                <VisualState x:Name="Pressed">
                                    <Storyboard>
                                        <!-- Emil: press scale 0.97, fast 60ms -->
                                        <DoubleAnimation Storyboard.TargetName="T" Storyboard.TargetProperty="ScaleX"
                                                         To="0.97" Duration="0:0:0.06">
                                            <DoubleAnimation.EasingFunction><CubicEase EasingMode="EaseOut" /></DoubleAnimation.EasingFunction>
                                        </DoubleAnimation>
                                        <DoubleAnimation Storyboard.TargetName="T" Storyboard.TargetProperty="ScaleY"
                                                         To="0.97" Duration="0:0:0.06">
                                            <DoubleAnimation.EasingFunction><CubicEase EasingMode="EaseOut" /></DoubleAnimation.EasingFunction>
                                        </DoubleAnimation>
                                        <DoubleAnimation Storyboard.TargetName="T" Storyboard.TargetProperty="TranslateY"
                                                         To="0" Duration="0:0:0.06" />
                                        <ObjectAnimationUsingKeyFrames Storyboard.TargetName="Overlay" Storyboard.TargetProperty="Background">
                                            <DiscreteObjectKeyFrame KeyTime="0" Value="{StaticResource NovaAccentPressedOverlayBrush}" />
                                        </ObjectAnimationUsingKeyFrames>
                                    </Storyboard>
                                </VisualState>
                                <VisualState x:Name="Disabled">
                                    <Storyboard>
                                        <DoubleAnimation Storyboard.TargetName="Root" Storyboard.TargetProperty="Opacity"
                                                         To="0.42" Duration="0:0:0.16" />
                                    </Storyboard>
                                </VisualState>
                            </VisualStateGroup>
                        </VisualStateManager.VisualStateGroups>
                    </Grid>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>

    <Style x:Key="GhostButtonStyle" TargetType="Button" BasedOn="{StaticResource RoundedButtonStyle}">
        <Setter Property="Foreground" Value="{ThemeResource AccentTextFillColorPrimaryBrush}" />
        <Setter Property="Background" Value="Transparent" />
        <Setter Property="BorderBrush" Value="{ThemeResource NovaBadgeBorderBrush}" />
    </Style>

    <!-- Primary: website button-primary gradient + press 0.97 -->
    <Style x:Key="AccentActionButtonStyle" TargetType="Button">
        <Setter Property="FontFamily" Value="Segoe UI Variable Text" />
        <Setter Property="FontSize" Value="14" />
        <Setter Property="FontWeight" Value="SemiBold" />
        <Setter Property="MinHeight" Value="44" />
        <Setter Property="MinWidth" Value="120" />
        <Setter Property="Padding" Value="24,0" />
        <Setter Property="CornerRadius" Value="{StaticResource ButtonCornerRadius}" />
        <Setter Property="Foreground" Value="White" />
        <Setter Property="Background" Value="{StaticResource NovaAccentGradientBrush}" />
        <Setter Property="BorderThickness" Value="0" />
        <Setter Property="HorizontalContentAlignment" Value="Center" />
        <Setter Property="VerticalContentAlignment" Value="Center" />
        <Setter Property="UseSystemFocusVisuals" Value="True" />
        <Setter Property="RenderTransformOrigin" Value="0.5,0.5" />
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="Button">
                    <Grid x:Name="RootGrid" RenderTransformOrigin="0.5,0.5">
                        <Grid.RenderTransform>
                            <CompositeTransform x:Name="PressTransform" />
                        </Grid.RenderTransform>
                        <Border x:Name="ButtonBorder"
                                Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="{TemplateBinding CornerRadius}" />
                        <Border x:Name="StateOverlay" Background="Transparent"
                                CornerRadius="{TemplateBinding CornerRadius}" IsHitTestVisible="False" />
                        <ContentPresenter x:Name="ContentPresenter"
                                          Content="{TemplateBinding Content}"
                                          ContentTemplate="{TemplateBinding ContentTemplate}"
                                          Padding="{TemplateBinding Padding}"
                                          HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}"
                                          VerticalAlignment="{TemplateBinding VerticalContentAlignment}" />
                        <VisualStateManager.VisualStateGroups>
                            <VisualStateGroup x:Name="CommonStates">
                                <VisualState x:Name="Normal" />
                                <VisualState x:Name="PointerOver">
                                    <Storyboard>
                                        <DoubleAnimation Storyboard.TargetName="PressTransform" Storyboard.TargetProperty="ScaleX"
                                                         To="1.03" Duration="0:0:0.16">
                                            <DoubleAnimation.EasingFunction><CubicEase EasingMode="EaseOut" /></DoubleAnimation.EasingFunction>
                                        </DoubleAnimation>
                                        <DoubleAnimation Storyboard.TargetName="PressTransform" Storyboard.TargetProperty="ScaleY"
                                                         To="1.03" Duration="0:0:0.16">
                                            <DoubleAnimation.EasingFunction><CubicEase EasingMode="EaseOut" /></DoubleAnimation.EasingFunction>
                                        </DoubleAnimation>
                                        <ObjectAnimationUsingKeyFrames Storyboard.TargetName="StateOverlay" Storyboard.TargetProperty="Background">
                                            <DiscreteObjectKeyFrame KeyTime="0" Value="{StaticResource NovaAccentHoverOverlayBrush}" />
                                        </ObjectAnimationUsingKeyFrames>
                                    </Storyboard>
                                </VisualState>
                                <VisualState x:Name="Pressed">
                                    <Storyboard>
                                        <DoubleAnimation Storyboard.TargetName="PressTransform" Storyboard.TargetProperty="ScaleX"
                                                         To="0.97" Duration="0:0:0.06">
                                            <DoubleAnimation.EasingFunction><CubicEase EasingMode="EaseOut" /></DoubleAnimation.EasingFunction>
                                        </DoubleAnimation>
                                        <DoubleAnimation Storyboard.TargetName="PressTransform" Storyboard.TargetProperty="ScaleY"
                                                         To="0.97" Duration="0:0:0.06">
                                            <DoubleAnimation.EasingFunction><CubicEase EasingMode="EaseOut" /></DoubleAnimation.EasingFunction>
                                        </DoubleAnimation>
                                        <ObjectAnimationUsingKeyFrames Storyboard.TargetName="StateOverlay" Storyboard.TargetProperty="Background">
                                            <DiscreteObjectKeyFrame KeyTime="0" Value="{StaticResource NovaAccentPressedOverlayBrush}" />
                                        </ObjectAnimationUsingKeyFrames>
                                    </Storyboard>
                                </VisualState>
                                <VisualState x:Name="Disabled">
                                    <Storyboard>
                                        <DoubleAnimation Storyboard.TargetName="RootGrid" Storyboard.TargetProperty="Opacity"
                                                         To="0.42" Duration="0:0:0.16" />
                                    </Storyboard>
                                </VisualState>
                            </VisualStateGroup>
                        </VisualStateManager.VisualStateGroups>
                    </Grid>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>

    <Style x:Key="RoundedTextBoxStyle" TargetType="TextBox">
        <Setter Property="CornerRadius" Value="12" />
        <Setter Property="MinHeight" Value="36" />
        <Setter Property="Padding" Value="12,7" />
        <Setter Property="Background" Value="{ThemeResource NovaGlassInputBrush}" />
        <Setter Property="BorderBrush" Value="{ThemeResource NovaGlassInputBorderBrush}" />
        <Setter Property="FontFamily" Value="Segoe UI Variable Text" />
        <Setter Property="FontSize" Value="13" />
        <Setter Property="UseSystemFocusVisuals" Value="True" />
    </Style>
    <Style x:Key="RoundedPasswordBoxStyle" TargetType="PasswordBox">
        <Setter Property="CornerRadius" Value="12" />
        <Setter Property="MinHeight" Value="36" />
        <Setter Property="Padding" Value="12,7" />
        <Setter Property="Background" Value="{ThemeResource NovaGlassInputBrush}" />
        <Setter Property="BorderBrush" Value="{ThemeResource NovaGlassInputBorderBrush}" />
        <Setter Property="FontFamily" Value="Segoe UI Variable Text" />
        <Setter Property="UseSystemFocusVisuals" Value="True" />
    </Style>
    <Style x:Key="RoundedComboBoxStyle" TargetType="ComboBox">
        <Setter Property="CornerRadius" Value="12" />
        <Setter Property="MinHeight" Value="36" />
        <Setter Property="Background" Value="{ThemeResource ControlFillColorDefaultBrush}" />
        <Setter Property="BorderBrush" Value="{ThemeResource ControlStrokeColorDefaultBrush}" />
        <Setter Property="FontFamily" Value="Segoe UI Variable Text" />
        <Setter Property="FontSize" Value="13" />
    </Style>
    <Style x:Key="RoundedNumberBoxStyle" TargetType="NumberBox">
        <Setter Property="CornerRadius" Value="12" />
        <Setter Property="MinHeight" Value="36" />
        <Setter Property="Background" Value="{ThemeResource ControlFillColorDefaultBrush}" />
        <Setter Property="BorderBrush" Value="{ThemeResource ControlStrokeColorDefaultBrush}" />
    </Style>
    <Style x:Key="LogTextBoxStyle" TargetType="TextBox" BasedOn="{StaticResource RoundedTextBoxStyle}">
        <Setter Property="FontFamily" Value="Cascadia Mono, Consolas" />
        <Setter Property="FontSize" Value="12" />
    </Style>

    <Style x:Key="NovaNavItemStyle" TargetType="NavigationViewItem">
        <Setter Property="FontFamily" Value="Segoe UI Variable Text" />
        <Setter Property="FontSize" Value="14" />
        <Setter Property="FontWeight" Value="Medium" />
        <Setter Property="MinHeight" Value="42" />
        <Setter Property="Padding" Value="12,10" />
        <Setter Property="CornerRadius" Value="12" />
        <Setter Property="UseSystemFocusVisuals" Value="True" />
    </Style>

    <!-- Website: pill progress 999, accent gradient -->
    <Style x:Key="NovaProgressBarStyle" TargetType="ProgressBar">
        <Setter Property="CornerRadius" Value="999" />
        <Setter Property="Foreground" Value="{StaticResource NovaAccentGradientBrush}" />
        <Setter Property="Background" Value="{ThemeResource ControlFillColorSecondaryBrush}" />
        <Setter Property="Height" Value="8" />
    </Style>

    <Style x:Key="PillBorderStyle" TargetType="Border">
        <Setter Property="CornerRadius" Value="{StaticResource PillCornerRadius}" />
        <Setter Property="BorderThickness" Value="1" />
        <Setter Property="Padding" Value="10,5" />
        <Setter Property="HorizontalAlignment" Value="Left" />
        <Setter Property="VerticalAlignment" Value="Center" />
    </Style>
    <Style x:Key="PillSoftStyle" TargetType="Border" BasedOn="{StaticResource PillBorderStyle}">
        <Setter Property="Background" Value="{ThemeResource NovaBadgeBrush}" />
        <Setter Property="BorderBrush" Value="{ThemeResource NovaBadgeBorderBrush}" />
    </Style>
    <Style x:Key="PillSuccessStyle" TargetType="Border" BasedOn="{StaticResource PillBorderStyle}">
        <Setter Property="Background" Value="{ThemeResource NovaBadgeSuccessBrush}" />
        <Setter Property="BorderBrush" Value="{ThemeResource NovaBadgeSuccessBorderBrush}" />
    </Style>
    <Style x:Key="PillMutedStyle" TargetType="Border" BasedOn="{StaticResource PillBorderStyle}">
        <Setter Property="Background" Value="{ThemeResource NovaBadgeMutedBrush}" />
        <Setter Property="BorderBrush" Value="{ThemeResource NovaBadgeMutedBorderBrush}" />
    </Style>
    <Style x:Key="PillTextStyle" TargetType="TextBlock">
        <Setter Property="FontSize" Value="12" />
        <Setter Property="FontWeight" Value="SemiBold" />
        <Setter Property="VerticalAlignment" Value="Center" />
    </Style>
    <Style x:Key="EmptyStateTitleStyle" TargetType="TextBlock">
        <Setter Property="FontSize" Value="15" />
        <Setter Property="FontWeight" Value="SemiBold" />
        <Setter Property="HorizontalAlignment" Value="Center" />
        <Setter Property="Foreground" Value="{ThemeResource TextFillColorPrimaryBrush}" />
    </Style>
    <Style x:Key="IconTileStyle" TargetType="Border">
        <Setter Property="Width" Value="42" />
        <Setter Property="Height" Value="42" />
        <Setter Property="CornerRadius" Value="13" />
        <Setter Property="Background" Value="{StaticResource NovaAccentGradientBrush}" />
        <Setter Property="HorizontalAlignment" Value="Left" />
        <Setter Property="VerticalAlignment" Value="Top" />
    </Style>

    <!-- Theme chip (website theme-switch) -->
    <Style x:Key="NovaThemeChipStyle" TargetType="RadioButton">
        <Setter Property="FontSize" Value="12" />
        <Setter Property="FontWeight" Value="Bold" />
        <Setter Property="Padding" Value="12,6" />
        <Setter Property="MinHeight" Value="0" />
        <Setter Property="MinWidth" Value="0" />
        <Setter Property="Foreground" Value="{ThemeResource NovaThemeChipOffFgBrush}" />
        <Setter Property="HorizontalContentAlignment" Value="Center" />
        <Setter Property="VerticalContentAlignment" Value="Center" />
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="RadioButton">
                    <Grid Background="Transparent">
                        <Border x:Name="Chip"
                                CornerRadius="{StaticResource ChipCornerRadius}"
                                BorderThickness="1"
                                BorderBrush="{ThemeResource NovaThemeChipOffBorderBrush}"
                                Background="{ThemeResource NovaThemeChipOffBgBrush}"
                                Padding="{TemplateBinding Padding}">
                            <Border.RenderTransform>
                                <CompositeTransform x:Name="Lift" />
                            </Border.RenderTransform>
                            <ContentPresenter x:Name="Content"
                                              Content="{TemplateBinding Content}"
                                              HorizontalAlignment="Center"
                                              VerticalAlignment="Center"
                                              Foreground="{TemplateBinding Foreground}" />
                        </Border>
                        <VisualStateManager.VisualStateGroups>
                            <VisualStateGroup x:Name="CheckStates">
                                <VisualState x:Name="Checked">
                                    <Storyboard>
                                        <ObjectAnimationUsingKeyFrames Storyboard.TargetName="Chip" Storyboard.TargetProperty="Background">
                                            <DiscreteObjectKeyFrame KeyTime="0" Value="{ThemeResource NovaThemeChipOnBrush}" />
                                        </ObjectAnimationUsingKeyFrames>
                                        <ObjectAnimationUsingKeyFrames Storyboard.TargetName="Chip" Storyboard.TargetProperty="BorderBrush">
                                            <DiscreteObjectKeyFrame KeyTime="0" Value="{ThemeResource NovaThemeChipOnBrush}" />
                                        </ObjectAnimationUsingKeyFrames>
                                        <ObjectAnimationUsingKeyFrames Storyboard.TargetName="Content" Storyboard.TargetProperty="Foreground">
                                            <DiscreteObjectKeyFrame KeyTime="0" Value="{ThemeResource NovaThemeChipOnFgBrush}" />
                                        </ObjectAnimationUsingKeyFrames>
                                    </Storyboard>
                                </VisualState>
                                <VisualState x:Name="Unchecked" />
                            </VisualStateGroup>
                            <VisualStateGroup x:Name="CommonStates">
                                <VisualState x:Name="Normal" />
                                <VisualState x:Name="PointerOver">
                                    <Storyboard>
                                        <DoubleAnimation Storyboard.TargetName="Lift" Storyboard.TargetProperty="TranslateY"
                                                         To="-1" Duration="0:0:0.14">
                                            <DoubleAnimation.EasingFunction><CubicEase EasingMode="EaseOut" /></DoubleAnimation.EasingFunction>
                                        </DoubleAnimation>
                                    </Storyboard>
                                </VisualState>
                                <VisualState x:Name="Pressed">
                                    <Storyboard>
                                        <DoubleAnimation Storyboard.TargetName="Lift" Storyboard.TargetProperty="ScaleX"
                                                         To="0.97" Duration="0:0:0.06" />
                                        <DoubleAnimation Storyboard.TargetName="Lift" Storyboard.TargetProperty="ScaleY"
                                                         To="0.97" Duration="0:0:0.06" />
                                    </Storyboard>
                                </VisualState>
                            </VisualStateGroup>
                        </VisualStateManager.VisualStateGroups>
                    </Grid>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>

    <!-- Left nav item (website nav + Apple press) -->
    <Style x:Key="NovaNavItemButtonStyle" TargetType="RadioButton">
        <Setter Property="MinHeight" Value="46" />
        <Setter Property="Margin" Value="0,3" />
        <Setter Property="Padding" Value="10,8" />
        <Setter Property="HorizontalContentAlignment" Value="Stretch" />
        <Setter Property="VerticalContentAlignment" Value="Center" />
        <Setter Property="Foreground" Value="{ThemeResource TextFillColorSecondaryBrush}" />
        <Setter Property="Template">
            <Setter.Value>
                <ControlTemplate TargetType="RadioButton">
                    <Grid Background="Transparent">
                        <Border x:Name="Shell"
                                CornerRadius="14"
                                Background="Transparent"
                                Padding="{TemplateBinding Padding}"
                                RenderTransformOrigin="0.5,0.5">
                            <Border.RenderTransform>
                                <CompositeTransform x:Name="Lift" />
                            </Border.RenderTransform>
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="34" />
                                    <ColumnDefinition Width="10" />
                                    <ColumnDefinition Width="*" />
                                </Grid.ColumnDefinitions>
                                <Border x:Name="Tile" Width="34" Height="34" CornerRadius="10"
                                        Background="{ThemeResource ControlFillColorSecondaryBrush}"
                                        VerticalAlignment="Center">
                                    <FontIcon x:Name="IconGlyph" FontSize="15"
                                              Glyph="{Binding Tag, RelativeSource={RelativeSource TemplatedParent}}"
                                              Foreground="{ThemeResource AccentTextFillColorPrimaryBrush}"
                                              HorizontalAlignment="Center" VerticalAlignment="Center" />
                                </Border>
                                <TextBlock x:Name="LabelHost" Grid.Column="2"
                                           Text="{TemplateBinding Content}"
                                           VerticalAlignment="Center" FontSize="13.5" FontWeight="SemiBold"
                                           Foreground="{TemplateBinding Foreground}" />
                            </Grid>
                        </Border>
                        <VisualStateManager.VisualStateGroups>
                            <VisualStateGroup x:Name="CommonStates">
                                <VisualState x:Name="Normal" />
                                <VisualState x:Name="PointerOver">
                                    <Storyboard>
                                        <DoubleAnimation Storyboard.TargetName="Lift" Storyboard.TargetProperty="TranslateY"
                                                         To="-1" Duration="0:0:0.16">
                                            <DoubleAnimation.EasingFunction><CubicEase EasingMode="EaseOut" /></DoubleAnimation.EasingFunction>
                                        </DoubleAnimation>
                                        <ObjectAnimationUsingKeyFrames Storyboard.TargetName="Shell" Storyboard.TargetProperty="Background">
                                            <DiscreteObjectKeyFrame KeyTime="0" Value="{ThemeResource ControlFillColorSecondaryBrush}" />
                                        </ObjectAnimationUsingKeyFrames>
                                    </Storyboard>
                                </VisualState>
                                <VisualState x:Name="Pressed">
                                    <Storyboard>
                                        <DoubleAnimation Storyboard.TargetName="Lift" Storyboard.TargetProperty="ScaleX"
                                                         To="0.97" Duration="0:0:0.06" />
                                        <DoubleAnimation Storyboard.TargetName="Lift" Storyboard.TargetProperty="ScaleY"
                                                         To="0.97" Duration="0:0:0.06" />
                                    </Storyboard>
                                </VisualState>
                                <VisualState x:Name="Disabled">
                                    <Storyboard>
                                        <DoubleAnimation Storyboard.TargetName="Shell" Storyboard.TargetProperty="Opacity"
                                                         To="0.4" Duration="0:0:0.1" />
                                    </Storyboard>
                                </VisualState>
                            </VisualStateGroup>
                            <VisualStateGroup x:Name="CheckStates">
                                <VisualState x:Name="Checked">
                                    <Storyboard>
                                        <ObjectAnimationUsingKeyFrames Storyboard.TargetName="Shell" Storyboard.TargetProperty="Background">
                                            <DiscreteObjectKeyFrame KeyTime="0" Value="{ThemeResource NovaThemeChipOnBrush}" />
                                        </ObjectAnimationUsingKeyFrames>
                                        <ObjectAnimationUsingKeyFrames Storyboard.TargetName="LabelHost" Storyboard.TargetProperty="Foreground">
                                            <DiscreteObjectKeyFrame KeyTime="0" Value="{ThemeResource NovaThemeChipOnFgBrush}" />
                                        </ObjectAnimationUsingKeyFrames>
                                        <ObjectAnimationUsingKeyFrames Storyboard.TargetName="Tile" Storyboard.TargetProperty="Background">
                                            <DiscreteObjectKeyFrame KeyTime="0" Value="{ThemeResource NovaBadgeBrush}" />
                                        </ObjectAnimationUsingKeyFrames>
                                        <ObjectAnimationUsingKeyFrames Storyboard.TargetName="IconGlyph" Storyboard.TargetProperty="Foreground">
                                            <DiscreteObjectKeyFrame KeyTime="0" Value="{ThemeResource NovaThemeChipOnFgBrush}" />
                                        </ObjectAnimationUsingKeyFrames>
                                    </Storyboard>
                                </VisualState>
                                <VisualState x:Name="Unchecked" />
                            </VisualStateGroup>
                        </VisualStateManager.VisualStateGroups>
                    </Grid>
                </ControlTemplate>
            </Setter.Value>
        </Setter>
    </Style>

    <!-- Page entrance (website .rise): scale 0.98 → 1 + fade -->
    <Style x:Key="NovaRiseStyle" TargetType="FrameworkElement">
        <Setter Property="RenderTransformOrigin" Value="0.5,0.5" />
    </Style>
</ResourceDictionary>
'''

(UI / "Styles" / "Theme.xaml").write_bytes(b"\xef\xbb\xbf" + theme.encode("utf-8"))
print("Theme.xaml rewritten", len(theme))
