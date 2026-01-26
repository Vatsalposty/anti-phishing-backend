
Add-Type -AssemblyName System.Drawing

$sourcePath = "extension\icons\shield_v129.png"
$icon128Path = "extension\icons\icon128.png"
$icon48Path = "extension\icons\icon48.png"
$icon16Path = "extension\icons\icon16.png"

# Ensure source exists
if (-not (Test-Path $sourcePath)) {
    Write-Error "Source file $sourcePath not found."
    exit 1
}

$image = [System.Drawing.Image]::FromFile($sourcePath)

# Save 128x128 (Just copy or save)
$image.Save($icon128Path, [System.Drawing.Imaging.ImageFormat]::Png)
Write-Host "Created $icon128Path"

# Resize to 48x48
$rect48 = New-Object System.Drawing.Rectangle 0, 0, 48, 48
$bitmap48 = New-Object System.Drawing.Bitmap 48, 48
$graphics48 = [System.Drawing.Graphics]::FromImage($bitmap48)
$graphics48.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$graphics48.DrawImage($image, $rect48)
$bitmap48.Save($icon48Path, [System.Drawing.Imaging.ImageFormat]::Png)
$graphics48.Dispose()
$bitmap48.Dispose()
Write-Host "Created $icon48Path"

# Resize to 16x16
$rect16 = New-Object System.Drawing.Rectangle 0, 0, 16, 16
$bitmap16 = New-Object System.Drawing.Bitmap 16, 16
$graphics16 = [System.Drawing.Graphics]::FromImage($bitmap16)
$graphics16.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$graphics16.DrawImage($image, $rect16)
$bitmap16.Save($icon16Path, [System.Drawing.Imaging.ImageFormat]::Png)
$graphics16.Dispose()
$bitmap16.Dispose()
Write-Host "Created $icon16Path"

$image.Dispose()
