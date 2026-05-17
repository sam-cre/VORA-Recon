$pngPath = "assets\logo.png"
$icoPath = "assets\logo.ico"

if (-not (Test-Path $pngPath)) {
    Write-Error "Source PNG not found at $pngPath"
    exit 1
}

$pngBytes = [System.IO.File]::ReadAllBytes($pngPath)
$pngSize = $pngBytes.Length

# ICO Header (6 bytes): Reserved(2), Type(2), Count(2)
$header = [byte[]](0, 0, 1, 0, 1, 0)

# Directory Entry (16 bytes):
# Width(1), Height(1), Colors(1), Reserved(1), Planes(2), BPP(2), Size(4), Offset(4)
$entry = New-Object byte[] 16
$entry[0] = 0 # Width 256 (0 means 256)
$entry[1] = 0 # Height 256 (0 means 256)
$entry[2] = 0 # Colors
$entry[3] = 0 # Reserved
$entry[4] = 1 # Planes
$entry[5] = 0
$entry[6] = 32 # Bits Per Pixel
$entry[7] = 0

# Size (4 bytes, Little Endian)
$sizeBytes = [BitConverter]::GetBytes($pngSize)
[Array]::Copy($sizeBytes, 0, $entry, 8, 4)

# Offset (4 bytes, Little Endian). Offset is 22 bytes (6 header + 16 entry)
$offsetBytes = [BitConverter]::GetBytes(22)
[Array]::Copy($offsetBytes, 0, $entry, 12, 4)

# Write the final ICO file
$icoStream = [System.IO.File]::Create($icoPath)
$icoStream.Write($header, 0, $header.Length)
$icoStream.Write($entry, 0, $entry.Length)
$icoStream.Write($pngBytes, 0, $pngBytes.Length)
$icoStream.Close()

Write-Host "Success: Created high-quality 256x256 ICO from $pngPath ($($pngSize) bytes)"
