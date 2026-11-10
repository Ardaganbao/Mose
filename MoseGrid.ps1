# MoseGrid: carry a file off a locked-down server through the screen, when no file transfer is
# allowed. QrReport.ps1 shows the report as one or more black-and-white grids of modules; QrReceive.ps1
# captures them from the remote-session window on the technician's computer and writes the file back.
#
# The data is compressed (raw Deflate), split into chunks, and each chunk is protected with Reed-Solomon
# error correction and a CRC, so a chunk still reads back when the remote session blurs a few modules;
# the whole file carries a SHA-256, checked once every chunk is in. A grid is read only by this decoder
# (it is not a standard QR code): the capture is of screen pixels, square and unrotated, so the decoder
# needs no camera, perspective or rotation handling.
#
# This file holds only the data functions (no window): QrReport.ps1 and QrReceive.ps1 dot-source it,
# and tests\Test-MoseGrid.ps1 checks the round-trip. It contacts nothing and reads no vault.

Set-StrictMode -Version Latest

# --- Reed-Solomon over GF(256), primitive polynomial 0x11D (as QR and most codes use) ---------------

$script:GfExp = New-Object 'int[]' 512
$script:GfLog = New-Object 'int[]' 256
$x = 1
for ($i = 0; $i -lt 255; $i++) {
    $script:GfExp[$i] = $x
    $script:GfLog[$x] = $i
    $x = $x -shl 1
    if ($x -band 0x100) {
        $x = $x -bxor 0x11D
    }
}
for ($i = 255; $i -lt 512; $i++) {
    $script:GfExp[$i] = $script:GfExp[$i - 255]
}

function Get-GfMul {
    param([int]$A, [int]$B)
    if ($A -eq 0 -or $B -eq 0) {
        return 0
    }
    return $script:GfExp[$script:GfLog[$A] + $script:GfLog[$B]]
}

function Get-GfDiv {
    param([int]$A, [int]$B)
    if ($B -eq 0) {
        throw 'Division by zero in GF(256).'
    }
    if ($A -eq 0) {
        return 0
    }
    return $script:GfExp[($script:GfLog[$A] + 255 - $script:GfLog[$B]) % 255]
}

# The generator polynomial for $Count parity symbols: (x - a^0)(x - a^1)...(x - a^(Count-1)).
function Get-RsGenerator {
    param([int]$Count)
    $generator = @(1)
    for ($i = 0; $i -lt $Count; $i++) {
        $next = New-Object 'int[]' ($generator.Count + 1)
        for ($j = 0; $j -lt $generator.Count; $j++) {
            $next[$j] = $next[$j] -bxor $generator[$j]
            $next[$j + 1] = $next[$j + 1] -bxor (Get-GfMul $generator[$j] $script:GfExp[$i])
        }
        $generator = $next
    }
    return $generator
}

# The $Count Reed-Solomon parity bytes for $Data (a byte array).
function Get-RsParity {
    param([byte[]]$Data, [int]$Count)
    $generator = Get-RsGenerator -Count $Count
    $remainder = New-Object 'int[]' $Count
    foreach ($byte in $Data) {
        $factor = $byte -bxor $remainder[0]
        for ($i = 0; $i -lt $Count - 1; $i++) {
            $remainder[$i] = $remainder[$i + 1] -bxor (Get-GfMul $generator[$i + 1] $factor)
        }
        $remainder[$Count - 1] = Get-GfMul $generator[$Count] $factor
    }
    return [byte[]]$remainder
}

# Multiplies two GF(256) polynomials (coefficient arrays, highest degree first).
function Get-GfPolyMul {
    param([int[]]$A, [int[]]$B)
    $result = New-Object 'int[]' ($A.Count + $B.Count - 1)
    for ($i = 0; $i -lt $A.Count; $i++) {
        for ($j = 0; $j -lt $B.Count; $j++) {
            $result[$i + $j] = $result[$i + $j] -bxor (Get-GfMul $A[$i] $B[$j])
        }
    }
    return $result
}

# Evaluates a GF(256) polynomial (highest degree first) at $X.
function Get-GfPolyEval {
    param([int[]]$Poly, [int]$X)
    $y = $Poly[0]
    for ($i = 1; $i -lt $Poly.Count; $i++) {
        $y = (Get-GfMul $y $X) -bxor $Poly[$i]
    }
    return $y
}

# Corrects up to $Count/2 wrong bytes in $Message (data followed by $Count parity bytes), returning the
# corrected data bytes only, or $null when there are too many errors to correct. Berlekamp-Massey finds
# the error locator, Chien search its roots (the error positions), and Forney the values to fix.
function Repair-RsMessage {
    param([byte[]]$Message, [int]$Count)

    $message = [int[]]$Message
    # Syndromes: the received polynomial at a^0..a^(Count-1); all zero means no error.
    $syndromes = New-Object 'int[]' $Count
    $anyError = $false
    for ($i = 0; $i -lt $Count; $i++) {
        $syndromes[$i] = Get-GfPolyEval -Poly $message -X $script:GfExp[$i]
        if ($syndromes[$i] -ne 0) {
            $anyError = $true
        }
    }
    if (-not $anyError) {
        return [byte[]]$message[0..($message.Count - $Count - 1)]
    }

    # Berlekamp-Massey: the error locator polynomial (highest degree first after reversal below).
    $locator = @(1)
    $previous = @(1)
    $shift = 1
    $b = 1
    for ($n = 0; $n -lt $Count; $n++) {
        $delta = $syndromes[$n]
        for ($i = 1; $i -lt $locator.Count; $i++) {
            $delta = $delta -bxor (Get-GfMul $locator[$locator.Count - 1 - $i] $syndromes[$n - $i])
        }
        if ($delta -eq 0) {
            $shift++
        }
        elseif (2 * ($locator.Count - 1) -le $n) {
            $temp = $locator
            $scaled = @($previous | ForEach-Object { Get-GfMul $_ (Get-GfDiv $delta $b) })
            $locator = Update-RsLocator -Locator $locator -Scaled $scaled -Shift $shift
            $previous = $temp
            $b = $delta
            $shift = 1
        }
        else {
            $scaled = @($previous | ForEach-Object { Get-GfMul $_ (Get-GfDiv $delta $b) })
            $locator = Update-RsLocator -Locator $locator -Scaled $scaled -Shift $shift
            $shift++
        }
    }

    $errorCount = $locator.Count - 1
    if ($errorCount -gt [math]::Floor($Count / 2)) {
        return $null
    }

    # Chien search: positions i where the locator has a root at a^-i.
    $positions = @()
    for ($i = 0; $i -lt $message.Count; $i++) {
        if ((Get-GfPolyEval -Poly $locator -X $script:GfExp[(255 - $i) % 255]) -eq 0) {
            $positions += ($message.Count - 1 - $i)
        }
    }
    if ($positions.Count -ne $errorCount) {
        return $null
    }

    # Forney: the error value at each position, from the syndrome and error-evaluator polynomials.
    $syndromePoly = @()
    for ($i = $Count - 1; $i -ge 0; $i--) {
        $syndromePoly += $syndromes[$i]
    }
    $evaluator = Get-GfPolyMul -A $syndromePoly -B $locator
    $evaluator = @($evaluator[($evaluator.Count - $Count)..($evaluator.Count - 1)])
    # Formal derivative of the locator: keep the odd-position coefficients.
    $derivative = @()
    for ($i = $locator.Count - 1; $i -ge 0; $i--) {
        if (((($locator.Count - 1) - $i) % 2) -eq 1) {
            $derivative += $locator[$i]
        }
        else {
            $derivative += 0
        }
    }
    $derivative = @($derivative[0..($derivative.Count - 2)])

    foreach ($position in $positions) {
        $xInverse = $script:GfExp[(255 - (($message.Count - 1 - $position) % 255)) % 255]
        $numerator = Get-GfPolyEval -Poly $evaluator -X $xInverse
        $denominator = Get-GfPolyEval -Poly $derivative -X $xInverse
        if ($denominator -eq 0) {
            return $null
        }
        $magnitude = Get-GfDiv $numerator $denominator
        $message[$position] = $message[$position] -bxor $magnitude
    }

    # Check the correction really cleared the syndromes.
    for ($i = 0; $i -lt $Count; $i++) {
        if ((Get-GfPolyEval -Poly $message -X $script:GfExp[$i]) -ne 0) {
            return $null
        }
    }
    return [byte[]]$message[0..($message.Count - $Count - 1)]
}

# One Berlekamp-Massey update: locator XOR (scaled shifted by $Shift).
function Update-RsLocator {
    param([int[]]$Locator, [int[]]$Scaled, [int]$Shift)
    $length = [math]::Max($Locator.Count, $Scaled.Count + $Shift)
    $result = New-Object 'int[]' $length
    for ($i = 0; $i -lt $Locator.Count; $i++) {
        $result[$i + ($length - $Locator.Count)] = $Locator[$i]
    }
    for ($i = 0; $i -lt $Scaled.Count; $i++) {
        $index = $i + ($length - $Scaled.Count - $Shift)
        $result[$index] = $result[$index] -bxor $Scaled[$i]
    }
    # Drop leading zeros so the degree stays right.
    $start = 0
    while ($start -lt $result.Count - 1 -and $result[$start] -eq 0) {
        $start++
    }
    return @($result[$start..($result.Count - 1)])
}

# --- CRC-32 (the usual polynomial, as zip and PNG) --------------------------------------------------

$script:Crc32Table = New-Object 'uint32[]' 256
for ($n = 0; $n -lt 256; $n++) {
    $c = [uint32]$n
    for ($k = 0; $k -lt 8; $k++) {
        if ($c -band 1) {
            $c = [uint32](0xEDB88320 -bxor ($c -shr 1))
        }
        else {
            $c = [uint32]($c -shr 1)
        }
    }
    $script:Crc32Table[$n] = $c
}

function Get-Crc32 {
    param([byte[]]$Data)
    $crc = [uint32]0xFFFFFFFF
    foreach ($byte in $Data) {
        $crc = [uint32]($script:Crc32Table[($crc -bxor $byte) -band 0xFF] -bxor ($crc -shr 8))
    }
    return [uint32]($crc -bxor 0xFFFFFFFF)
}
