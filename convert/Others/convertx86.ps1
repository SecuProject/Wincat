#Remove-Item .\StructHeader.h
$currentPath = (Get-Location).Path
Get-ChildItem "exeX86" -Filter *.exe |Foreach-Object{
    $currentExe = $_
    $name = $currentExe -replace ".exe"
    $nameUPX = "comp\"+ $name +"UPX.exe"
    $nameCAB = "comp\"+ $name +"CAB.exe"
    $headerPath = "../Wincat/PeFile/"+ $name +".h"
    Remove-Item $nameUPX    2>$null
    Remove-Item $headerPath 2>$null
    ./Others/upx -qqq -o $nameUPX -9 $currentExe.FullName
    if(!$?){
        Copy-Item $currentExe.FullName $nameUPX
    }
    ./Others/DefenderCheckC.exe -f "$currentPath\$nameUPX"
    ./Others/CabCompression.exe $nameUPX $nameCAB
    ./Others/FileToHex.exe -i $nameCAB -o $headerPath -n "$name"
}

Get-ChildItem "PowershellScript" -Filter *.ps1 |Foreach-Object{
    $currentPs = $_
    
    $name = $currentPs -replace ".ps1"
    $nameCAB = "comp\"+ $name +"CAB.ps1"
    $headerPath = "../Wincat/PsScript/"+ $name +".h"
    Remove-Item $headerPath 2>$null
    
    ./Others/DefenderCheckC.exe -f $currentPs.FullName
    ./Others/CabCompression.exe $currentPs.FullName $nameCAB
    ./Others/FileToHex.exe -i $nameCAB -o $headerPath -n "$name"
}