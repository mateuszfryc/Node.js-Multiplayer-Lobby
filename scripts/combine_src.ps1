# Define the directory to search (current directory)
$sourceDirectory = Get-Location

# Define the output file
$outputFile = "$sourceDirectory\combined.js"

# Remove the output file if it already exists
if (Test-Path $outputFile) {
    Remove-Item $outputFile
}

# Recursively get all .js files
$jsFiles = Get-ChildItem -Path $sourceDirectory -Recurse -Filter "*.js"

# Loop through each file and append its content to the output file
foreach ($file in $jsFiles) {
    # Append a comment indicating the source file
    Add-Content -Path $outputFile -Value "// File: $($file.FullName)"

    # Append the content of the file
    Get-Content -Path $file.FullName | Add-Content -Path $outputFile

    # Add a newline for separation between files
    Add-Content -Path $outputFile -Value "`n"
}

Write-Host "All JavaScript files have been combined into $outputFile"
