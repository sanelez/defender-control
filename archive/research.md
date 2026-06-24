## Reversal
I reversed parts of the freeware with some hooks & x64 debugger, read a bunch of security papers & here are some of my findings!

## x64 Debug 
### disabling defender

```asm
008CE9E8  043DCA88  L"HKLM64"
...
008CEA08  043DCBC0  L"SOFTWARE\\Policies\\Microsoft\\Windows Defender"

008CE8F0  043DCFE8  L"HKLM64"
...
008CE910  043DD120  L"SYSTEM\\CurrentControlSet\\Services\\WinDefend"

76122F7F | 397D 0C                  | cmp dword ptr ss:[ebp+C],edi            | [ebp+C]:L"Start"`

https://answers.microsoft.com/en-us/protect/forum/protect_defender-protect_start-windows_10/how-to-disable-windows-defender-in-windows-10/b834d36e-6da8-42a8-85f6-da9a520f05f2

76122FF0 | 8945 CC                  | mov dword ptr ss:[ebp-34],eax           | [ebp-34]:L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run"
76122FF3 | 66:8B01                  | mov ax,word ptr ds:[ecx]                | ecx:&L"SecurityHealth"

EDX : 043DCD78     L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection"
EIP : 7591E420     <advapi32.RegCreateKeyExW>

We have 2 flags set:
DisableRealtimeMonitoring as a REG_DWORD set to 0x01
DpaDisabled as REG_DWORD set to 0x0

008CEFF8  043EB4C8  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run"
```

### enabling defender

there seems to be a reference with "Policy Manager" using RegEnumKeyExW  

It seems to call RegDeleteValueW on security health (see above)  


## reversing w hooks
We are going to write a simple dll to inject into defender control to dump out the parameters of the functions we are interested in.  

Here are the logs:  

```asm
obtained RegDeleteKeyW from 75A60000
obtained RegDeleteValueW from 75A60000
obtained RegEnumValueW from 75A60000
obtained RegSetValueExW from 75A60000
obtained RegCreateKeyExW from 75A60000
obtained RegConnectRegistryW from 75A60000
obtained RegEnumKeyExW from 75A60000
obtained RegQueryValueExW from 75A60000
obtained RegOpenKeyExW from 75A60000
imports resolved
preparing to hook

Registry Routine to check if defender activated:

[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
[RegQueryValueExW]
lpValueName: C:\Program Files (x86)\DefenderControl\dControl.exe

Routine to disable defender

[RegCreateKeyExW]
lpSubKey: SOFTWARE\Policies\Microsoft\Windows Defender
[RegSetValueExW]
lpValueName: DisableAntiSpyware
[RegCreateKeyExW]
lpSubKey: SOFTWARE\Microsoft\Windows Defender
[RegCreateKeyExW]
lpSubKey: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegCreateKeyExW]
lpSubKey: SYSTEM\CurrentControlSet\Services\WinDefend
[RegSetValueExW]
lpValueName: Start
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
[RegQueryValueExW]
lpValueName: SecurityHealth
[RegQueryValueExW]
lpValueName: SecurityHealth
[RegCreateKeyExW]
lpSubKey: SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run
[RegSetValueExW]
lpValueName: SecurityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
[RegEnumValueW]
lpValueName: SecurityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
[RegQueryValueExW]
lpValueName: C:\Program Files (x86)\DefenderControl\dControl.exe

Routine to enable defender

[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegOpenKeyExW]
lpValueName: SYSTEM\CurrentControlSet\Services\SecLogon
[RegQueryValueExW]
lpValueName: Start
[RegQueryValueExW]
lpValueName: Start
[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
[RegEnumValueW]
lpValueName: SecurityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
[RegQueryValueExW]
lpValueName: SecurityHealth
[RegQueryValueExW]
lpValueName: SecurityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run
[RegDeleteValueW]
lpValueNameSecurityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
[RegEnumValueW]
lpValueName: SecurityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
[RegQueryValueExW]
lpValueName: WindowsDefender
[RegQueryValueExW]
lpValueName: WindowsDefender
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
[RegEnumValueW]
lpValueName: WindowsDefender
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
[RegQueryValueExW]
lpValueName: C:\Program Files (x86)\DefenderControl\dControl.exe
<also redacted a bunch of stuff from policy manager stuff>
-----
SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
DisableRealtimeMonitoring
```
  
When it disables the AV it modifies these registries:  

```asm
[RegCreateKeyExW]
lpSubKey: SOFTWARE\Policies\Microsoft\Windows Defender
[RegSetValueExW]
lpValueName: DisableAntiSpyware
[RegCreateKeyExW]
lpSubKey: SOFTWARE\Microsoft\Windows Defender
[RegCreateKeyExW]
lpSubKey: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegCreateKeyExW]
lpSubKey: SYSTEM\CurrentControlSet\Services\WinDefend
[RegSetValueExW]
lpValueName: Start
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
[RegQueryValueExW]
lpValueName: SecurityHealth
[RegCreateKeyExW]
lpSubKey: SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run
[RegSetValueExW]
lpValueName: SecurityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
[RegEnumValueW]
lpValueName: SecurityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
```

### Dumping VTable Calls
```asm
[Control Table] 0x495b78
[Control Table] 0x493658
[Control Table] 0x4932f8
[Control Table] 0x494e1c
[Control Table] 0x4949e4
[Control Table] 0x4965e0
[Control Table] 0x496088
[Control Table] 0x4951c4
[Control Table] 0x4960d0
[Control Table] 0x49463c
[Control Table] 0x493808
[Control Table] 0x493850
[Control Table] 0x494ed0
[Control Table] 0x49382c
[Control Table] 0x49532c
[Control Table] 0x493874
[Control Table] 0x493898
[Control Table] 0x4931fc
[Control Table] 0x4931b4
[Control Table] 0x495500
[Control Table] 0x495cbc
[Control Table] 0x495ce0
[Control Table] 0x4958cc
[Control Table] 0x494a74
[Control Table] 0x495c08
[Control Table] 0x494cfc
[Control Table] 0x493c40
[Control Table] 0x493e5c
[Control Table] 0x493ea4
[Control Table] 0x493b8c
[Control Table] 0x495b0c
[Control Table] 0x495c2c
[Control Table] 0x493f7c
[Control Table] 0x4930dc
[Control Table] 0x493fe8
[Control Table] 0x494c00
[Control Table] 0x495644
[Control Table] 0x495428
[Control Table] 0x496430
[Control Table] 0x4963e8
[Control Table] 0x4954b8
[Control Table] 0x4945d0
[Control Table] 0x496040
[Control Table] 0x4960ac
[Control Table] 0x494a50
[Control Table] 0x495be4
```


Upon starting the AV, the program calls CreateProcessW on C:\Windows\System32\SecurityHealthSystray.exe

## Windows File Protection

But theres, a catch. In a newer recent windows update - you can no longer disable the defender via registries without elevated permissions.  
Well, our program runs completely in usermode, so there must be another way its making these registry changes - most likely through the powershell command  Set-MpPreference if we do some research into changing the registry. So we will need to take a peek into the wmic api it accesses. 

Luckily for us, all this stuff is documented. Check out these two links:  
- https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2019-ps
- https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-c---application-examples

I first wanted to see how powershell called the command, so i looked through the powershell github since its open sourced and found that the command was in a cmdlet that was not documented in the repository. So after reading up on some powershell commands I dumped the powershell informating using this:

```asm
Get-Command Set-MpPreference | fl
```

If we wanted to read the MSFT_MpPreference class, it is documented here:
https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/dn455323(v=vs.85)#requirements  
We can access via powershell like so:  

```asm
Get-WmiObject -ClassName MSFT_MpPreference -Namespace root/microsoft/windows/defender
```

If we look further we can write to this using the WMI - it is documented here:
https://docs.microsoft.com/en-us/previous-versions/windows/desktop/defender/windows-defender-wmiv2-apis-portal  

We can find the specific wmi com classes if we do the following command:
  
`MpPreference |fl *`

We get an output and we are intrested in this:

```asm
CimClass                                      : root/Microsoft/Windows/Defender:MSFT_MpPreference
CimInstanceProperties                         : {AllowDatagramProcessingOnWinServer, AllowNetworkProtectionDownLevel,
                                                AllowNetworkProtectionOnWinServer,
                                                AttackSurfaceReductionOnlyExclusions...}
CimSystemProperties                           : Microsoft.Management.Infrastructure.CimSystemProperties
```

We can find the class here: https://docs.microsoft.com/en-us/dotnet/api/microsoft.management.infrastructure.cimsystemproperties?view=powershellsdk-7.0.0

It is also located in windows binaries in the following path: C:\Program Files (x86)\Reference Assemblies\Microsoft\WMI\v1.0 

Here is an intersting article that got me started in understanding the WMI: https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf

## Gaining permission
Remeber when I said you need more permissions to edit certain registries and edit services?  
Well there is! 
You can read more about it here: https://0x00-0x00.github.io/research/2018/10/17/Windows-API-and-Impersonation-Part1.html  

We adapt it into C++ code which can be found in trusted. Then using an elevated process, we can now edit those registries we can't before!.

## Windows Tamper Protection
Well. We can once we disable tamper protection... But to do that without going through the security menu - we need to first kill the windefend service. Luckily now that we have TrustedInstaller privillege we can directly do that using winapi.

### Windows 11

New dump:

```asm
obtained RegDeleteKeyW from 75DD0000
obtained RegDeleteValueW from 75DD0000
obtained RegEnumValueW from 75DD0000
obtained RegSetValueExW from 75DD0000
obtained RegCreateKeyExW from 75DD0000
obtained RegConnectRegistryW from 75DD0000
obtained RegEnumKeyExW from 75DD0000
obtained RegQueryValueExW from 75DD0000
obtained RegOpenKeyExW from 75DD0000
obtained CreateProcessW from 76000000
obtained ShellExecuteExW from 76DE0000
imports resolved
preparing to hook

IDLE:


[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: C:\Program Files (x86)\DefenderControl\dControl.exe



---


[RegQueryValueExW]
lpValueName: C:\Program Files (x86)\DefenderControl\dControl.exe
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdFilter
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdNisDrv
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdNisSvc
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Policies\Microsoft\Windows Defender
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE754
Ret: 0
[RegSetValueExW]
lpValueName: DisableAntiSpyware
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Policies\Microsoft\Windows Defender
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE754
Ret: 0
[RegSetValueExW]
lpValueName: DisableAntiVirus
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Microsoft\Windows Defender
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE664
Ret: 0
[RegSetValueExW]
lpValueName: DisableAntiSpyware
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Microsoft\Windows Defender
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CEB54
Ret: 0
[RegSetValueExW]
lpValueName: DisableAntiVirus
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE754
Ret: 0
[RegSetValueExW]
lpValueName: DisableRealtimeMonitoring
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WinDefend
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CEA94
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdFilter
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdNisDrv
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdNisSvc
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WinDefend
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE834
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Policies\Microsoft\Windows Defender
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE8E4
Ret: 0
[RegSetValueExW]
lpValueName: DisableAntiSpyware
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Policies\Microsoft\Windows Defender
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE8E4
Ret: 0
[RegSetValueExW]
lpValueName: DisableAntiVirus
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Microsoft\Windows Defender
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE7F4
Ret: 0
[RegSetValueExW]
lpValueName: DisableAntiSpyware
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Microsoft\Windows Defender
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CECE4
Ret: 0
[RegSetValueExW]
lpValueName: DisableAntiVirus
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE8E4
Ret: 0
[RegSetValueExW]
lpValueName: DisableRealtimeMonitoring
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: SecurityHealth
[RegQueryValueExW]
lpValueName: SecurityHealth
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CEDD4
Ret: 0
[RegSetValueExW]
lpValueName: SecurityHealth
Reserved: 0
dwType: 3
cbData: 12
Ret: 0
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegEnumValueW]
lpValueName:→0‼rityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: Riot Vanguard
[RegQueryValueExW]
lpValueName: Riot Vanguard
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegEnumValueW]
lpValueName:→0‼ Vanguard
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mpcmdrun.exe
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE8CC
Ret: 0
[RegSetValueExW]
lpValueName: Debugger
Reserved: 0
dwType: 1
cbData: 64
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mpcmdrun.exe
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE7C4
Ret: 0
[RegSetValueExW]
lpValueName: Debugger
Reserved: 0
dwType: 1
cbData: 64
Ret: 0
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mpcmdrun.exe
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: Debugger
[RegQueryValueExW]
lpValueName: Debugger
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WinDefend
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE834
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0


---

ENABLE:

[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdFilter
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdNisDrv
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdNisSvc
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
ulOptions: 0
samDesired: 131103
[RegEnumKeyExW]
lpName: ì☻♦
[RegOpenKeyExW]
lpValueName: Policy Manager
ulOptions: 0
samDesired: 131097
[RegEnumKeyExW]
lpName: ═☻♦
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
ulOptions: 0
samDesired: 131359
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
ulOptions: 0
samDesired: 131359
[RegDeleteValueW]
lpValueNameDisableAntiSpyware
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
ulOptions: 0
samDesired: 131359
[RegDeleteValueW]
lpValueNameDisableAntiVirus
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
ulOptions: 0
samDesired: 131359
[RegDeleteValueW]
lpValueNameDisableRealtimeMonitoring
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
ulOptions: 0
samDesired: 131359
[RegDeleteValueW]
lpValueNameDisableAntiSpywareRealtimeProtection
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WinDefend
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE834
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdFilter
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdNisDrv
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 5
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdNisSvc
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 5
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WinDefend
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE834
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 5
[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
ulOptions: 0
samDesired: 131103
[RegEnumKeyExW]
lpName: ]☻♦
lpValueName: DisableAntiSpyware
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[CreateProcessW]
lpCommandLine: "C:\j\bin\dControl\w11 fix\dfControl.exe" /EXP |6324|
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegEnumValueW]
lpValueName: h.°$♀
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: SecurityHealth
[RegQueryValueExW]
lpValueName: SecurityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run
ulOptions: 0
samDesired: 131359
[RegDeleteValueW]
lpValueNameSecurityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegEnumValueW]
lpValueName: h.°$rityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: Riot Vanguard
[RegQueryValueExW]
lpValueName: Riot Vanguard
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegEnumValueW]
lpValueName: h.°$ Vanguard
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mpcmdrun.exe
ulOptions: 0
samDesired: 131359
[RegEnumKeyExW]
lpName: ♣☻♦
[RegOpenKeyExW]
lpValueName: SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mpcmdrun.exe
ulOptions: 0
samDesired: 131359
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mpcmdrun.exe
ulOptions: 0
samDesired: 131353
[CreateProcessW]
lpCommandLine: C:\Program Files\Windows Defender\mpcmdrun.exe -wdenable
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
ulOptions: 0
samDesired: 131353

```



## Conclusion
Well thats all there is to disabling defender... TLDR: We gain TrustedInstaller permission, disable the windefend service and modify the registries & make calls to the wmi to our hearts content.

## Relevant links:
- https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf
- https://0x00-0x00.github.io/research/2018/10/17/Windows-API-and-Impersonation-Part1.html  
- http://myne-us.blogspot.cz/2012/08/reverse-engineering-powershell-cmdlets.html

---

# 2026 Update Plan — privacy.sexy Cross-Reference

This section catalogues the full 2026 Defender-disabling surface (extracted from a
privacy.sexy v0.13.8 export, 212 technique sections) and cross-references it against the
current `dcontrol.cpp` implementation. It is the working plan for bringing the project
up to date.

## Mechanism overview

privacy.sexy uses four mechanism types. The current code implements ~2.5 of them:

| Mechanism | In research | In current code |
|---|---|---|
| Registry policy/value writes (~95 keys) | yes | mostly |
| Service disable (`Set-Service` / `Start=4`) | ~20 services | yes (registry `Start=4`) |
| **Soft-delete binaries** (takeown + rename `.sys`/`.dll`/`.exe`) | 101 files | **none** |
| **Disable scheduled tasks** | 5 tasks | **none** |

The code substitutes binary deletion with **IFEO debugger hijack** + **DisallowRun** +
**process kill**. Valid alternative, but functionally weaker (Defender binaries remain on
disk and can be relaunched by other triggers).

## Already implemented correctly (matches research)

- **Cloud / MAPS / telemetry**: `DisableBlockAtFirstSeen`, `MpBafsExtendedTimeout=50`,
  `MpCloudBlockLevel=0`, `SpynetReporting=0`, `LocalSettingOverrideSpynetReporting=0`,
  `SubmitSamplesConsent=2`, `MAPSReporting=0`, `DisableCoreService1DSTelemetry=1`,
  `DisableCoreServiceECSIntegration=1`
- **Real-Time Protection**: all 10 RTP keys (`DisableRealtimeMonitoring`,
  `DisableBehaviorMonitoring`, `DisableIOAVProtection`, `DisableOnAccessProtection`,
  `DisableIntrusionPreventionSystem`, `DisableScanOnRealtimeEnable`,
  `DisableRawWriteNotification`, `DisableInformationProtectionControl`, `IOAVMaxSize=1`,
  `RealTimeScanDirection=1`)
- **NIS**: `DisableProtocolRecognition`, `DisableSignatureRetirement`,
  `ThrottleDetectionEventsRate=10000000`
- **Signature updates**: every value matches, including the counterintuitive ones the
  research itself uses (`ForceUpdateFromMU=1`, `UpdateOnStartUp=1`,
  `SignatureUpdateInterval=24`, `ASSignatureDue`/`AVSignatureDue=0xFFFFFFFF`) and
  Microsoft's literal misspelling `DisableGenericRePorts`
- **Threats**: `Threats_ThreatSeverityDefaultAction=1` + per-severity `1`-`5`=`9`
- **Scan (partial)**: `DisableHeuristics`, `DisableArchiveScanning`, `DisableEmailScanning`,
  `DisableRemovableDriveScanning`, `DisablePackedExeScanning`, `DisableScanningNetworkFiles`,
  `DisableScanningMappedNetworkDrivesForFullScan`, `DisableReparsePointScanning`,
  `DisableRestorePoint`, `DisableCatchupFullScan`, `DisableCatchupQuickScan`, `ScheduleDay=8`,
  `AvgCPULoadFactor=1`, `ScanOnlyIfIdle=1`, `CheckForSignaturesBeforeRunningScan=0`,
  `PurgeItemsAfterDelay=1`
- **AMSI**: HKCU `Windows Script\Settings\AmsiEnable=0`
- **ETW**: `DefenderApiLogger`/`DefenderAuditLogger` autologgers, WINEVT Operational/WHC channels
- **Quarantine** purge, **MRT** (both keys), `ServiceKeepAlive`/`AllowFastServiceStartup`
  (both Defender + Microsoft Antimalware paths)
- **WTDS** components + feature flags, **App Guard** (`AppHVSI`), **Exploit Guard** NP+CFA,
  **IE SmartScreen** zones, **Legacy Edge** PhishingFilter, full **Edge** SmartScreen policy
  set, **UX lockdown**, all Security Center UI section lockdowns, **notifications**, systray
- **IFEO** debugger list (13 exes) maps ~1:1 onto the exes privacy.sexy soft-deletes

## Missing — Tier 1 (whole categories)

1. **Binary soft-deletion (101 files)** — the research's primary persistence mechanism.
   Requires TrustedInstaller takeown + rename (to `.old`) with rollback support. Notable
   targets: `WdFilter.sys`, `WdBoot.sys`, `MsMpEng.exe`, `mpengine.dll`, `MpRtp.dll`,
   `MpOav.dll` (AMSI provider), `MpClient.dll`, `MpSvc.dll`, the Security Health DLLs,
   `smartscreen.exe` + libs, `webthreatdefsvc.dll`. (Full list extracted; ~101 entries.)
2. **Scheduled task disabling (5)** —
   `\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance`,
   `... Cleanup`, `... Scheduled Scan`, `... Verification`, and
   `\Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh`.
3. **VBS / HVCI / Device Guard (~16 keys)** —
   `EnableVirtualizationBasedSecurity=0`, `RequirePlatformSecurityFeatures=0`, HVCI
   scenarios, `Locked/Unlocked/Mandatory/NoLock`. Currently untouched.
4. **Firewall** — `EnableFirewall=0` across all 4 profiles in both
   `Policies\...\WindowsFirewall` and `SharedAccess\...\FirewallPolicy`; services `mpsdrv`
   + `MpsSvc` not in the service list; netsh disable. (Optional — breaks Store/winget/
   WSL/Docker/Sandbox.)
5. **System Guard startup verification** —
   `DeviceGuard\ConfigureSystemGuardLaunch=2` (policy) and
   `Scenarios\SystemGuard\Enabled=0` (SGRM services are killed but these keys are not set).

## Missing — Tier 2 (individual registry keys)

- **Scan extras**: `ArchiveMaxDepth=0`, `ArchiveMaxSize=1`,
  `MissedScheduledScanCountBeforeCatchup=20`, `QuickScanInterval=24`, `ScanParameters=1`,
  `DisableCpuThrottleOnIdleScans=0`
- **SmartScreen gaps**: `Explorer\AicEnabled="Anywhere"`; the **`WOW6432Node`** copy of
  `SmartScreenEnabled=Off` (only the 64-bit hive is written today)
- **Direct (non-policy) mirrors** the research also writes:
  `SOFTWARE\Microsoft\Windows Defender\MpEngine` (`MpBafsExtendedTimeout`, `MpCloudBlockLevel`)
  and `Microsoft Antimalware\Signature Updates\SignatureDisableNotification`
- **Service**: add `WdDevFlt` (device filter driver) to `disable_services_registry`

## Tier 3 — review (not necessarily bugs)

- **`EnableNetworkProtection`** — code sets `1`; research also sets `1`. But `1` = Block
  (enabled), `0` = off, `2` = audit. Both look semantically inverted; the in-code comment
  saying "1 = audit mode" is wrong (audit is `2`). Inherited from the research.
- **Threat-action value mismatch** — WMI path uses `6` (Allow) for High/Moderate/Low/Severe
  while the registry path uses `9`. Research uses `9` (registry) and `9` for
  `UnknownThreatDefaultAction` (WMI). Consider aligning to `9`.
- **Tamper Protection** — research's "Disable Tamper Protection" section is effectively a
  manual/no-op (TP cannot be turned off by registry while active). Current
  `TamperProtection=4` + `Source=2` is a community trick that only sticks if TP is already
  off or the right token is held.

## Suggested implementation priority

1. **Scheduled tasks (5)** — cheap, high value; `schtasks /Change /DISABLE` or registry.
2. **Tier 2 registry keys** — trivial additions to existing
   `set_group_policies` / `disable_smartscreen_registry`.
3. **VBS/Device Guard + Firewall registry blocks** — new helper functions, medium effort.
4. **Binary soft-deletion** — largest effort (TrustedInstaller takeown + rename with
   rollback) and the biggest behavioral change. Decide whether to adopt this vs. keeping the
   IFEO/service approach.

