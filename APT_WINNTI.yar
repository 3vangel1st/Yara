rule cb2_01
{
strings:
$e1 = „Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411015}” ascii nocase
$e2 = „Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411014}” ascii nocase
$e3 = „Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411016}” ascii nocase
$e4 = „\\BaseNamedObjects\\{B2B87CCA-66BC-4C24-89B2-C23C9EAC2A66}” wide
$e5 = „BFE_Notify_Event_{7D00FA3C-FBDC-4A8D-AEEB-3F55A4890D2A}” nocase
condition:
(any of ($e*))
}

rule cb2_02
{
strings:
$a1 = „IPSecMiniPort” wide fullword
$a2 = „ndis6fw” wide fullword
$a3 = „TCPIP” wide fullword
$a4 = „NDIS.SYS” ascii fullword
$a5 = „ntoskrnl.exe” ascii fullword
$a6 = „\\BaseNamedObjects\\{B2B87CCA-66BC-4C24-89B2-C23C9EAC2A66}” wide
$a7 = „\\Device\\Null” wide
$a8 = „\\Device” wide
$a9 = „\\Driver” wide
$b1 = { 66 81 7? ?? 70 17 }
$b2 = { 81 7? ?? 07 E0 15 00 }
$b3 = { 8B 46 18 3D 03 60 15 00 }
condition:
(6 of ($a*)) and (2 of ($b*))
}

rule cb2_03
{
strings:
$b1 = { 0F B7 ?? 16 [0-1] (81 E? | 25) 00 20 [0-2] [8] 8B ?? 50 41 B9 40 00 00 00 41 B8 00
10 00 00 }
$b2 = { 8B 40 28 [5-8] 48 03 C8 48 8B C1 [5-8] 48 89 41 28 }
$b3 = { 48 6B ?? 28 [5-8] 8B ?? ?? 10 [5-8] 48 6B ?? 28 [5-8] 8B ?? ?? 14 }
$b4 = { 83 B? 90 00 00 00 00 0F 84 [9-12] 83 B? 94 00 00 00 00 0F 84 }
$b5 = { (45 | 4D) (31 | 33) C0 BA 01 00 00 00 [10-16] FF 5? 28 [0-1] (84 | 85) C0 }
condition:
(4 of ($b*))
}

rule cb2_04
{
strings:
$b1 = { 4C 8D 41 24 33 D2 B9 03 00 1F 00 FF 9? F8 00 00 00 48 85 C0 74 }
$b2 = { 4C 8B 4? 08 BA 01 00 00 00 49 8B C? FF D0 85 C0 [2-6] C7 4? 1C 01 00 00 00 B8 01
00 00 00 }
$b3 = { 8B 4B E4 8B 53 EC 41 B8 00 40 00 00 4? 0B C? FF 9? B8 00 00 00 EB }
condition:
(2 of ($b*))
}

rule cb2_05
{
strings:
$a1 = „-k netsvcs” ascii
$a2 = „svchost.exe” ascii fullword
$a3 = „%SystemRoot%\\System32\\ntoskrnl.exe” ascii
$a4 = „Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411015}” ascii
$a5 = „Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411014}” ascii
$a6 = „Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411016}” ascii
$a7 = „cmd.exe” wide
$a8 = „,XML” wide
$a9 = „\\rundll32.exe” wide
$a10 = „\\conhost.exe” wide
$a11 = „\\cmd.exe” wide
$a12 = „NtQueryInformationProcess” ascii
$a13 = „Detours!” ascii fullword
$a14 = „Loading modified build of detours library designed for MPC-HC player
(http://sourceforge.net/projects/mpc-hc/)” ascii
$a15 = „CONOUT$” wide fullword
$a16 = { C6 0? E9 4? 8? 4? 05 [2] 89 4? 01 }
condition:
(12 of ($a*))
}
