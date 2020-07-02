# PoshC2 CyberChef Recipes
Poshc2 Payloads CyberChef Recipes:

-------------------------------- .BAT & .HTA --------------------------------

payload.bat & Launcher.hta:
https://gchq.github.io/CyberChef/#recipe=Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%2B%3D%5D%7B400,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%2B%3D%5D%7B400,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Gunzip()

-------------------------------- .XML --------------------------------

cs_sct.xml & rg_sct.xml
https://gchq.github.io/CyberChef/#recipe=Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%2B%3D%5D%7B400,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%2B%3D%5D%7B400,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Gunzip()
 
msbuild.xml
https://gchq.github.io/CyberChef/#recipe=Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%5C%5C%2B%3D%5D%7B300,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%5C%5C%2B%3D%5D%7B300,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%5C%5C%2B%3D%5D%7B300,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Gunzip()

-------------------------------- .CS --------------------------------

csc.cs
https://gchq.github.io/CyberChef/#recipe=Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%5C%5C%2B%3D%5D%7B300,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%5C%5C%2B%3D%5D%7B300,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%5C%5C%2B%3D%5D%7B300,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Gunzip()

Sharp_posh_Stager.cs

https://gchq.github.io/CyberChef/#recipe=Regular_expression('User%20defined','%22(.*?)%22',true,true,false,false,false,false,'List%20capture%20groups')Remove_whitespace(true,true,true,true,true,false)From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%5C%5C%2B%3D%5D%7B300,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Gunzip()

-------------------------------- .B64 --------------------------------

Sharp_v4_x86_Shellcode.b64 & Sharp_v4_x64_Shellcode.b64
https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%2B%3D%5D%7B400,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','Host.*%5C%5Cs(.*)',true,true,false,false,false,false,'List%20matches')

Posh_v4_x86_Shellcode.b64 & Posh_v4_x64_Shellcode.b64 & Posh_v2_x86_Shellcode.b64 & Posh_v2_x64_Shellcode.b64
https://gchq.github.io/CyberChef/#recipe=Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%5C%5C%2B%3D%5D%7B300,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%5C%5C%2B%3D%5D%7B300,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%5C%5C%2B%3D%5D%7B300,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Gunzip()

DotNet2JS_CS.b64
https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%2B%3D%5D%7B400,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5B0-9a-z/%5C%5C%2B%3D%5D%7B400,%7D',true,false,false,false,false,false,'List%20matches')Regular_expression('User%20defined','%5B0-9a-z/%5C%5C%2B%3D%5D%7B500,%7D',true,true,false,false,false,false,'Highlight%20matches')Fork('SHOWmscorlibLoadcmdhWndCreateEventSourceGetTypeEventLogEntryTypeGuidAttributeDebuggableAttributeComVisibleAttributeAssemblyTitleAttributeAssemblyTrademarkAttributeAssemblyFileVersionAttributeAssemblyConfigurationAttributeAssemblyDescriptionAttributeCompilationRelaxationsAttributeAssemblyProductAttributeAssemblyCopyrightAttributeAssemblyCompanyAttributeRuntimeCompatibilityAttributeFromBase64StringEventLogkernel32','%5C%5Cn',false)From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','Host.*%5C%5Cs(.*)',true,true,false,false,false,false,'List%20matches')


-------------------------------- .BIN --------------------------------

Sharp_v4_x86_Shellcode.bin
https://gchq.github.io/CyberChef/#recipe=Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%2B%3D%5D%7B400,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','Host.*%5C%5Cs*(.*)',true,true,false,false,false,false,'List%20matches')

Posh_v4_x86_Shellcode.bin & Posh_v4_x64_Shellcode.bin & Posh_v2_x86_Shellcode.bin & Posh_v2_x64_Shellcode.bin
https://gchq.github.io/CyberChef/#recipe=Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%2B%3D%5D%7B400,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%2B%3D%5D%7B400,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Gunzip()

-------------------------------- .SH & .PY --------------------------------
 
py_dropper.sh & py_dropper.py
https://gchq.github.io/CyberChef/#recipe=Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%5C%5C%5C%5C%5C%5C%2B%3D%5D%7B300,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)  
 
-------------------------------- .DLL --------------------------------
Sharp_v4_x86.dll & Sharp_v4_x64.dll
https://gchq.github.io/CyberChef/#recipe=Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%2B%3D%5D%7B400,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','Host.*%5C%5Cs*(.*)',true,true,false,false,false,false,'List%20matches')

Posh_v4_x86.dll & Posh_v4_x64.dll & Posh_v2_x86.dll & Posh_v2_x64.dll
https://gchq.github.io/CyberChef/#recipe=Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%2B%3D%5D%7B400,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%2B%3D%5D%7B400,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Gunzip()

dropper_cs.dll
https://gchq.github.io/CyberChef/#recipe=Remove_null_bytes()Regular_expression('User%20defined','Host.*%5C%5Cs*(.*)',true,true,false,false,false,false,'List%20matches')

-------------------------------- .JS --------------------------------

DotNet2JS_CS.js
https://gchq.github.io/CyberChef/#recipe=Regular_expression('User%20defined','safdsv64%20%3D%20%22(.*?)%22',true,true,false,false,false,false,'List%20capture%20groups')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%2B%3D%5D%7B500,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','Host.*%5C%5Cs*(.*)',true,true,false,false,false,false,'List%20matches')

DotNet2JS.js
https://gchq.github.io/CyberChef/#recipe=Regular_expression('User%20defined','safdsv64%20%3D%20%22(.*?)%22',true,true,false,false,false,false,'List%20capture%20groups')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%2B%3D%5D%7B500,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%2B%3D%5D%7B500,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Gunzip()

-------------------------------- .C --------------------------------

Posh64_migrate.c & Posh64.c & Posh32_migrate.c
https://gchq.github.io/CyberChef/#recipe=Regular_expression('User%20defined','%22(.*?)%22',true,true,false,false,false,false,'List%20capture%20groups')Remove_whitespace(true,true,true,true,true,false)From_Hex('Auto')Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%2B%3D%5D%7B500,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%2B%3D%5D%7B500,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Gunzip()

-------------------------------- MACRO --------------------------------
Macro.txt
https://gchq.github.io/CyberChef/#recipe=Regular_expression('User%20defined','%22(.*?)%22',true,true,false,false,false,false,'List%20capture%20groups')Remove_whitespace(true,true,true,true,true,false)From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%5C%5C%2B%3D%5D%7B300,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Gunzip()

-------------------------------- .EXE --------------------------------

Posh32.exe & Posh32_migrate.exe & Posh64.exe & Posh64_migrate.exe
https://gchq.github.io/CyberChef/#recipe=Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%2B%3D%5D%7B400,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Remove_null_bytes()Regular_expression('User%20defined','%5Ba-z0-9/%5C%5C%2B%3D%5D%7B400,%7D',true,true,false,false,false,false,'List%20matches')From_Base64('A-Za-z0-9%2B/%3D',true)Gunzip()

dropper_cs.exe
https://gchq.github.io/CyberChef/#recipe=Remove_null_bytes()Regular_expression('User%20defined','Host.*%5C%5Cs*(.*)',true,true,false,false,false,false,'List%20matches')
