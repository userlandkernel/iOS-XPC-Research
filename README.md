# iOS-XPC-Research
Implementing reverse engineered XPC service clients 

## For researchers
1. Jailbreak your device and boot into the fake palera1n os https://palera.in/
2. Install Sileo and add the following repo https://build.frida.re
3. Install frida from Sileo and on your computer install https://pypi.org/project/frida-tools/
4. Frida is a perfect introspection and runtime debugging tool, it let's you write javascript hooks for native functions and injects into running processes.
5. In order to examine XPC services you can use my scripts with frida
6. I also have used this tweak [XPC Sniffer](https://github.com/evilpenguin/XPCSniffer) as an alternative to frida
7. As of iOS 16.5 there seems to no longer be an xpcd cache nor a dyld_shared_cache. This complicates research a bit
8. Run on iOS to get an idea of existing XPC services accessible by lockdownd (over USB).
```
for file in $(find / -type f -executable -print);do
  jtool2 -d "$file" 2>/dev/null | grep -m 2 "lockdown_checkin_xpc" | head -n 3 | tail -n 1 | tr -d '\t' | awk -F '_lockdown_checkin_xpc' '{pr
int $2}' | awk -F "," '{print $1}' | tr -d "(\"";
done
```


## For users
Currently I have made the following advancements in an attempt to find vulnerable XPC services that either have type confusion or privilege escallation within and outside the sandbox:
- Analyzed runningboard (RunningBoardServices) and created code to interface with it (Abusing the xpc service spawn launchd jobs no longer works due to sandbox policies)
- Analyzed nehelper (NetworkExtension) and created code to interface with it (WIP)
- Some recent vulnerabilities in XPC services on iOS and exploits for it can be found here [Mov ax br Blog][(https://movaxbx.ru/2021/09/)
- Some good information on where to start researching XPC can be found here by researcher [Ian Beer](https://thecyberwire.com/events/docs/IanBeer_JSS_Slides.pdf)


## Tools and resources
- [XPoCe 2.0](https://www.newosxbook.com/tools/XPoCe2.html) By Jonathan Levin. Doesn't support arm64 and up.
- [Entitlements database](https://newosxbook.com/ent.jl?osVer=iOS16&p=possess) By Jonathan Levin. Comes in handy for picking privelege escallation targets.
- [IOS Runtime Headers](https://developer.limneos.net/index.php?ios=17.1). Private Frameworks often implement High-Level logic for XPC
