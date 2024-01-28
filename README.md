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

## For users
Currently I have made the following advancements in an attempt to find vulnerable XPC services that either have type confusion or privilege escallation within and outside the sandbox:
- Analyzed runningboard (RunningBoardServices) and created code to interface with it (Abusing the xpc service spawn launchd jobs no longer works due to sandbox policies)
- Some recent vulnerabilities in XPC services on iOS and exploits for it can be found here [Mov ax br Blog][(https://movaxbx.ru/2021/09/)
- Some good information on where to start researching XPC can be found here by researcher [Ian Beer](https://thecyberwire.com/events/docs/IanBeer_JSS_Slides.pdf)
