# RunningBoardServices launcher
- Just to clarify, I did not commit plagiarism on [Secura B.V Writeup](https://www.secura.com/nl/blog/ios-apps-on-arm-macs-pentesting-opportunities-part-2) [PoC](https://github.com/srepsa/launchr)
- I discovered the existence later during the research. My code differs in that it is completely without private api usage and targets different selectors than in their code as they aren't implemented iin the iOS 16.5 XPC service.
- Code currently calls the right methods, but sandbox denies the execution. E.g.: "Sandbox: xpcsploit(14248) deny(1) process-info-pidinfo others \[SpringBoard(12115)\]"
- Probably works outside of the sandbox
