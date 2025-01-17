# ⚠️ Attention
This project is displayed **ONLY** to showcase what I was doing 3 years ago compared to an IT student taking classes. I **highly advise** against trying to use or modify this code without a thorough understanding of what you’re doing. 

Additionally, I **do not recommend** using this code as it contains a serious bug in the `knownProcess` implementation. This bug may cause the user-mode communication to mistakenly believe that a process is still running, leading to potential read/write operations on another process that has taken the same PID.

## About
This driver is an **unsigned driver**—technically malware, much like anti-cheat software. However, its purpose was to **protect my cheat customers** from said anti-cheats.  

The development process was riddled with PC/VM crashes, and I was only able to get the driver to its current state after much trial and error. I would strongly recommend writing **user-mode wrapped kernel code** rather than directly writing kernel-level code—unless, of course, you can run a virtual machine.

The driver is mapped to lala-land region in ring 0 with no module identifier,
if I recall correctly from there my usermode .dll sends a windows dataptr named \REDACTED/ and from there my nonsense implementation of hivemind
goes onto become a temporary/permanent middle man for \REDACTED/ and after that our comlib dll interfaces all our completely legitimate calls to \REDACTED/.

## Reflection
Despite future me seeing the implementation as terrible, stupid, unmaintainable, bad coding practices. I’m glad I undertook this project. Through it, I learned about computer science, assembly, and bit-by-bit manipulation.
I worked so hard during this period I remember, this repo is technically a fork from a private archived one, that one had over 200 commits that spans back to mid 2023 maybe. I never thought id unprivate so much of my work.
I can't even fathom how I managed to do all of this back then, let alone the will-power to learn so much and to make these projects work. I was definitely more of an enthusiast back then. 

Needles to say the sheer intuition, constant trial and error and unbreakable dedication I put into my hobby around 2022-2023 has benefited me so much e.g intuitive programming.  
If I'm not sounding too arrogant I at least believe HR is wrong in judging me as a weak candidate for a baby/junior UNPAID intership in non-compiled languages.


