# ⚠️ Attention

This project is displayed **only** to showcase where I was 3 years ago. I **highly advise** against trying to use or modify this code without a thorough understanding of what you’re doing. 

Additionally, I **do not recommend** using this code as it contains a serious bug in the `knownProcess` implementation. This bug may cause the user-mode communication to mistakenly believe that a process is still running, leading to potential read/write operations on another process that has taken the same PID.

---

## About

This driver is an **unsigned driver**—technically malware, much like anti-cheat software. However, its purpose was to **protect my cheat customers** from said anti-cheats.  

The development process was riddled with PC/VM crashes, and I was only able to get the driver to its current state after much trial and error. I would strongly recommend writing **user-mode wrapped kernel code** rather than directly writing kernel-level code—unless, of course, you can run a virtual machine.

The driver is mapped to lala-land region in ring 0 with no module identifier,
if I recall correctly from there my usermode .dll sends a windows dataptr named \REDACTED/ and from there my nonsense implementation of hivemind
goes onto become a temporary/permanent middle man for \REDACTED/ and after that our comlib dll interfaces all our completely legitimate calls to \REDACTED/.

---

## Reflection

Despite my perception of the implementation as terrible, I’m glad I undertook this project. Through it, I learned about computer science, assembly, and bit-by-bit manipulation.  

That said, it's worth noting that projects like this will likely not impress HR teams enough to even consider offering you a baby-junior unpaid internship in **any tech field**.

---
