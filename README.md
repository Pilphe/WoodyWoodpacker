# WoodyWoodpacker

The goal of this educational project was to encrypt the executable section of a target program (whose path was given through command line arguments), add a decryption payload to it, change its entry point to point to the decryption payload, then once ran, the decryption payload had to decrypt the encrypted section, print the string `....WOODY....` then give back the execution flow to the original program without altering its original behavior.

The original program given in the command line arguments remains untouched, a new file containing the Woodyfied program called `woody.exe` is created.

The project name is kinda confusing, I think it acts more like a crypter than a packer since compression isn't involved.

We were a team of two students working on this project, my mate did the ELF part (mandatory) and as a bonus I challenged myself to work on a [PE](https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format) (Windows) version.

Since Windows has more GUIs than CLIs, I decided to print the string in a message box.

I used Visual Studio in combination with [MASM for x64](https://docs.microsoft.com/en-us/cpp/assembler/masm/microsoft-macro-assembler-reference) to achieve this project, which means I was only targeting 64-bit executables.

It is a very basic crypter, to store the decryption payload I create a new section, the encryption algorithm used is the [XOR cipher](https://en.wikipedia.org/wiki/XOR_cipher), executables containing [Thread Local Storage](https://kr-manish.github.io/aragorn/blog/Thread-Local-Storage) callbacks aren't supported (I wrote a check for it) and I also tried to disable [Control Flow Guard](https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard) by clearing the `IMAGE_DLLCHARACTERISTICS_GUARD_CF` flag if present.