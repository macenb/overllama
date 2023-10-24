# Cereal Killer 05

### Description:

We think Dr. Geschichter of Lytton Labs likes to use his favorite monster cereal as a password for ALL of his accounts! See if you can figure out what it is, and keep it handy! Choose one of the binaries to work with.

Enter the answer as flag{WHATEVER-IT-IS}

[File](./re05.bin)

### Solve:

When we decompile this program with Ghidra, the first thing we see is the main function:

```C
undefined4 main(void)

{
  int iVar1;
  undefined4 uVar2;
  int in_GS_OFFSET;
  int local_254;
  byte local_235 [33];
  undefined local_214 [512];
  int local_14;
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  for (local_254 = 0; local_254 < 0x21; local_254 = local_254 + 1) {
    if ((&DAT_00012008)[local_254] != '\0') {
      local_235[local_254] = (&DAT_00012008)[local_254] ^ "Xen0M0rphMell0wz"[local_254 % 0x10];
    }
  }
  local_235[32] = 0;
  FUN_000110e0(
              "Dr. Geschichter, just because he is evil, doesn\'t mean he doesn\'t have a favorite c ereal."
              );
  FUN_000110c0(&DAT_0001211c,
               "Please enter the passphrase, which is based off his favorite cereal and entity: ");
  FUN_00011100(&DAT_0001211c,local_214);
  iVar1 = FUN_000110b0(local_214,"Xen0M0rphMell0wz");
  if (iVar1 == 0) {
    FUN_000110e0(local_235);
  }
  else {
    FUN_000110e0("notf1aq{you-guessed-it---this-is-not-the-f1aq}");
  }
  uVar2 = 0;
  if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
    uVar2 = __stack_chk_fail_local();
  }
  return uVar2;
}
```

This program is asking for input and storing it in the variable local_214. It immediately then compares it with the string "Xen0M0rphMell0wz". If the string matches, it will print the flag! Let's give it a try in our terminal:

```bash
overllama@overllama: ~/CerealKiller5$ ./re05.bin
    Dr. Geschichter, just because he is evil, doesn't mean he doesn't have a favorite cereal.
    Please enter the passphrase, which is based off his favorite cereal and entity:
```

We just input Xen0M0rphMell0wz and like expected, it gives us the flag!

Flag: flag{XENO-DO-DO-DO-DO-DO-DOOOOO}