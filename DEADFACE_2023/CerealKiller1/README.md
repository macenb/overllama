# Cereal Killer 01

### Challenge Description:

How well do you know your DEADFACE hackers? Test your trivia knowledge of our beloved friends at our favorite hactivist collective! We’ll start with bumpyhassan. Even though he grates on TheZeal0t a bit, we find him to be absolutely ADORKABLE!!!

Choose one of the binaries below to test your BH trivia knowlege.

Enter the flag in the format: flag{Ch33ri0z_R_his_FAV}

[File](./re01)

### Solve

When we add the file into Ghidra, we get this as our main function:

```c
undefined4 main(void)

{
  int iVar1;
  undefined4 uVar2;
  int in_GS_OFFSET;
  char *local_1090;
  char *local_108c;
  char *local_1088;
  char local_1078 [100];
  char local_1014 [4096];
  int local_14;
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  local_108c = "I&_9a%mx_tRmE4D3DmYw_9fbo6rd_aFcRbE,D.D>Y[!]!\'!q";
  puts("Bumpyhassan loves Halloween, so naturally, he LOVES SPOOKY CEREALS!");
  puts("He also happens to be a fan of horror movies from the 1970\'s to the 1990\'s.");
  printf("What is bumpyhassan\'s favorite breakfast cereal? ");
  fgets(local_1014,0xfff,_stdin);
  for (local_1090 = local_1014; *local_1090 != '\0'; local_1090 = local_1090 + 1) {
    *local_1090 = *local_1090 + '\a';
  }
  *local_1090 = '\0';
  iVar1 = memcmp(&DAT_00012039,local_1014,0xe);
  if (iVar1 == 0) {
    puts("You are correct!");
    local_1088 = local_1078;
    for (; *local_108c != '\0'; local_108c = local_108c + 2) {
      *local_1088 = *local_108c;
      local_1088 = local_1088 + 1;
    }
    *local_1088 = '\0';
    printf("flag{%s}\n",local_1078);
  }
  else {
    puts("Sorry, that is not bumpyhassan\'s favorite cereal. :( ");
  }
  uVar2 = 0;
  if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
    uVar2 = __stack_chk_fail_local();
  }
  return uVar2;
}
```

The first thing we see is that this one, like [Cereal Killer 5](../CerealKiller5/), will ask us for input when run. Sure enough:

```bash
overllama@overllama: ~/CerealKiller1$ ./re01
  Bumpyhassan loves Halloween, so naturally, he LOVES SPOOKY CEREALS!
  He also happens to be a fan of horror movies from the 1970's to the 1990's.
  What is bumpyhassan's favorite breakfast cereal? ^C
```

So we need to look in the file itself to figure out what bumpyhassan's favorite cereal is, then. Looking at the decompiled code, we can see that, first of all, the comparation is being done to a variable local_1014 to a memory address. This is the for loop in question:

```c
for (local_1090 = local_1014; *local_1090 != '\0'; local_1090 = local_1090 + 1) {
    *local_1090 = *local_1090 + '\a';
  }
```

For people less familiar with decompiled C (and I'm no expert), this code is using the variable local_1090 as a reference to the a letter in the String stored at local_1014 (your input `fgets(local_1014,0xfff,_stdin);`) and changing the values slightly. Once they're all inputted and changed in the string, it's compared to the values at a memory address (`0xe` of them, or 12) and the flag is printed if you're right. The flag is also printed in ciphertext towards the top of the binary, and can be analyzed and decrypted in a similar manner, but that's both longer and more complicated so let's just determine the input :)

First, we need to find the data at this address. Ghidra is nice becuase if you double click on `&DAT_00012039`, it takes you to the data address and you can find the hex values associated with a string of 12 letters. The string in question is `My|p{ GRY\LNLY` but that's not exactly what we're looking for. If we look at the source code for decryption (above), we can see that the only thing being done to these values is each input value is incremented by `\a` (or 7).

Let's grab all the hex values and edit them with Python to get the flag. Here they are:

```Python
cereal = ['4d', '79', '7c', '70', '7b', '80', '47', '52', '59', '5c', '4c', '4e', '4c', '59']
```

Now we just need to subtract 7 from each value and print its associated letter for the input:

```Python
cereal = ['4d', '79', '7c', '70', '7b', '80', '47', '52', '59', '5c', '4c', '4e', '4c', '59']

print(''.join([chr(int(val, 16) - 7) for val in cereal]))
```

The input we get is Fruity@KRUEGER, so we just need to input that into the running program, and we have the flag.

Flag: flag{I_am_REDDY_for_FREDDY!!!}