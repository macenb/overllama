# Refill on Soup

### Challenge Description: 

How could we have missed this?? There were TWO word searches stuck together that the DEADFACE courier dropped. We’ve already solved the first one, but maybe solving this second word search will help us uncover the secret message they’re trying to covertly relay to the other members of DEADFACE. Hopefully, THIS will tell us how they plan to execute their next move.

Submit the flag as flag{TARGETNAME} (e.g., flag{THISISTHEANSWER})

[Image](./Deadface_Word_Search_Part_2.png)

### Solve:

If you solve the word search, just like in the last challenge you can just string all the letters together to get this string:

nvavaolshzaspulmvyaolmshnhuzdlyaohanvlzpuzpklaoliyhjrlazzavwnqwkddevwzlztjnthxskeadvucbvtrklhsweebgbdthhzaolfmsfhjyvzz
hzaolfmsfhjyvzz

After putting it into [dcode](dcode.fr) I figured out that the letters that were left were actually a vigenere cipher. Then, when plugged in, it gave you this text:

```
gotothelastlinefortheflaganswerthatgoesinsidethebracketsstopgjpdwwxopsesmcgmaqldxtwonvuomkdealpxxuzuwmaastheyflyacross```

Then, you just need to go to that last line, which starts with the 'hzaol' in the ciphertext and run it through the cipher, and you get the inside contents of the flag:

Flag: flag{astheyflyacross}