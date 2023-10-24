# Letter Soup

### Challenge description: 

We believe we have ran into one of the newest members of DEADFACE while they were waiting for the train. The member seemed to have gotten spooked and stood up suddenly to jump on the train right before the doors shut. They seemed to have gotten away, but dropped this innocent looking word search. I believe this member might be actually a courier for DEADFACE. Let’s solve the word search to decode the mystery message. We believe the message might tell us their next move.

Submit the flag as flag{TARGETNAME} (e.g., flag{THISISTHEANSWER})

[Image](./Deadface_Word_Search.png)

# Solve: 

When you solve the word search, you can string the leftover letters together to get this string:

```
mshnhzishjrmlhaolyzzopulpuaolzbu
```

When I put that string into [dcode](dcode.fr) the solve was doing a ROT cipher shift on these leftover letters to get the flag: `flagasblackfeathersshineinthesun`

Flag: flag{asblackfeathersshineinthesun}