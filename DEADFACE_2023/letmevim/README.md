# Host Busters 1

### Challenge description:
```

Turbo Tactical has gained access to a DEADFACE machine that belongs to gh0st404. This machine was used to scan one of TGRI’s websites. See if you can find anything useful in the vim user’s directory.

On a side note, it’s also a good idea to collect anything you think might be useful in the future for going after DEADFACE.

Submit the flag as flag{flag_here}.

vim@gh0st404.deadface.io

Password: letmevim
```

### Solution:

Using SSH, you can get a shell to their machine, but it drops you in vim. If you exit vim with :q or any variants, it closes your shell. You can get the flag by using the :ter[minal] command, which drops you into a normal shell in which you can find the file hostbusters1.txt, which contains the flag

Flag: flag{esc4P3_fr0m_th3_V1M}