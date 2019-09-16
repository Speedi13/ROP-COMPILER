# CSGO-Triggerbot-Tutorial

Code that has to be modified: <br />
[CSGO_Triggerbot.asm](https://github.com/Speedi13/ROP-COMPILER/blob/master/CheatSourceCodes/CSGO_Triggerbot.asm#L40)

## Step 1
Make sure to disable any Exploit-protection in your AnitVirus software.<br />
You can also try to exclude CSGO from the exploit-protection.

## Step 2 - Trigger key

### Key codes:
https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
<br/>

<img src="https://i.imgur.com/znZyTPL.jpg" alt="Image of Mouse with Labels" width="500"/>

In the [Assembly file](https://github.com/Speedi13/ROP-COMPILER/blob/master/CheatSourceCodes/CSGO_Triggerbot.asm#L40):<br />
```asm
@l_MainLoop:;//EAX => Triggerbot key:
mov eax,0x6;//-> VK_XBUTTON2
;//https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
mov VR9, eax;
```

## Step 3 - Change the trigger key
Lets change the Trigger-bot-key to ``Y``<br />
In the [Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes) you can find:
```
0x59                       Y key
```

You need to change the [source code](https://github.com/Speedi13/ROP-COMPILER/blob/master/CheatSourceCodes/CSGO_Triggerbot.asm#L40) to the following:
```asm
@l_MainLoop:;//EAX => Triggerbot key:
mov eax,0x59;
;//https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
mov VR9, eax;
```
