from pwn import *

import math


def is_prime(n):
    for i in range(2, int(math.sqrt(n))+1):
        if (n % i) == 0:
            return False
    return True


def find_p_q(tot):
    for i in range(2, int(math.sqrt(tot)+1)):
        if tot % i == 0:
            p = tot//i
            q = tot//p
            if is_prime(p+1) and is_prime(q+1):
                return p+1, q+1
    return None, None


r = remote("34.159.151.110", 31094)

r.sendline("B")
r.sendline("C")
r.sendline("C")
r.sendline("B")
r.sendline("factordb.com")

p = 17
q = 23
tot = (p-1)*(q-1)
e = 7
d = pow(e, -1, tot)
r.sendline(str(d))
r.sendline("No")

e = 65537
tot = 7921872076
d = pow(e, -1, tot)
c = 7326956863
p, q = find_p_q(tot)
n = p * q
ptext = pow(c, d, n)
r.sendline(str(ptext))
r.sendline("No")

e = 7
n = 186538699056613790346750788479124975303
c = 170980716079866232953
d = pow(e, -1)
ptext = int(round(pow(c, d)))
r.sendline(str(ptext))

e = 65537
q = 74339912603552871288910550819796428390535736156226089114846887894793014783473
n = 7191510338250850990984020535504881803323225477874425027937225669045109857335298362594734551165368539491285483426638981176640217022446544893134863335869453
c = 6902350760011584185668925984552984577941627394500688034128674835266504296632231525360573955392668157647672990537705989032876446683806276823654479584261973
p = n//q
tot = math.lcm(p-1, q-1)
d = pow(e, -1, tot)
ptext = pow(c, d, n)
ptext = ptext.to_bytes(800, "big").lstrip(b"\x00")
r.send(ptext)
# CTF{RSA_15_n0t_th4t_h45d_4ft354ll}

r.interactive()
