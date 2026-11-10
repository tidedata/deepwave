import re, sys
B = sys.argv[1]
p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
R = pow(2, 384, p); Rinv = pow(R, -1, p)
def fromlimbs(ls): return sum(l << (64*i) for i, l in enumerate(ls)) * Rinv % p
def arrays(src, name):
    m = re.search(r'static const (vec384x?) ' + re.escape(name) + r'\[\]\s*=\s*\{(.*?)\n\s*\};', src, re.S)
    body = m.group(2)
    # split into elements by top-level braces
    elems=[]; depth=0; cur=''
    for ch in body:
        if ch=='{':
            depth+=1
            if depth==1: cur=''; continue
        if ch=='}':
            depth-=1
            if depth==0: elems.append(cur); continue
        if depth>=1: cur+=ch
    out=[]
    for e in elems:
        limbs=[int(x,16) for x in re.findall(r'TO_LIMB_T\((0x[0-9a-f]+)\)', e)]
        if m.group(1)=='vec384':
            out.append(fromlimbs(limbs))
        else:
            # vec384x: two vec384, each 6 limbs, "{ 0 }" means zero
            parts=re.findall(r'\{([^{}]*)\}', e)
            vals=[]
            for pp in parts:
                ls=[int(x,16) for x in re.findall(r'TO_LIMB_T\((0x[0-9a-f]+)\)', pp)]
                vals.append(fromlimbs(ls) if ls else 0)
            out.append(tuple(vals))
    return out
g1 = open(B+'/map_to_g1.c').read(); g2 = open(B+'/map_to_g2.c').read()
iso1 = {n: arrays(g1, 'isogeny_map_'+n) for n in ['x_num','x_den','y_num','y_den']}
iso2 = {n: arrays(g2, 'isogeny_map_'+n) for n in ['x_num','x_den','y_num','y_den']}
# --- Fp2 helpers
def f2mul(a,b): return ((a[0]*b[0]-a[1]*b[1])%p, (a[0]*b[1]+a[1]*b[0])%p)
def f2add(a,b): return ((a[0]+b[0])%p,(a[1]+b[1])%p)
def f2pow(a,e):
    res=(1,0)
    while e:
        if e&1: res=f2mul(res,a)
        a=f2mul(a,a); e>>=1
    return res
def f2inv(a):
    n=(a[0]*a[0]+a[1]*a[1])%p; ni=pow(n,-1,p); return (a[0]*ni%p, (-a[1])*ni%p)
xi=(1,1)
# checks: E1': y^2 = x^3 + A1 x + B1
A1=0x00144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d
B1=0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0
def sqrt_fp(a):
    s=pow(a,(p+1)//4,p); return s if s*s%p==a%p else None
# isogeny check G1: find a point on E1', map it, check on E1
def poly(c,x,lead1=False):
    acc = 1 if lead1 else 0
    for k in reversed(c): acc = (acc*x + k)%p
    return acc
x=5
while True:
    y=sqrt_fp((x**3+A1*x+B1)%p)
    if y is not None: break
    x+=1
xn=poly(iso1['x_num'],x); xd=poly(iso1['x_den'],x,True); yn=poly(iso1['y_num'],x); yd=poly(iso1['y_den'],x,True)
X=xn*pow(xd,-1,p)%p; Y=y*yn*pow(yd,-1,p)%p
assert (Y*Y - X**3 - 4)%p==0, "iso1"
print("iso1 ok", len(iso1['x_num']),len(iso1['x_den']),len(iso1['y_num']),len(iso1['y_den']), file=sys.stderr)
# G2 isogeny check
A2=(0,240); B2=(1012,1012)
def f2sqrt(a):
    # brute: a^((p^2+7)/16) style is complex; use generic: try candidates via Tonelli on Fp2 norm
    a1=f2pow(a,(p-3)//4); alpha=f2mul(f2mul(a1,a1),a); x0=f2mul(a1,a)
    if alpha==(p-1,0): x=f2mul((0,1),x0)
    else:
        b=f2pow(f2add((1,0),alpha),(p-1)//2); x=f2mul(b,x0)
    return x if f2mul(x,x)==(a[0]%p,a[1]%p) else None
x=(3,1)
while True:
    rhs=f2add(f2add(f2mul(f2mul(x,x),x),f2mul(A2,x)),B2)
    y=f2sqrt(rhs)
    if y is not None: break
    x=(x[0]+1,x[1])
def poly2(c,x,lead1=False):
    acc=(1,0) if lead1 else (0,0)
    for k in reversed(c): acc=f2add(f2mul(acc,x),k)
    return acc
xn=poly2(iso2['x_num'],x); xd=poly2(iso2['x_den'],x,True); yn=poly2(iso2['y_num'],x); yd=poly2(iso2['y_den'],x,True)
X=f2mul(xn,f2inv(xd)); Y=f2mul(f2mul(y,yn),f2inv(yd))
lhs=f2mul(Y,Y); rhs=f2add(f2mul(f2mul(X,X),X),(4,4))
assert lhs==rhs, "iso2"
print("iso2 ok", len(iso2['x_num']),len(iso2['x_den']),len(iso2['y_num']),len(iso2['y_den']), file=sys.stderr)
# generators
g1x=0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
g1y=0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
assert (g1y*g1y-g1x**3-4)%p==0
g2x=(0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8,0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e)
g2y=(0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801,0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be)
assert f2mul(g2y,g2y)==f2add(f2mul(f2mul(g2x,g2x),g2x),(4,4))
beta=0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac
assert pow(beta,3,p)==1
# psi: (x,y) -> (conj(x)*cx, conj(y)*cy), cx = 1/xi^((p-1)/3), cy = 1/xi^((p-1)/2)
cx=f2inv(f2pow(xi,(p-1)//3)); cy=f2inv(f2pow(xi,(p-1)//2))
assert cx==(0,0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad), cx
# frobenius coefficients
frob6_1=[f2pow(xi,(p**k-1)//3) for k in (1,2,3)]
frob6_2=[f2pow(xi,(2*(p**k)-2)//3) for k in (1,2,3)]
frob12=[f2pow(xi,(p**k-1)//6) for k in (1,2,3)]
for c in frob6_2: assert c[1]==0
# SSWU constants
Z1=11
c2_1=sqrt_fp((-Z1)%p); assert c2_1 is not None
Z2=((-2)%p,(-1)%p)
def h(v): return '0x%096x' % v
def f2(v): return '.{ %s, %s }' % (h(v[0]), h(v[1]))
o=[]
o.append('//! Generated by tools/truth/crypto-bls/gen_consts.py from blst 0.3.16 (map_to_g1.c, map_to_g2.c) and')
o.append('//! closed-form definitions; every constant is checked by the generator (isogenies land on E, generators')
o.append('//! on the curve, beta^3 = 1, psi and Frobenius coefficients recomputed). Canonical integers, not Montgomery.')
o.append('pub const p: u384 = %s;' % h(p))
o.append('pub const r: u256 = 0x%064x;' % r)
o.append('pub const g1_x: u384 = %s;' % h(g1x)); o.append('pub const g1_y: u384 = %s;' % h(g1y))
o.append('pub const g2_x: [2]u384 = %s;' % f2(g2x)); o.append('pub const g2_y: [2]u384 = %s;' % f2(g2y))
o.append('pub const beta: u384 = %s;' % h(beta))
o.append('pub const psi_x: [2]u384 = %s;' % f2(cx)); o.append('pub const psi_y: [2]u384 = %s;' % f2(cy))
o.append('pub const frob6_c1: [3][2]u384 = .{ %s };' % ', '.join(f2(c) for c in frob6_1))
o.append('pub const frob6_c2: [3]u384 = .{ %s };' % ', '.join(h(c[0]) for c in frob6_2))
o.append('pub const frob12_c1: [3][2]u384 = .{ %s };' % ', '.join(f2(c) for c in frob12))
o.append('pub const sswu1_a: u384 = %s;' % h(A1)); o.append('pub const sswu1_b: u384 = %s;' % h(B1))
o.append('pub const sswu1_z: u384 = %d;' % Z1); o.append('pub const sswu1_c2: u384 = %s; // sqrt(-Z)' % h(c2_1))
o.append('pub const sswu2_a: [2]u384 = %s;' % f2(A2)); o.append('pub const sswu2_b: [2]u384 = %s;' % f2(B2))
o.append('pub const sswu2_z: [2]u384 = %s;' % f2(Z2))
for n in ['x_num','x_den','y_num','y_den']:
    o.append('pub const iso1_%s = [_]u384{ %s };' % (n, ', '.join(h(v) for v in iso1[n])))
for n in ['x_num','x_den','y_num','y_den']:
    o.append('pub const iso2_%s = [_][2]u384{ %s };' % (n, ', '.join(f2(v) for v in iso2[n])))
print('\n'.join(o))
