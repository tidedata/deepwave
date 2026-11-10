#include <metal_stdlib>
using namespace metal;
typedef uint u32;
typedef ulong u64;
#define GLOBAL device
#define CONSTANT constant
#define FN inline
#define THREAD thread
#define I8 char
#define MULW(a, b) ((u64)(a) * (u64)(b))
#define I8G char
// ed25519 field mul/sq as real calls: the inlined 10-limb products blow up the kernel (and the
// Metal compiler miscompiled the fully inlined loop-carried point chains); calls are faster too.
#define FXFN __attribute__((noinline))
