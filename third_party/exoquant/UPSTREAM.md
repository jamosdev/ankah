# exoquant upstream source

Repository: https://github.com/exoticorn/exoquant
Revision: `4ec54abaa078e948d52ab23d0457b56f8c96ba47`

Original file SHA-256 values:

- `exoquant.c`: `9f3ba476ae853dade211c81ad11d101aed0ad4e8290b029bfe69df35546b7fb8`
- `exoquant.h`: `177d52c32dd98061182781e8fb0bb8333256685bea66101a4356f024850caca7`

Local changes:

- Remove the non-portable `malloc.h` include; use `stdlib.h`.
- Route allocations through the bounded allocator and report allocation failure.
- Use a `(void)` prototype for initialization.
- Count distinct histogram entries so callers can avoid splitting empty nodes.
