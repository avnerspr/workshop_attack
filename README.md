# workshop_attack

## Usage

Install `<gmp.h>` and `<gmpxx.h>` with:

```sudo apt-get install libgmp-dev libgmpxx-dev```

Compile `utils/LLL/lll.cpp` with:

```g++ utils/LLL/lll.cpp -shared -o utils/LLL/liblll.so -fPIC -lgmpxx -lgmp```

You can then use lll.py to interface with the C++ LLL implementation. Make sure to pass the path of
the ".so" file to the "LLLWrapper".
