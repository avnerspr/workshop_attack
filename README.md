# workshop_attack

## Usage

Compile `lll/lll.cpp` with:

```g++ LLL/lll.cpp -shared -o LLL/liblll.so -fPIC```

You can then use lll.py to interface with the C++ LLL implementation. Make sure to pass the path of
the ".so" file to the "LLLWrapper".
