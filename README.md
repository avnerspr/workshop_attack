# **Workshop Attack - Bleichenbacher Attack Implementation**  

## **Prerequisites**  

Before compiling and running the attack, install the required libraries:  

```bash
sudo apt-get install libgmp-dev libgmpxx-dev
```

## **Compilation**  

Compile the `LLL` implementation:  

```bash
g++ utils/LLL/lll.cpp -shared -o utils/LLL/liblll.so -fPIC -lgmpxx -lgmp
```

## **Usage**  

You can interface with the C++ LLL implementation using `lll.py`.  
Make sure to pass the path of the `.so` file to `LLLWrapper`.  

## **Attack Implementation**  

The `attack` module contains three attack classes:  
- `Attacker`  
- `MultiServerAttacker`  
- `ParallelAttack`  

### **Running the Attack**  

1. Start the server:  
   ```bash
   python -m oracle_server.server
   ```
2. Run the attack:  
   ```bash
   python -m attack.<attack-name>
   ```  
   Replace `<attack-name>` with one of the available attack classes (`attacker`, `multiserver_attacker`, or `parallel_attack`).  

Each attack module is configurable via command-line arguments. Use the `-h` flag to see available options:  

```bash
python -m attack.<attack-name> -h
