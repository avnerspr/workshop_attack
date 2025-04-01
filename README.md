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
```


# Running the CTF

## Setup

Make sure the players have the files `eval_server/ctf_params.py` and `eval_server/eval_client.py`
Additionally, make sure they have the attached PDF file with instructions (in Hebrew).
Also make sure that `eval_server/eval_client.py` is configured with the correct port and host.

## Running the Servers

1. To run the oracle server, use `python -m oracle_server.server`. 
    See `python -m oracle_server.server --help` for additional details.
2. To run the evaluation server (to which players send their answers), run `python -m eval_server`.
    See `python -m eval_server --help` for additional configuration and details. Make sure the players
    know to use the provided interface (`eval_server/eval_client.py`) to interact with the server.

