import subprocess
import random
from coverage import helper_find_coverage


def Angr_Handler():
    return 0


def read_firmware_hex(file_path):
    instructions = []
    with open(file_path, "r") as f:
        lines = f.readlines()
    for line in lines:
        line = line.strip()
        if not line.startswith("@") and line:
            bytes_list = line.split()  
            for i in range(0, len(bytes_list), 4):
                instruction = " ".join(bytes_list[i:i + 4])
                if len(instruction.split()) == 4:
                    instructions.append(instruction)
    return instructions


def run_simulation():
    try:
        print("Running iverilog...")
        subprocess.run(
            [
                "iverilog", 
                "-s", "testbench", 
                "-o", "ice.vvp", 
                "icebreaker_tb.v", "icebreaker.v", 
                "ice40up5k_spram.v", "spimemio.v", 
                "simpleuart.v", "picosoc.v", 
                "picorv32.v", "spiflash.v", 
                "/usr/share/yosys/ice40/cells_sim.v"
            ],
            check=True
        )
        print("iverilog completed successfully!")
        print("Running vvp...")
        subprocess.run(["vvp", "-N", "ice.vvp"], check=True)
        print("vvp simulation completed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"Error during simulation: {e}")
        return




def generate_new_instructions(existing_instructions, dropped_instructions, num_new_instructions):
    previous_instructions = set(existing_instructions + dropped_instructions)
    
    def generate_random_instruction():
        """Generate a random 32-bit instruction in the format 'XX XX XX XX'."""
        return " ".join(f"{random.randint(0, 255):02X}" for _ in range(4))

    new_instructions = []
    while len(new_instructions) < num_new_instructions:
        candidate = generate_random_instruction()
        if candidate not in previous_instructions: 
            new_instructions.append(candidate)
            previous_instructions.add(candidate)
    
    return new_instructions




def delete_last_instructions(hex_file_path, n, dropped_file_path="dropped_instrs.txt"):
    with open(hex_file_path, 'r') as file:
        lines = file.readlines()
    header = lines[0].strip() if lines[0].startswith("@") else None
    hex_lines = lines[1:] if header else lines
    instructions = []
    for line in hex_lines:
        instructions.extend(line.strip().split())
        
    total_instructions = len(instructions) // 4
    if n > total_instructions:
        raise ValueError(f"Cannot delete {n} instructions. The file only has {total_instructions} instructions.")
    remaining_instructions = instructions[:-(n * 4)]
    dropped_instructions = instructions[-(n * 4):]
    new_lines = []
    for i in range(0, len(remaining_instructions), 16): 
        new_lines.append(" ".join(remaining_instructions[i:i + 16]) + "\n")

    if header:
        new_lines.insert(0, header + "\n")
    with open(hex_file_path, 'w') as file:
        file.writelines(new_lines)
        
    with open(dropped_file_path, 'a') as file:
        for i in range(0, len(dropped_instructions), 16):
            file.write(" ".join(dropped_instructions[i:i + 16]) + "\n")
    print(f"Deleted the last {n} instructions from {hex_file_path} and appended them to {dropped_file_path}.")
    


def add_new_instructions(new_instructions):
    try:
        # Open the firmware file in append mode
        with open("firmware.hex", 'a') as firmware_file:
            # Append each new instruction to the file
            for instruction in new_instructions:
                firmware_file.write(f"{instruction}\n")
        print(f"Successfully appended {len(new_instructions)} instructions to firmware.hex")
    except Exception as e:
        print(f"An error occurred while appending instructions: {e}")



def fuzz_firmware(firmware_file, drop_file, previous_coverage, num_iterations, num_holds ,num_instructions, diff_coverage):
    print("FUZZING ENTRY POINT")
    iterations = 0
    switch_count = 0
    while iterations < num_iterations:
        print(f"Fuzzing Iteration ID: {iterations}")
        existing_instructions = read_firmware_hex(firmware_file)
        dropped_instructions = read_firmware_hex(drop_file)
        
        new_instructions = generate_new_instructions(existing_instructions, dropped_instructions, num_instructions)
        
        add_new_instructions(new_instructions)
        
        run_simulation()
        
        current_coverage = helper_find_coverage(vcd_file_path="testbench.vcd")
        print(f"current coverage: {current_coverage}")
        
        print(f"switch_count: {switch_count}, still {num_holds - switch_count} iterations remaining before switching to Angr")
        if switch_count == num_holds:
            Angr_Handler()
        
        if (current_coverage - previous_coverage) < diff_coverage:
            delete_last_instructions(firmware_file, num_instructions, drop_file)
            switch_count += 1
        else:
            previous_coverage = current_coverage
        iterations += 1
    
    
    
    
    

if __name__ == "__main__":
    # PARAMS
    firmware_file = "firmware.hex"
    drop_file = "dropped_instrs.txt"
    previous_coverage = 50                  # set based in initial simulation and coverage
    num_iterations = 10
    num_holds = 3                           # number of iterations the engine waits before switching to Angr
    num_instructions = 4
    diff_coverage = 0.01 
    fuzz_firmware(firmware_file, drop_file, previous_coverage, num_iterations, num_holds, num_instructions, diff_coverage)
