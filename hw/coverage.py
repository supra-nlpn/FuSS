import sys
import csv

# Function to parse the variable declarations and signal bits
def parse_var_lines(vcd_lines):
    total_bits = 0
    signal_bits = {}
    signal_descriptions = {}

    for line in vcd_lines:
        var_list = line.split()

        if var_list[0] == "$var":
            num_bits = int(var_list[2])  # Number of bits in the signal
            unique_symbol = var_list[3]  # Unique symbol of the signal
            signal_bits[unique_symbol] = [num_bits, 0]  # [bitcount, toggled_bits]

            # Store the full description of the signal
            signal_descriptions[unique_symbol] = line.strip()

            total_bits += num_bits

    return total_bits, signal_bits, signal_descriptions


def track_toggles(vcd_lines, signal_bits):
    signal_values = {}

    for line in vcd_lines:
        line = line.strip()

        if line.startswith("b"):  # Binary values (for multi-bit signals)
            binary_value, signal_id = line.split()
            binary_value = binary_value.replace("x", "0").replace("z", "0")  # Handle x/z as 0

            # Get the bit width of the signal
            num_bits = signal_bits[signal_id][0]

            # Pad binary value with leading zeros to match the signal bit width
            binary_value = binary_value.zfill(num_bits)

            if signal_id not in signal_values:
                signal_values[signal_id] = ['0'] * num_bits  # Initialize the signal with "0"s
            else:
                prev_value = signal_values[signal_id]

                # Count the toggles (0 -> 1) for each bit position
                toggled_bits = 0
                for i in range(num_bits):
                    if prev_value[i] == '0' and binary_value[i] == '1':
                        prev_value[i] = '1'  # Mark the bit as toggled from 0 to 1
                        toggled_bits += 1
                
                signal_bits[signal_id][1] = min(signal_bits[signal_id][1] + toggled_bits, num_bits)

                signal_values[signal_id] = list(binary_value)

        elif line[0] in "01xz":  # Single-bit signals
            value = line[0].replace("x", "0").replace("z", "0")  # Handle x/z as 0
            signal_id = line[1:]

            if signal_id not in signal_values:
                signal_values[signal_id] = value
            else:
                prev_value = signal_values[signal_id]
                if prev_value == "0" and value == "1":
                    signal_bits[signal_id][1] = 1  # Set toggle value to 1 for a single-bit signal
                signal_values[signal_id] = value

    return signal_bits


# Function to process the VCD file
def process_vcd_file(file_path):
    with open(file_path, "r") as f:
        vcd_lines = f.readlines()

    total_bits, signal_bits, signal_descriptions = parse_var_lines(vcd_lines)  # Parse the signal declarations
    signal_bits = track_toggles(vcd_lines, signal_bits)  # Track toggles in $dumpvars

    return total_bits, signal_bits, signal_descriptions


# Function 1: all_vars
def all_vars(signal_bits):
    return signal_bits


# Function 2: single_bit_vars
def single_bit_vars(signal_bits):
    return {key: value for key, value in signal_bits.items() if value[0] == 1}


# Function 3: untoggled_vars
def untoggled_vars(signal_bits):
    return {key: value for key, value in signal_bits.items() if value[1] != value[0]}


# Function 4: toggles
def toggles(total_bits, signal_bits):
    toggled_bits = sum(value[1] for value in signal_bits.values())
    #total_bits = sum(value[0] for value in signal_bits.values())
    toggle_percentage = (toggled_bits / total_bits) * 100 if total_bits > 0 else 0
    return total_bits, toggled_bits, toggle_percentage, len(signal_bits)

# HELPER FUCNTION FOR FUZZING ENGINE
def helper_find_coverage(vcd_file_path):
    # Process the VCD file
    total_bits, signal_bits, _ = process_vcd_file(vcd_file_path)
    toggled_bits = sum(value[1] for value in signal_bits.values())
    toggle_percentage = (toggled_bits / total_bits) * 100 if total_bits > 0 else 0
    return toggle_percentage

# Function 5: def_sym
def def_sym(symbol, signal_descriptions):
    return signal_descriptions.get(symbol, f"No description found for symbol: {symbol}")


# Function 6: make_csv
def make_csv(signal_bits):
    csv_filename = "signals.csv"
    with open(csv_filename, mode="w", newline="") as csv_file:
        csv_writer = csv.writer(csv_file)

        # Write CSV headers
        csv_writer.writerow(["Symbol", "Bit Width", "Toggled Bits"])

        # Write each signal's information
        for symbol, (bit_width, toggled_bits) in signal_bits.items():
            csv_writer.writerow([symbol, bit_width, toggled_bits])

    print(f"CSV file '{csv_filename}' created successfully.")


# Function 7: help
def help():
    help_text = """
    Usage: python coverage.py <vcd_file> <function_name> | help
    Available commands:
    1. all_vars         - Print all variables with their bit widths and toggle counts.
    2. single_bit_vars  - Print all single-bit variables.
    3. untoggled_vars   - Print variables that haven't toggled all bits.
    4. toggles          - Print total number of bits, number of toggled bits, and toggle coverage percentage of the entire VCD.
    5. def_sym <symbol> - Print the description of the specified symbol.
    6. make_csv         - Generate a CSV file of all variables with their bit widths and toggle counts.
    7. help             - Print this help message.
    """
    print(help_text)


# Command-line Interface
def main():
    # Check if the user asked for help
    if len(sys.argv) == 2 and sys.argv[1] == "help":
        help()
        sys.exit(0)

    if len(sys.argv) < 3:
        print("Usage: python coverage.py <vcd_file> <function_name> [symbol]")
        sys.exit(1)

    file_path = sys.argv[1]
    function_name = sys.argv[2]

    # Process the VCD file
    total_bits, signal_bits, signal_descriptions = process_vcd_file(file_path)

    # Call the appropriate function based on the command-line argument
    if function_name == "all_vars":
        result = all_vars(signal_bits)
        print(result)
    elif function_name == "single_bit_vars":
        result = single_bit_vars(signal_bits)
        print(result)
    elif function_name == "untoggled_vars":
        result = untoggled_vars(signal_bits)
        print(result)
    elif function_name == "toggles":
        result = toggles(total_bits, signal_bits)
        print(f"Total bits: {result[0]}")
        print(f"Toggled bits: {result[1]}")
        print(f"Toggle coverage: {result[2]:.2f}%")
        print(f"len of signal_bits: {result[3]}")
    elif function_name == "def_sym":
        if len(sys.argv) != 4:
            print("Usage for def_sym: python coverage.py <vcd_file> def_sym <symbol>")
            sys.exit(1)
        symbol = sys.argv[3]
        result = def_sym(symbol, signal_descriptions)
        print(result)
    elif function_name == "make_csv":
        make_csv(signal_bits)
    else:
        print(f"Unknown function: {function_name}")
        sys.exit(1)


if __name__ == "__main__":
    main()
