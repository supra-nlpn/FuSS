#include <stdint.h>
#include <stdbool.h>

#define reg_uart_data (*(volatile uint32_t*)0x02000008)  // UART data register
#define reg_uart_ready (*(volatile uint32_t*)0x0200000C) // UART ready register

void putchar(char c)
{
    if (c == '\n')
        putchar('\r');
    reg_uart_data = c;
}

void print_str(const char *p)
{
    while (*p)
        putchar(*(p++));
}

void print_number(uint32_t num)
{
    char buffer[11]; // Buffer to hold string representation of the number
    int i = 0;

    if (num == 0) {
        putchar('0');
        return;
    }

    while (num > 0) {
        buffer[i++] = (num % 10) + '0'; // Get last digit and convert to character
        num /= 10; // Remove last digit
    }

    // Print the number in reverse order
    while (i > 0) {
        putchar(buffer[--i]);
    }
}

// Function to receive a character via UART (blocking read)
char getchar(void)
{
    while ((reg_uart_ready & 1) == 0);  // Wait until UART is ready to receive
    return reg_uart_data;
}

// Function to receive an input number via UART
uint32_t receive_number(void)
{
    char c;
    uint32_t number = 0;

    print_str("Enter a number to start counting:\n");

    while (1) {
        c = getchar();
        putchar(c);  // Echo the input back

        if (c >= '0' && c <= '9') {  // Check if the input is a digit
            number = number * 10 + (c - '0');  // Convert character to integer
        } else if (c == '\n' || c == '\r') {  // Stop receiving input on newline
            break;
        } else {
            print_str("\nInvalid input. Please enter a valid number:\n");
            number = 0;  // Reset the number if input is invalid
        }
    }

    return number;
}

// Simulated branching logic to increase code coverage
void test_conditions(uint32_t input)
{
    if (input == 0) {
        print_str("Input is zero.\n");
    } else if (input > 0 && input <= 5) {
        print_str("Input is between 1 and 5.\n");
    } else if (input > 5 && input <= 10) {
        print_str("Input is between 6 and 10.\n");
    } else {
        print_str("Input is greater than 10.\n");
    }

    // Further logic to introduce more branches
    if (input % 2 == 0) {
        print_str("Input is even.\n");
    } else {
        print_str("Input is odd.\n");
    }
}

void main(void)
{
    (*(volatile uint32_t*)0x02000004) = 104; // Set UART clock rate

    // Receive a number from UART
    uint32_t input = receive_number();

    // Test conditions to explore different code paths
    test_conditions(input);

    // Start counting up to 10 from the input
    for (uint32_t count = input; count <= 10; count++) {
        print_number(count);  // Print the current count
        putchar('\n');  // Print a newline after each count
    }
}
