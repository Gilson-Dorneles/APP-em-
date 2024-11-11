import serial.tools.list_ports
import tkinter as tk
from tkinter import ttk, messagebox
import serial
import binascii
import time


def calculate_bcc(data):
    bcc = 0x00
    for b in data:
        bcc ^= b
    return bcc


def send_command():
    try:
        port = port_var.get()
        baudrate = int(baudrate_var.get())
        header = bytes.fromhex(header_var.get())
        command = command_var.get().encode("ascii")
        trailer = bytes.fromhex(trailer_var.get())

        full_command = header + command + trailer
        bcc = calculate_bcc(full_command)
        full_command += bytes([bcc])

        with serial.Serial(port, baudrate, timeout=3) as ser:
            ser.write(full_command)
            response = ser.read(100)

            response_text = (
                binascii.hexlify(response).decode()
                + " - "
                + response.decode("ascii").strip()
            )
            terminal.insert(
                tk.END,
                f"Enviado: {
                            binascii.hexlify(full_command).decode()}\n",
            )
            terminal.insert(tk.END, f"Recebido: {response_text}\n")
    except Exception as e:
        messagebox.showerror("Erro", str(e))


def clear_terminal():
    terminal.delete("1.0", tk.END)


def list_ports():
    ports = [port.device for port in serial.tools.list_ports.comports()]
    port_var.set("")
    port_menu["menu"].delete(0, "end")
    for port in ports:
        port_menu["menu"].add_command(label=port, command=tk._setit(port_var, port))
    if ports:
        port_var.set(ports[0])


root = tk.Tk()
root.title("Serial Communication")

style = ttk.Style()
style.configure("TButton", padding=6, relief="flat", background="#ccc")

mainframe = ttk.Frame(root, padding="10")
mainframe.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Make the mainframe resizable
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
mainframe.columnconfigure(1, weight=1)

# Port selection
ttk.Label(mainframe, text="Porta Serial:").grid(row=0, column=0, sticky=tk.W)
port_var = tk.StringVar()
port_menu = ttk.OptionMenu(mainframe, port_var, "")
port_menu.grid(row=0, column=1, sticky=(tk.W, tk.E))

# Baudrate selection
ttk.Label(mainframe, text="Baudrate:").grid(row=1, column=0, sticky=tk.W)
baudrate_var = tk.StringVar(value="115200")
baudrate_menu = ttk.Combobox(
    mainframe,
    textvariable=baudrate_var,
    values=["9600", "19200", "38400", "57600", "115200"],
)
baudrate_menu.grid(row=1, column=1, sticky=(tk.W, tk.E))

# Header input
ttk.Label(mainframe, text="Header (Hex):").grid(row=2, column=0, sticky=tk.W)
header_var = tk.StringVar(value="02")
header_entry = ttk.Entry(mainframe, textvariable=header_var)
header_entry.grid(row=2, column=1, sticky=(tk.W, tk.E))

# Command input
ttk.Label(mainframe, text="Comando:").grid(row=3, column=0, sticky=tk.W)
command_var = tk.StringVar(value="V0")
command_entry = ttk.Entry(mainframe, textvariable=command_var)
command_entry.grid(row=3, column=1, sticky=(tk.W, tk.E))

# Trailer input
ttk.Label(mainframe, text="Trailer (Hex):").grid(row=4, column=0, sticky=tk.W)
trailer_var = tk.StringVar(value="03")
trailer_entry = ttk.Entry(mainframe, textvariable=trailer_var)
trailer_entry.grid(row=4, column=1, sticky=(tk.W, tk.E))

# Terminal output with scrollbar
terminal_frame = ttk.Frame(mainframe)
terminal_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))

terminal_scrollbar = ttk.Scrollbar(terminal_frame, orient=tk.VERTICAL)
terminal_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

terminal = tk.Text(
    terminal_frame, height=10, width=50, yscrollcommand=terminal_scrollbar.set
)
terminal.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
terminal_scrollbar.config(command=terminal.yview)

# Make terminal_frame resizable
mainframe.rowconfigure(5, weight=1)
terminal_frame.columnconfigure(0, weight=1)
terminal_frame.rowconfigure(0, weight=1)

# Send, Clear and Refresh buttons
button_frame = ttk.Frame(mainframe)
button_frame.grid(row=0, column=2, rowspan=5, sticky=(tk.N, tk.S, tk.E, tk.W))

send_button = ttk.Button(
    button_frame, text="Enviar Comando", command=send_command, style="TButton"
)
send_button.grid(row=1, column=0, sticky=(tk.W, tk.E))

clear_button = ttk.Button(
    button_frame, text="Limpar Terminal", command=clear_terminal, style="TButton"
)
clear_button.grid(row=2, column=0, sticky=(tk.W, tk.E))

refresh_button = ttk.Button(
    button_frame, text="Refresh Ports", command=list_ports, style="TButton"
)
refresh_button.grid(row=0, column=0, sticky=(tk.W, tk.E))

# Ensure button_frame is resizable
button_frame.columnconfigure(0, weight=1)
button_frame.rowconfigure(0, weight=1)
button_frame.rowconfigure(1, weight=1)
button_frame.rowconfigure(2, weight=1)

# List available ports at startup
list_ports()

root.mainloop()
