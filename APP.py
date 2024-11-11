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
        command = command_var.get().encode('ascii')
        trailer = bytes.fromhex(trailer_var.get())

        full_command = header + command + trailer
        bcc = calculate_bcc(full_command)
        full_command += bytes([bcc])

        with serial.Serial(port, baudrate, timeout=3) as ser:
            ser.write(full_command)
            response = ser.read(100)

            response_text = binascii.hexlify(response).decode(
            ) + " - " + response.decode('ascii').strip()
            terminal.insert(tk.END, f"Enviado: {
                            binascii.hexlify(full_command).decode()}\n")
            terminal.insert(tk.END, f"Recebido: {response_text}\n")
    except Exception as e:
        messagebox.showerror("Erro", str(e))


def clear_terminal():
    terminal.delete('1.0', tk.END)


def list_ports():
    ports = [port.device for port in serial.tools.list_ports.comports()]
    port_var.set('')
    port_menu['menu'].delete(0, 'end')
    for port in ports:
        port_menu['menu'].add_command(
            label=port, command=tk._setit(port_var, port))
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
port_menu = ttk.OptionMenu(mainframe, port_var, '')
port_menu.grid(row=0, column=1, sticky=(tk.W, tk.E))

# Baudrate selection
ttk.Label(mainframe, text="Baudrate:").grid(row=1, column=0, sticky=tk.W)
baudrate_var = tk.StringVar(value="115200")
baudrate_menu = ttk.Combobox(mainframe, textvariable=baudrate_var, values=[
                             "9600", "19200", "38400", "57600", "115200"])
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
terminal_frame.grid(row=5, column=0, columnspan=3,
                    sticky=(tk.W, tk.E, tk.N, tk.S))

terminal_scrollbar = ttk.Scrollbar(terminal_frame, orient=tk.VERTICAL)
terminal_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

terminal = tk.Text(terminal_frame, height=10, width=50,
                   yscrollcommand=terminal_scrollbar.set)
terminal.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
terminal_scrollbar.config(command=terminal.yview)

# Make terminal_frame resizable
mainframe.rowconfigure(5, weight=1)
terminal_frame.columnconfigure(0, weight=1)
terminal_frame.rowconfigure(0, weight=1)

# Send, Clear and Refresh buttons
button_frame = ttk.Frame(mainframe)
button_frame.grid(row=0, column=2, rowspan=5, sticky=(tk.N, tk.S, tk.E, tk.W))

send_button = ttk.Button(button_frame, text="Enviar Comando",
                         command=send_command, style="TButton")
send_button.grid(row=1, column=0, sticky=(tk.W, tk.E))

clear_button = ttk.Button(
    button_frame, text="Limpar Terminal", command=clear_terminal, style="TButton")
clear_button.grid(row=2, column=0, sticky=(tk.W, tk.E))

refresh_button = ttk.Button(
    button_frame, text="Refresh Ports", command=list_ports, style="TButton")
refresh_button.grid(row=0, column=0, sticky=(tk.W, tk.E))

# Ensure button_frame is resizable
button_frame.columnconfigure(0, weight=1)
button_frame.rowconfigure(0, weight=1)
button_frame.rowconfigure(1, weight=1)
button_frame.rowconfigure(2, weight=1)

# List available ports at startup
list_ports()

root.mainloop()


# Esta versão está sem o ajuste dos botões
'''import serial.tools.list_ports
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
        command = command_var.get().encode('ascii')
        trailer = bytes.fromhex(trailer_var.get())

        full_command = header + command + trailer
        bcc = calculate_bcc(full_command)
        full_command += bytes([bcc])

        with serial.Serial(port, baudrate, timeout=3) as ser:
            ser.write(full_command)
            response = ser.read(100)

            response_text = binascii.hexlify(response).decode(
            ) + " - " + response.decode('ascii').strip()
            terminal.insert(tk.END, f"Enviado: {
                            binascii.hexlify(full_command).decode()}\n")
            terminal.insert(tk.END, f"Recebido: {response_text}\n")
    except Exception as e:
        messagebox.showerror("Erro", str(e))


def clear_terminal():
    terminal.delete('1.0', tk.END)


def list_ports():
    ports = [port.device for port in serial.tools.list_ports.comports()]
    port_var.set('')
    port_menu['menu'].delete(0, 'end')
    for port in ports:
        port_menu['menu'].add_command(
            label=port, command=tk._setit(port_var, port))
    if ports:
        port_var.set(ports[0])


root = tk.Tk()
root.title("Serial Communication")

mainframe = ttk.Frame(root, padding="10")
mainframe.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Make the mainframe resizable
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
mainframe.columnconfigure(1, weight=1)

# Port selection
ttk.Label(mainframe, text="Porta Serial:").grid(row=0, column=0, sticky=tk.W)
port_var = tk.StringVar()
port_menu = ttk.OptionMenu(mainframe, port_var, '')
port_menu.grid(row=0, column=1, sticky=(tk.W, tk.E))

# Baudrate selection
ttk.Label(mainframe, text="Baudrate:").grid(row=1, column=0, sticky=tk.W)
baudrate_var = tk.StringVar(value="115200")
baudrate_menu = ttk.Combobox(mainframe, textvariable=baudrate_var, values=[
                             "9600", "19200", "38400", "57600", "115200"])
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
terminal_frame.grid(row=5, column=0, columnspan=3,
                    sticky=(tk.W, tk.E, tk.N, tk.S))

terminal_scrollbar = ttk.Scrollbar(terminal_frame, orient=tk.VERTICAL)
terminal_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

terminal = tk.Text(terminal_frame, height=10, width=50,
                   yscrollcommand=terminal_scrollbar.set)
terminal.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
terminal_scrollbar.config(command=terminal.yview)

# Make terminal_frame resizable
mainframe.rowconfigure(5, weight=1)
terminal_frame.columnconfigure(0, weight=1)
terminal_frame.rowconfigure(0, weight=1)


# Refresh Ports button
refresh_button = ttk.Button(
    mainframe, text="Refresh Ports", command=list_ports)
refresh_button.grid(row=0, column=2, sticky=tk.W)

# Send and Clear buttons
send_button = ttk.Button(
    mainframe, text="Enviar Comando", command=send_command)
send_button.grid(row=1, column=2, sticky=tk.W)
clear_button = ttk.Button(
    mainframe, text="Limpar Terminal", command=clear_terminal)
clear_button.grid(row=2, column=2, sticky=tk.E)

# List available ports at startup
list_ports()

root.mainloop()'''

# versão sem o refresh das portas.
'''import serial.tools.list_ports
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
        command = command_var.get().encode('ascii')
        trailer = bytes.fromhex(trailer_var.get())

        full_command = header + command + trailer
        bcc = calculate_bcc(full_command)
        full_command += bytes([bcc])

        with serial.Serial(port, baudrate, timeout=3) as ser:
            ser.write(full_command)
            response = ser.read(100)

            response_text = binascii.hexlify(response).decode(
            ) + " - " + response.decode('ascii').strip()
            terminal.insert(tk.END, f"Enviado: {
                            binascii.hexlify(full_command).decode()}\n")
            terminal.insert(tk.END, f"Recebido: {response_text}\n")
    except Exception as e:
        messagebox.showerror("Erro", str(e))


def clear_terminal():
    terminal.delete('1.0', tk.END)


def list_ports():
    ports = [port.device for port in serial.tools.list_ports.comports()]
    port_var.set('')
    port_menu['menu'].delete(0, 'end')
    for port in ports:
        port_menu['menu'].add_command(
            label=port, command=tk._setit(port_var, port))
    if ports:
        port_var.set(ports[0])


root = tk.Tk()
root.title("Serial Communication")

mainframe = ttk.Frame(root, padding="10")
mainframe.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Make the mainframe resizable
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
mainframe.columnconfigure(1, weight=1)

# Port selection
ttk.Label(mainframe, text="Porta Serial:").grid(row=0, column=0, sticky=tk.W)
port_var = tk.StringVar()
port_menu = ttk.OptionMenu(mainframe, port_var, '')
port_menu.grid(row=0, column=1, sticky=(tk.W, tk.E))

# Baudrate selection
ttk.Label(mainframe, text="Baudrate:").grid(row=1, column=0, sticky=tk.W)
baudrate_var = tk.StringVar(value="115200")
baudrate_menu = ttk.Combobox(mainframe, textvariable=baudrate_var, values=[
                             "9600", "19200", "38400", "57600", "115200"])
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
terminal_frame.grid(row=5, column=0, columnspan=2,
                    sticky=(tk.W, tk.E, tk.N, tk.S))

terminal_scrollbar = ttk.Scrollbar(terminal_frame, orient=tk.VERTICAL)
terminal_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

terminal = tk.Text(terminal_frame, height=10, width=50,
                   yscrollcommand=terminal_scrollbar.set)
terminal.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
terminal_scrollbar.config(command=terminal.yview)

# Make terminal_frame resizable
mainframe.rowconfigure(5, weight=1)
terminal_frame.columnconfigure(0, weight=1)
terminal_frame.rowconfigure(0, weight=1)

# Send and Clear buttons
send_button = ttk.Button(
    mainframe, text="Enviar Comando", command=send_command)
send_button.grid(row=6, column=0, sticky=tk.W)
clear_button = ttk.Button(
    mainframe, text="Limpar Terminal", command=clear_terminal)
clear_button.grid(row=6, column=1, sticky=tk.E)

# List available ports at startup
list_ports()

root.mainloop()'''


# Versão sem a correção das porta serial
'''import tkinter as tk
from tkinter import ttk
import serial.tools.list_ports
import serial
import binascii
import time


def list_serial_ports():
    ports = serial.tools.list_ports.comports()
    return [port.device for port in ports]


def send_command():
    # Captura os valores dos campos de entrada
    port = port_var.get()
    baudrate = int(baudrate_var.get())
    command = command_entry.get().encode('ascii')
    header = header_entry.get()  # Header em formato hexadecimal
    trailer = trailer_entry.get()  # Trailer em formato hexadecimal

    try:
        # Abrir a porta serial
        ser = serial.Serial(port, baudrate, timeout=3)
        log_text.insert(tk.END, f"Porta {port} aberta com sucesso.\n")

        # Converter header e trailer de hexadecimal para bytes
        header_bytes = bytes.fromhex(header)
        trailer_bytes = bytes.fromhex(trailer)

        # Combinar header, comando e trailer
        full_command = header_bytes + command + trailer_bytes

        # Calcular BCC se necessário
        bcc = calculate_bcc(full_command)
        full_command += bytes([bcc])

        # Enviar comando
        ser.write(full_command)
        log_text.insert(tk.END, f"Comando enviado: {
                        binascii.hexlify(full_command).decode()}\n")

        # Aguardar um tempo para garantir que o dispositivo tenha tempo de responder
        time.sleep(3)  # Esperar 3 segundos (ajuste conforme necessário)

        # Ler e processar a resposta
        response = ser.read(100)  # Ler até 100 bytes da resposta
        log_text.insert(tk.END, f"Bytes lidos: {len(response)}\n")

        if response:
            # Decodificar a resposta para texto
            response_text = response.decode('ascii').strip()

            # Substituir emojis por pontos
            response_text_clean = ''.join('.' if ord(
                char) >= 128 else char for char in response_text)

            # Exibir a resposta na tela
            log_text.insert(tk.END, f"Resposta recebida (hex): {
                            binascii.hexlify(response).decode()}\n")
            log_text.insert(tk.END, f"Resposta recebida (texto): {
                            response_text_clean}\n")
        else:
            log_text.insert(tk.END, "Nenhuma resposta recebida.\n")

    except serial.SerialException as e:
        log_text.insert(tk.END, f"Erro ao abrir a porta {port}: {e}\n")
    finally:
        # Fechar a porta serial
        if ser.is_open:
            ser.close()
            log_text.insert(tk.END, f"Porta {port} fechada.\n")


def calculate_bcc(data):
    bcc = 0x00
    for b in data:
        bcc ^= b
    return bcc


def clear_log():
    log_text.delete('1.0', tk.END)


# Configuração da interface gráfica
root = tk.Tk()
root.title("Envio de Comando Serial")

# Criar widgets
port_label = tk.Label(root, text="Porta Serial:")
port_label.grid(row=0, column=0, padx=10, pady=5)

ports = list_serial_ports()
port_var = tk.StringVar(root)
port_dropdown = ttk.Combobox(root, textvariable=port_var, values=ports)
port_dropdown.grid(row=0, column=1, padx=10, pady=5)
port_dropdown.current(0)  # Selecionar a primeira porta como padrão

baudrate_label = tk.Label(root, text="Taxa de Baud:")
baudrate_label.grid(row=1, column=0, padx=10, pady=5)

baudrate_var = tk.StringVar(root)
baudrate_var.set('115200')  # Valor padrão
baudrate_entry = ttk.Combobox(root, textvariable=baudrate_var, values=[
                              '9600', '19200', '38400', '57600', '115200'])
baudrate_entry.grid(row=1, column=1, padx=10, pady=5)

command_label = tk.Label(root, text="Comando:")
command_label.grid(row=2, column=0, padx=10, pady=5)
command_entry = tk.Entry(root)
command_entry.grid(row=2, column=1, padx=10, pady=5)
command_entry.insert(tk.END, 'V0')  # Valor padrão

header_label = tk.Label(root, text="Header (Hex):")
header_label.grid(row=3, column=0, padx=10, pady=5)
header_entry = tk.Entry(root)
header_entry.grid(row=3, column=1, padx=10, pady=5)
header_entry.insert(tk.END, '02')  # Valor padrão

trailer_label = tk.Label(root, text="Trailer (Hex):")
trailer_label.grid(row=4, column=0, padx=10, pady=5)
trailer_entry = tk.Entry(root)
trailer_entry.grid(row=4, column=1, padx=10, pady=5)
trailer_entry.insert(tk.END, '03')  # Valor padrão

send_button = tk.Button(root, text="Enviar Comando", command=send_command)
send_button.grid(row=5, column=0, columnspan=2, pady=10)

clear_button = tk.Button(root, text="Limpar Terminal", command=clear_log)
clear_button.grid(row=6, column=0, columnspan=2, pady=10)

log_text = tk.Text(root, height=10, width=50)
log_text.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

# Iniciar a interface gráfica
root.mainloop()'''


'''import tkinter as tk
import serial
import binascii
import time


def send_command():
    # Captura os valores dos campos de entrada
    port = port_entry.get()
    baudrate = int(baudrate_var.get())
    command = command_entry.get().encode('ascii')

    try:
        # Abrir a porta serial
        ser = serial.Serial(port, baudrate, timeout=3)
        log_text.insert(tk.END, f"Porta {port} aberta com sucesso.\n")

        # Estrutura do comando com header e trailer
        header = bytes.fromhex('02')  # Header em hexadecimal
        trailer = bytes.fromhex('03')  # Trailer em hexadecimal

        # Combinar header, comando e trailer
        full_command = header + command + trailer

        # Calcular BCC se necessário
        bcc = calculate_bcc(full_command)
        full_command += bytes([bcc])

        # Enviar comando
        ser.write(full_command)
        log_text.insert(tk.END, f"Comando enviado: {
                        binascii.hexlify(full_command).decode()}\n")

        # Aguardar um tempo para garantir que o dispositivo tenha tempo de responder
        time.sleep(3)  # Esperar 3 segundos (ajuste conforme necessário)

        # Ler e processar a resposta
        response = ser.read(100)  # Ler até 100 bytes da resposta
        log_text.insert(tk.END, f"Bytes lidos: {len(response)}\n")

        if response:
            # Decodificar a resposta para texto
            response_text = response.decode('ascii').strip()

            # Substituir emojis por pontos
            response_text_clean = ''.join('.' if ord(
                char) >= 128 else char for char in response_text)

            # Exibir a resposta na tela
            log_text.insert(tk.END, f"Resposta recebida (hex): {
                            binascii.hexlify(response).decode()}\n")
            log_text.insert(tk.END, f"Resposta recebida (texto): {
                            response_text_clean}\n")
        else:
            log_text.insert(tk.END, "Nenhuma resposta recebida.\n")

    except serial.SerialException as e:
        log_text.insert(tk.END, f"Erro ao abrir a porta {port}: {e}\n")
    finally:
        # Fechar a porta serial
        if ser.is_open:
            ser.close()
            log_text.insert(tk.END, f"Porta {port} fechada.\n")


def calculate_bcc(data):
    bcc = 0x00
    for b in data:
        bcc ^= b
    return bcc


def clear_log():
    log_text.delete('1.0', tk.END)


# Configuração da interface gráfica
root = tk.Tk()
root.title("Envio de Comando Serial")

# Criar widgets
port_label = tk.Label(root, text="Porta Serial:")
port_label.grid(row=0, column=0, padx=10, pady=5)
port_entry = tk.Entry(root)
port_entry.grid(row=0, column=1, padx=10, pady=5)
port_entry.insert(tk.END, 'COM16')  # Valor padrão

baudrate_label = tk.Label(root, text="Taxa de Baud:")
baudrate_label.grid(row=1, column=0, padx=10, pady=5)

baudrate_var = tk.StringVar(root)
baudrate_var.set('115200')  # Valor padrão
baudrate_entry = tk.OptionMenu(
    root, baudrate_var, '9600', '19200', '38400', '57600', '115200')
baudrate_entry.grid(row=1, column=1, padx=10, pady=5)

command_label = tk.Label(root, text="Comando:")
command_label.grid(row=2, column=0, padx=10, pady=5)
command_entry = tk.Entry(root)
command_entry.grid(row=2, column=1, padx=10, pady=5)
command_entry.insert(tk.END, 'V0')  # Valor padrão

send_button = tk.Button(root, text="Enviar Comando", command=send_command)
send_button.grid(row=3, column=0, columnspan=2, pady=10)

clear_button = tk.Button(root, text="Limpar Terminal", command=clear_log)
clear_button.grid(row=4, column=0, columnspan=2, pady=10)

log_text = tk.Text(root, height=10, width=50)
log_text.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

# Iniciar a interface gráfica
root.mainloop()'''


'''import serial
import binascii
import time


def calculate_bcc(data):
    bcc = 0x00
    for b in data:
        bcc ^= b
    return bcc


# Configuração da porta serial
port = 'COM16'  # No Windows, pode ser 'COM3', 'COM4', etc. No Linux/Mac, algo como '/dev/ttyUSB0'
baudrate = 115200  # Configure a taxa de baud correta para o seu dispositivo
timeout = 3  # Aumentar o tempo de espera para garantir que a resposta seja recebida

try:
    # Abrir a porta serial
    ser = serial.Serial(port, baudrate, timeout=timeout)
    print(f"Porta {port} aberta com sucesso.")

    # Estrutura do comando com header e trailer
    header = bytes.fromhex('02')  # Header em hexadecimal
    command = 'V0'.encode('ascii')  # Comando em si
    trailer = bytes.fromhex('03')  # Trailer em hexadecimal

    # Combinar header, comando e trailer
    full_command = header + command + trailer

    # Calcular BCC se necessário
    bcc = calculate_bcc(full_command)
    full_command += bytes([bcc])

    # Enviar comando
    ser.write(full_command)
    print(f"Comando enviado: {binascii.hexlify(full_command).decode()}")

    # Aguardar um tempo para garantir que o dispositivo tenha tempo de responder
    time.sleep(3)  # Esperar 3 segundos (ajuste conforme necessário)

    # Ler e processar a resposta
    response = ser.read(100)  # Ler até 100 bytes da resposta
    print(f"Bytes lidos: {len(response)}")

    if response:
        # Decodificar a resposta para texto
        response_text = response.decode('ascii').strip()

        # Substituir emojis por pontos
        response_text_clean = ''.join('.' if ord(
            char) >= 128 else char for char in response_text)

        # Imprimir a resposta em formato hexadecimal e texto substituindo emojis
        print(f"Resposta recebida (hex): {
              binascii.hexlify(response).decode()}")
        print(f"Resposta recebida (texto): {response_text_clean}")
    else:
        print("Nenhuma resposta recebida.")

except serial.SerialException as e:
    print(f"Erro ao abrir a porta {port}: {e}")
finally:
    # Fechar a porta serial
    if ser.is_open:
        ser.close()
        print(f"Porta {port} fechada.")'''


'''import serial
import binascii
import time


def calculate_bcc(data):
    bcc = 0x00
    for b in data:
        bcc ^= b
    return bcc


# Configuração da porta serial
port = 'COM16'  # No Windows, pode ser 'COM3', 'COM4', etc. No Linux/Mac, algo como '/dev/ttyUSB0'
baudrate = 115200  # Configure a taxa de baud correta para o seu dispositivo
timeout = 3  # Aumentar o tempo de espera para garantir que a resposta seja recebida

try:
    # Abrir a porta serial
    ser = serial.Serial(port, baudrate, timeout=timeout)
    print(f"Porta {port} aberta com sucesso.")

    # Estrutura do comando com header e trailer
    header = bytes.fromhex('02')  # Header em hexadecimal
    command = 'V0'.encode('ascii')  # Comando em si
    trailer = bytes.fromhex('03')  # Trailer em hexadecimal

    # Combinar header, comando e trailer
    full_command = header + command + trailer

    # Calcular BCC se necessário
    bcc = calculate_bcc(full_command)
    full_command += bytes([bcc])

    # Enviar comando
    ser.write(full_command)
    print(f"Comando enviado: {binascii.hexlify(full_command).decode()}")

    # Aguardar um tempo para garantir que o dispositivo tenha tempo de responder
    time.sleep(3)  # Esperar 3 segundos (ajuste conforme necessário)

    # Ler e processar a resposta
    response = ser.read(100)  # Ler até 300 bytes da resposta
    print(f"Bytes lidos: {len(response)}")

    if response:
        # Imprimir a resposta em formato hexadecimal
        print(f"Resposta recebida: {binascii.hexlify(
            response).decode()} - {response.decode('ascii').strip()}")
    else:
        print("Nenhuma resposta recebida.")

except serial.SerialException as e:
    print(f"Erro ao abrir a porta {port}: {e}")
finally:
    # Fechar a porta serial
    if ser.is_open:
        ser.close()
        print(f"Porta {port} fechada.")'''


'''import serial

# Configuração da porta serial (substitua 'COM16' pelo nome da porta correta no seu sistema)
port = 'COM16'  # No Windows, pode ser 'COM3', 'COM4', etc. No Linux/Mac, algo como '/dev/ttyUSB0'
baudrate = 115200  # Configure a taxa de baud correta para o seu dispositivo

try:
    # Abrir a porta serial
    ser = serial.Serial(port, baudrate, timeout=1)
    print(f"Porta {port} aberta com sucesso.")

    # Estrutura do comando com header e trailer
    header = bytes.fromhex('02')  # Substitua pelo seu header em hexadecimal
    command = 'V0'.encode()  # Comando em si
    trailer = bytes.fromhex('67')  # Substitua pelo seu trailer em hexadecimal

    # Combinar header, comando e trailer
    full_command = header + command + trailer

    # Enviar comando
    ser.write(full_command)

    # Ler a resposta
    response = ser.readline().decode().strip()
    print(f"Resposta: {response}")

except serial.SerialException as e:
    print(f"Erro ao abrir a porta {port}: {e}")
finally:
    # Fechar a porta serial
    if ser.is_open:
        ser.close()
        print(f"Porta {port} fechada.")
'''
