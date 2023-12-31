# Loop Variable Definitions:
# cd = cards drawn,
# mpil = mana produced in loop,
# tos = triggers on stack
# msil = mana spent in loop,
# nmp = net mana produced,
# gat = game actions taken,
import tkinter as tk
from tkinter import ttk, font

import numpy
import hashlib

# Assumptions: Infinite Mana, no Lands, no other cards in hand, no other cards in GY.


def on_encrypt():
    # Store the values in variables
    k_value = key_entry.get()
    msg = message_entry.get()
    block_size = extract_leading_number(rd_button_1.get())
    k = int_to_padded_binary_string(string_to_int_hash(k_value, block_size))
    gen_key = key_gen_wrapper(k)
    key_hash = int_to_n_bit_byte_hash(gen_key, block_size)
    msg_in = f"{msg}".encode('utf-8')
    ct = encrypt_ecb_with_padding(msg_in, key_hash, block_size)

    output_string = f"""
ENCRYPTION RESULTS:    
    
---INPUT VARIABLES---
key_in: "{k_value}"
plaintext_in: "{msg}"
hash_size: {rd_button_1.get()} bits

---OUTPUT VARIABLES---
generated_key: {gen_key}
ciphertext_out: 0x{ct.hex()}
"""

    # Insert the formatted output to the display
    display_text.delete(1.0, tk.END)  # Clear existing text
    display_text.insert(tk.END, output_string)
    key_entry_1.delete(0, tk.END)  # Clear existing text
    message_entry_1.delete(0, tk.END)  # Clear existing text
    key_entry_1.insert(0, f"{k_value}")
    message_entry_1.insert(0, f"0x{ct.hex()}")
    rd_button_2.set(rd_button_1.get())

    # Temporarily Enable Decryption Button
    submit_button_1.config(state=tk.NORMAL)


def on_decrypt():
    # Store the values in variables
    k_value_1 = key_entry_1.get()
    block_size = extract_leading_number(rd_button_2.get())
    ct = bytes.fromhex(message_entry_1.get()[2:])
    k = int_to_padded_binary_string(string_to_int_hash(k_value_1, block_size))

    # Generate Temp Key
    gen_key = key_gen_wrapper(k)
    key_hash = int_to_n_bit_byte_hash(gen_key, block_size)
    pt = decrypt_ecb_with_padding(ct, key_hash, block_size)

    output_string = f"""
DECRYPTION RESULTS:

---INPUT VARIABLES---
key_in: "{k_value_1}"
ciphertext_in: "0x{ct.hex()}"
hash_size: {rd_button_2.get()} bits

---OUTPUT VARIABLES---
generated_key: {gen_key}
plaintext_out: "{pt.decode('utf-8')}"
"""

    # Insert the formatted output to the display
    display_text.delete(1.0, tk.END)  # Clear existing text
    display_text.insert(tk.END, output_string)

    # Re-Disable the Encryption Button
    submit_button_1.config(state=tk.DISABLED)


def extract_leading_number(s):
    num_str = ""
    for char in s:
        if char.isdigit():
            num_str += char
        else:
            break

    return int(num_str) if num_str else None


def string_to_int_hash(s, bit_length=64):
    """Convert a string to an integer hash of the specified bit length and return its byte representation."""
    if bit_length not in [64, 128, 256]:
        raise ValueError("Only 64, 128, and 256 bit lengths are supported")

    bytes_needed = bit_length // 8
    hash_output = b''

    while len(hash_output) < bytes_needed:
        hash_output += hashlib.sha256(hash_output + s.encode()).digest()

    truncated_hash = hash_output[:bytes_needed]
    return int.from_bytes(truncated_hash, byteorder='big')


def int_to_n_bit_byte_hash(value, bit_length=64):
    """Return a byte representation of the hash of the given value with the specified bit length."""
    if bit_length not in [64, 128, 256]:
        raise ValueError("Only 64, 128, and 256 bit lengths are supported")

    bytes_needed = bit_length // 8
    hash_output = b''

    while len(hash_output) < bytes_needed:
        hash_output += hashlib.sha256(hash_output + str(value).encode()).digest()

    return hash_output[:bytes_needed]


def int_to_padded_binary_string(n):
    bin_str = bin(n)[2:]  # Convert to binary and remove the "0b" prefix
    bit_length = len(bin_str)

    # Determine the required width based on bit length
    if bit_length <= 64:
        width = 64
    elif bit_length <= 128:
        width = 128
    else:
        width = 256

    return bin_str.rjust(width, '0')


def get_3_most_significant_bits(key):
    return key[:3]


def get_nth_bit_from_end(key, n):
    try:
        return key[n]
    except IndexError:
        return '0'


def get_bits_before_position_n(key, n):
    return key[n:]


def binary_string_to_int(bin_str):
    return int(bin_str, 2)


def reset_dict(vd):
    vd['cd'] = 0
    vd['mpil'] = 0
    vd['msil'] = 0
    vd['nmp'] = 0
    vd['gat'] = 0
    vd['tos'] = 0
    vd['sos'] = 0


# Tap Mox Opal for mana + sac it to KCI
def tap_n_sac_mopal(vd):
    vd['gat'] = vd['gat'] + 2
    vd['mpil'] = vd['mpil'] + 3


# Tap Mind Stone for mana + sac it to KCI
def tap_n_sac_mstone(vd, num_trawlers):
    vd['gat'] = vd['gat'] + 2
    vd['mpil'] = vd['mpil'] + 3
    vd['tos'] = vd['tos'] + num_trawlers


# Sac Myr Retriever to KCI
def sac_retriever(vd, num_trawlers):
    vd['gat'] = vd['gat'] + 1
    vd['tos'] = vd['tos'] + 1 + num_trawlers
    vd['mpil'] = vd['mpil'] + 2


# Activate Chromatic Star
def activate_chromatic_star(vd):
    vd['gat'] = vd['gat'] + 1
    vd['tos'] = vd['tos'] + 2
    vd['msil'] = vd['msil'] + 1
    vd['cd'] = vd['cd'] + 1


# Activate Spell Bomb
def activate_sbomb(vd):
    vd['gat'] = vd['gat'] + 1
    vd['tos'] = vd['tos'] + 1
    vd['msil'] = vd['msil'] + 1


# Sacrifice an arbitrary artifact with some number of abilities
def sac_artifact(vd, is_spine, does_draw, num_trawlers):
    vd['gat'] = vd['gat'] + 1
    vd['mpil'] = vd['mpil'] + 2
    if is_spine:
        vd['tos'] = vd['tos'] + 1 + num_trawlers
    elif does_draw:
        vd['cd'] = vd['cd'] + 1
        vd['tos'] = vd['tos'] + 1 + num_trawlers
    else:
        vd['tos'] = vd['tos'] + num_trawlers


# Cast an arbitrary artifact with an arbitrary CMC
def cast_artifact(vd, cmc, has_etb, is_ichor_wellspring):
    vd['gat'] = vd['gat'] + 1
    vd['sos'] = vd['sos'] + 1
    vd['msil'] = vd['msil'] + cmc
    if is_ichor_wellspring:
        vd['cd'] = vd['cd'] + 1
        vd['tos'] = vd['tos'] + 1
    elif has_etb:
        vd['tos'] = vd['tos'] + 1


# Calculate Net Mana Produced
def calc_nmp(vd):
    vd['nmp'] = vd['mpil'] - vd['msil']


def perform_n_iterations(vd, n_iter):
    vd['cd'] = vd['cd'] * n_iter
    vd['mpil'] = vd['mpil'] * n_iter
    vd['msil'] = vd['msil'] * n_iter
    vd['nmp'] = vd['nmp'] * n_iter
    vd['gat'] = vd['gat'] * n_iter
    vd['tos'] = vd['tos'] * n_iter
    vd['sos'] = vd['sos'] * n_iter


# Loop 0: KCI, Scrap Trawler, Myr Retriever (in Play), Myr Retriever (in GY), Mox Opal
def loop_0(n, loop_value_dictionary):
    tap_n_sac_mopal(loop_value_dictionary)
    sac_retriever(loop_value_dictionary, 1)
    # Cast Mopal
    cast_artifact(loop_value_dictionary, 0, False, False)
    # Cast Myr Retriever
    cast_artifact(loop_value_dictionary, 2, False, False)
    calc_nmp(loop_value_dictionary)
    perform_n_iterations(loop_value_dictionary, n)


# Loop 1: KCI, Scrap Trawler, Spine of Ish Sah, Mind Stone (in GY), Chromatic Star (in GY), Mox Opal (in GY)
def loop_1(n, loop_value_dictionary):
    # Sac Spine of Ish Sah
    sac_artifact(loop_value_dictionary, True, False, 1)
    # Cast Mind Stone
    cast_artifact(loop_value_dictionary, 2, False, False)
    # Tap and Sac Stone
    tap_n_sac_mstone(loop_value_dictionary, 1)
    # Cast Star
    cast_artifact(loop_value_dictionary, 1, False, False)
    # Sac Star
    sac_artifact(loop_value_dictionary, False, True, 1)
    # Cast Mopal
    cast_artifact(loop_value_dictionary, 0, False, False)
    # Tap and Sac Mopal
    tap_n_sac_mopal(loop_value_dictionary)
    # Cast Spine
    cast_artifact(loop_value_dictionary, 7, True, False)
    calc_nmp(loop_value_dictionary)
    perform_n_iterations(loop_value_dictionary, n)


# Loop 2: KCI, Scrap Trawler, Myr Retriever, Chromatic Star (in Play), Chromatic Star (in Hand), Mox Opal
def loop_2(n, loop_value_dictionary):
    # Cast Star (paying for it with following sacrifices)
    cast_artifact(loop_value_dictionary, 1, False, False)
    # Tap Mox for Mana and Sacrifice
    tap_n_sac_mopal(loop_value_dictionary)
    # Sac Star
    sac_artifact(loop_value_dictionary, False, True, 1)
    # Sac Myr
    sac_retriever(loop_value_dictionary, 1)
    # Sac Trawler
    sac_artifact(loop_value_dictionary, False, False, 1)
    # Cast Mox
    cast_artifact(loop_value_dictionary, 0, False, False)
    # Cast Myr
    cast_artifact(loop_value_dictionary, 2, False, False)
    # Cast Trawler
    cast_artifact(loop_value_dictionary, 3, False, False)
    calc_nmp(loop_value_dictionary)
    perform_n_iterations(loop_value_dictionary, n)


# Loop 3: KCI, Scrap Trawler, Myr Retriever, Chromatic Star (in Play), Mox Opal
def loop_3(n, loop_value_dictionary):
    # Activate Star (to pay, do the following)
    activate_chromatic_star(loop_value_dictionary)
    # Tap Mox for Mana and Sacrifice
    tap_n_sac_mopal(loop_value_dictionary)
    # Sac Myr
    sac_retriever(loop_value_dictionary, 1)
    # Sac KCI
    sac_artifact(loop_value_dictionary, False, False, 1)
    # Cast Mox
    cast_artifact(loop_value_dictionary, 0, False, False)
    # Cast Myr
    cast_artifact(loop_value_dictionary, 2, False, False)
    # Cast KCI
    cast_artifact(loop_value_dictionary, 4, False, False)
    calc_nmp(loop_value_dictionary)
    perform_n_iterations(loop_value_dictionary, n)


# Loop 4: KCI, Scrap Trawler x 2, Myr Retriever (in GY), Mox Opal (in GY)
def loop_4(n, loop_value_dictionary):
    # Sac Trawler returning Myr, Mopal
    sac_artifact(loop_value_dictionary, False, False, 2)
    # Cast Mopal
    cast_artifact(loop_value_dictionary, 0, False, False)
    # Cast Myr Retriever
    cast_artifact(loop_value_dictionary, 2, False, False)
    # Tap Mopal + Sacrifice to KCI
    tap_n_sac_mopal(loop_value_dictionary)
    # Sacrifice Myr returning Trawler, Mopal
    sac_retriever(loop_value_dictionary, 1)
    # Cast Mopal
    cast_artifact(loop_value_dictionary, 0, False, False)
    # Tap Mopal + Sacrifice to KCI
    tap_n_sac_mopal(loop_value_dictionary)
    # Cast Trawler
    cast_artifact(loop_value_dictionary, 3, False, False)
    calc_nmp(loop_value_dictionary)
    perform_n_iterations(loop_value_dictionary, n)


# Loop 5: KCI, Scrap Trawler x 2, Spine of Ish Sah, Ichor Wellspring (in GY), Mox Opal x 2 (in GY)
def loop_5(n, loop_value_dictionary):
    # Sac Spine of Ish Sah
    sac_artifact(loop_value_dictionary, True, False, 2)
    # Cast Wellspring
    cast_artifact(loop_value_dictionary, 2, False, True)
    # Cast Mopal
    cast_artifact(loop_value_dictionary, 0, False, False)
    # Tap and Sac Mopal
    tap_n_sac_mopal(loop_value_dictionary)
    # Sac Wellspring returning Mox/Mox
    sac_artifact(loop_value_dictionary, False, True, 2)
    # Cast Mopal
    cast_artifact(loop_value_dictionary, 0, False, False)
    # Tap and Sac Mopal
    tap_n_sac_mopal(loop_value_dictionary)
    # Cast Mopal
    cast_artifact(loop_value_dictionary, 0, False, False)
    # Tap and Sac Mopal
    tap_n_sac_mopal(loop_value_dictionary)
    # Cast Spine
    cast_artifact(loop_value_dictionary, 7, True, False)
    calc_nmp(loop_value_dictionary)
    perform_n_iterations(loop_value_dictionary, n)


# Loop 6: KCI, Scrap Trawler, Myr Retriever, Chromatic Sphere (in Play), Chromatic Sphere (in Hand), Mox Opal
def loop_6(n, loop_value_dictionary):
    # Cast Sphere (paying for it with following sacrifices)
    cast_artifact(loop_value_dictionary, 1, False, False)
    # Tap Mox for Mana and Sacrifice
    tap_n_sac_mopal(loop_value_dictionary)
    # Sac Sphere
    sac_artifact(loop_value_dictionary, False, False, 1)
    # Sac Myr
    sac_retriever(loop_value_dictionary, 1)
    # Sac Trawler
    sac_artifact(loop_value_dictionary, False, False, 1)
    # Cast Mox
    cast_artifact(loop_value_dictionary, 0, False, False)
    # Cast Myr
    cast_artifact(loop_value_dictionary, 2, False, False)
    # Cast Trawler
    cast_artifact(loop_value_dictionary, 3, False, False)
    calc_nmp(loop_value_dictionary)
    perform_n_iterations(loop_value_dictionary, n)


# Loop 7: KCI, Scrap Trawler, Myr Retriever, Pyrite S-Bomb, Mox Opal
def loop_7(n, loop_value_dictionary):
    # Activate Spell Bomb (paying for it with following sacrifices)
    activate_sbomb(loop_value_dictionary)
    # Tap Mox for Mana and Sacrifice
    tap_n_sac_mopal(loop_value_dictionary)
    # Sac Myr
    sac_retriever(loop_value_dictionary, 1)
    # Sac Trawler
    sac_artifact(loop_value_dictionary, False, False, 1)
    # Cast Mox
    cast_artifact(loop_value_dictionary, 0, False, False)
    # Cast Myr
    cast_artifact(loop_value_dictionary, 2, False, False)
    # Cast Trawler
    cast_artifact(loop_value_dictionary, 3, False, False)
    # Cast Spell Bomb
    cast_artifact(loop_value_dictionary, 1, False, False)
    calc_nmp(loop_value_dictionary)
    perform_n_iterations(loop_value_dictionary, n)


def perform_kci_loop_s(s, i, loop_values):
    kci_loop_dict = {
        0: loop_0,
        1: loop_1,
        2: loop_2,
        3: loop_3,
        4: loop_4,
        5: loop_5,
        6: loop_6,
        7: loop_7

    }
    # Reset Dictionary Values
    reset_dict(loop_values)
    # Get the function from switch_dict dictionary with the help of get() method.
    kci_loop_dict.get(s)(i, loop_values)


def key_gen_function(d, cd_b, nmp_b, gat_b, tos_b, sos_b):
    largest128bitint = 340282366920938463463374607431768211455
    return (numpy.power(d['cd'], cd_b + 1)
            + numpy.power(d['nmp'], nmp_b)
            + numpy.power(d['gat'], gat_b + 1)
            + numpy.power(d['tos'], tos_b)
            + numpy.power(d['sos'], sos_b * 2) + numpy.power(d['mpil'] + d['msil'], nmp_b + 2)) % largest128bitint


def key_gen_wrapper(provided_key):
    start_state = get_3_most_significant_bits(provided_key)
    cd_bool = get_nth_bit_from_end(provided_key, 3)
    nmp_bool = get_nth_bit_from_end(provided_key, 4)
    gat_bool = get_nth_bit_from_end(provided_key, 5)
    tos_bool = get_nth_bit_from_end(provided_key, 6)
    sos_bool = get_nth_bit_from_end(provided_key, 7)
    iterations = get_bits_before_position_n(provided_key, 7)
    perform_kci_loop_s(binary_string_to_int(start_state), binary_string_to_int(iterations), kci_loop_values)
    result = key_gen_function(kci_loop_values, binary_string_to_int(cd_bool), binary_string_to_int(nmp_bool),
                              binary_string_to_int(gat_bool), binary_string_to_int(tos_bool),
                              binary_string_to_int(sos_bool))
    return result


def encrypt_block(block, key, block_size_bytes):
    assert len(block) == block_size_bytes
    assert len(key) == block_size_bytes

    return bytes([b ^ j for b, j in zip(block, key)])


def encrypt_ecb(message, key, block_size_bytes):
    assert len(message) % block_size_bytes == 0
    ciphertext = b""
    for i in range(0, len(message), block_size_bytes):
        block = message[i:i + block_size_bytes]
        ciphertext += encrypt_block(block, key, block_size_bytes)
    return ciphertext


def decrypt_block(ciphertext, key, block_size_bytes):
    assert len(ciphertext) == block_size_bytes
    assert len(key) == block_size_bytes

    return bytes([c ^ j for c, j in zip(ciphertext, key)])


def decrypt_ecb(ciphertext, key, block_size_bytes):
    assert len(ciphertext) % block_size_bytes == 0

    message = b""
    for i in range(0, len(ciphertext), block_size_bytes):
        block = ciphertext[i:i + block_size_bytes]
        message += decrypt_block(block, key, block_size_bytes)
    return message


def pkcs7_pad(plaintext, block_size_bytes):
    padding_size = block_size_bytes - (len(plaintext) % block_size_bytes)
    padding = bytes([padding_size] * padding_size)
    return plaintext + padding


def pkcs7_unpad(padded_plaintext):
    padding_size = padded_plaintext[-1]
    return padded_plaintext[:-padding_size]


def encrypt_ecb_with_padding(message, key, block_size_bits):
    block_size_bytes = block_size_bits // 8
    padded_message = pkcs7_pad(message, block_size_bytes)
    return encrypt_ecb(padded_message, key, block_size_bytes)


def decrypt_ecb_with_padding(ciphertext, key, block_size_bits):
    block_size_bytes = block_size_bits // 8
    padded_message = decrypt_ecb(ciphertext, key, block_size_bytes)
    return pkcs7_unpad(padded_message)


def print_kci_dictionary(k_d):
    print("--- KCI LOOP VARIABLES ---")
    print("Cards Drawn: ", k_d['cd'])
    print("TOTAL Mana Produced: ", k_d['mpil'])
    print("TOTAL Mana Spent: ", k_d['msil'])
    print("Net Mana: +", k_d['nmp'])
    print("Game Actions Taken: ", k_d['gat'])
    print("Total Triggers put on Stack: ", k_d['tos'])
    print("Total Spells Cast: ", k_d['sos'])


kci_loop_values = {
    'cd': 0,
    'mpil': 0,
    'msil': 0,
    'gat': 0,
    'tos': 0,
    'sos': 0,
    'nmp': 0
}

root = tk.Tk()
root.title("The Snider-KCI Cipher")
root.geometry("800x750")
root.configure(bg='white')

# Font configurations
header_font = font.Font(family='Arial', size=16, weight='bold')
entry_font = font.Font(family='Arial', size=14)

# Main Frame
main_frame = ttk.Frame(root, padding="10")
main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Title Label
title_label = ttk.Label(main_frame, text="The Snider-KCI Cipher", font=header_font)
title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20), sticky=tk.W)

# Key Entry
key_label = ttk.Label(main_frame, text="Key (k):", font=entry_font)
key_label.grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
key_entry = ttk.Entry(main_frame, font=entry_font)
key_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W+tk.E)

# Message Entry
message_label = ttk.Label(main_frame, text="Plaintext (p):", font=entry_font)
message_label.grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
message_entry = ttk.Entry(main_frame, font=entry_font)
message_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W+tk.E)

# Radio buttons
# Frame
radio_frame_1 = tk.Frame(main_frame, bd=2, relief="groove")
radio_frame_1.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

# Init rd_button_1
rd_button_1 = tk.StringVar(value="64")

# Pick Label
pick_label_1 = ttk.Label(main_frame, text="Hash Size (h):", font=entry_font)
pick_label_1.grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)

# Radio Buttons 3 side-by-side
radio1 = tk.Radiobutton(radio_frame_1, text="64 bit", variable=rd_button_1, value="64")
radio1.grid(row=0, column=0, pady=10, padx=10)
radio2 = tk.Radiobutton(radio_frame_1, text="128 bit", variable=rd_button_1, value="128")
radio2.grid(row=0, column=1, pady=10, padx=10)
radio3 = tk.Radiobutton(radio_frame_1, text="256 bit", variable=rd_button_1, value="256")
radio3.grid(row=0, column=2, pady=10, padx=10)

# Submit Button
submit_button = ttk.Button(radio_frame_1, text="Encrypt", command=on_encrypt)
submit_button.grid(row=0, column=3, pady=10, padx=10, columnspan=1)

# Key Entry
key_label_1 = ttk.Label(main_frame, text="Key (k):", font=entry_font)
key_label_1.grid(row=5, column=0, sticky=tk.W, padx=5, pady=5)
key_entry_1 = ttk.Entry(main_frame, font=entry_font)
key_entry_1.grid(row=5, column=1, padx=5, pady=5, sticky=tk.W+tk.E)

# Message Entry
message_label_1 = ttk.Label(main_frame, text="Ciphertext (c):", font=entry_font)
message_label_1.grid(row=6, column=0, sticky=tk.W, padx=5, pady=5)
message_entry_1 = ttk.Entry(main_frame, font=entry_font)
message_entry_1.grid(row=6, column=1, padx=5, pady=5, sticky=tk.W+tk.E)

# init rd_button_2
rd_button_2 = tk.StringVar(value="64")

# init radio_frame_2
radio_frame_2 = tk.Frame(main_frame, bd=2, relief="groove")
radio_frame_2.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

# Radio buttons
pick_label_1 = ttk.Label(main_frame, text="Hash Size (h):", font=entry_font)
pick_label_1.grid(row=7, column=0, sticky=tk.W, padx=5, pady=5)

# Radio Buttons 3 side-by-side
radio4 = tk.Radiobutton(radio_frame_2, text="64 bit", variable=rd_button_2, value="64", state=tk.DISABLED)
radio4.grid(row=0, column=0, pady=10, padx=10)
radio5 = tk.Radiobutton(radio_frame_2, text="128 bit", variable=rd_button_2, value="128", state=tk.DISABLED)
radio5.grid(row=0, column=1, pady=10, padx=10)
radio6 = tk.Radiobutton(radio_frame_2, text="256 bit", variable=rd_button_2, value="256", state=tk.DISABLED)
radio6.grid(row=0, column=2, pady=10, padx=10)

# Submit Button
submit_button_1 = ttk.Button(radio_frame_2, text="Decrypt", command=on_decrypt, state=tk.DISABLED)
submit_button_1.grid(row=0, column=4, pady=10, padx=10, columnspan=1)


# Display Text widget for output with a horizontal scrollbar
display_label = ttk.Label(main_frame, text="Output:", font=entry_font)
display_label.grid(row=9, column=0, sticky=tk.W, padx=5, pady=5)
display_text = tk.Text(main_frame, height=14, width=40, font=entry_font, wrap=tk.NONE)  # set wrap to NONE
display_text.grid(row=10, column=0, columnspan=2, padx=5, sticky=tk.W+tk.E)

# Horizontal Scrollbar for the display_text
x_scroll = ttk.Scrollbar(main_frame, orient="horizontal", command=display_text.xview)
x_scroll.grid(row=11, column=0, columnspan=2, sticky=tk.W+tk.E)
display_text.configure(xscrollcommand=x_scroll.set)

# Horizontal Scrollbar for the display_text
y_scroll = ttk.Scrollbar(main_frame, orient="vertical", command=display_text.yview)
y_scroll.grid(row=10, column=4, rowspan=10, sticky=tk.W+tk.E)
display_text.configure(yscrollcommand=y_scroll.set)

# Make the Entry fields expand with the window resizing
main_frame.columnconfigure(1, weight=1)

root.mainloop()
