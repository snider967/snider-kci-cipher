# In this iteration we will assume a fixed length 64-bit integer for a key.
# I am also attempting my own form of stream cipher, by intentionally creating a key >= length of the list.
# Once I have created the key I plan to split it to be the exact


def key_gen_loop_wrapper(key_in, msg_bit_len):
    k = int_to_padded_binary_string(key_in)
    k_gen = key_gen_wrapper(k)
    k_arr = [k_gen]
    count = 0

    # Loop to extend the key to the requisite length
    while len(k_gen) < msg_bit_len:
        k_arr.append(key_gen_wrapper(k_arr[count]))
        k_gen = k_arr[count + 1] + k_gen
        count += 1

    return k_gen


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


def key_gen_function(d, cd_b, nmp_b, gat_b, tos_b, sos_b):
    return int_to_padded_binary_string(
        (d['cd'] * cd_b + d['nmp'] * nmp_b + d['gat'] * gat_b + d['tos'] * tos_b + d['sos'] * sos_b
         + d['mpil'] * d['msil']) % 18446744073709551615)


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


# Re-zero the dictionary
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
