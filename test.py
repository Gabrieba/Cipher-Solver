import string

def rotate_alphabet(alphabet, shift_amount):
    return alphabet[-shift_amount:] + alphabet[:-shift_amount]

PRINTABLE_ASCII = string.printable.replace('\t\n\r\x0b\x0c', '')


def core_encrypt(filtered_message, keyed_alphabets, iv):

    result = []
    cycle_length = len(keyed_alphabets)
    current_index = 0
    current_iv = iv

    # Process message in digraphs (pairs of characters)
    for i in range(0, len(filtered_message), 2):
        digraph = filtered_message[i:i+2]
        next_index = (current_index + 1) % cycle_length

        # Calculate positions for first round of substitution
        first_pos = ((keyed_alphabets[current_index].index(current_iv[0]) + 1) +
                    (keyed_alphabets[current_index].index(digraph[0]) + 1) - 1) % 95
        second_pos = ((keyed_alphabets[current_index].index(current_iv[1]) + 1) +
                     (keyed_alphabets[current_index].index(digraph[1]) + 1) - 1) % 95
        intermediate_block = (keyed_alphabets[current_index][first_pos] +
                            keyed_alphabets[current_index][second_pos])
        print("IV = "+current_iv)
        print("IB = "+intermediate_block)
        print("key1 = "+keyed_alphabets[0])
        print("key2 = "+keyed_alphabets[1])
        print("current_iv0 = "+current_iv[0])
        print("digraph0 = "+digraph[0])
        print("first_pos = "+str(first_pos))
        print(str(keyed_alphabets[current_index].index(current_iv[0]) + 1)+" "+str(keyed_alphabets[current_index].index(digraph[0])))

        # Calculate distances and perform second round of substitution
        if intermediate_block[0] == intermediate_block[1]:
            first_letter_distance = 95
        else:
            first_letter_distance = (keyed_alphabets[current_index].index(intermediate_block[1]) -
                                   keyed_alphabets[current_index].index(intermediate_block[0])) % 95

        first_letter = keyed_alphabets[next_index][(first_letter_distance + 94) % 95]

        second_letter_distance = (keyed_alphabets[next_index].index(intermediate_block[0]) -
                                keyed_alphabets[next_index].index(first_letter)) % 95
        second_letter = keyed_alphabets[current_index][(second_letter_distance + 94) % 95]

        ciphertext_digraph = first_letter + second_letter
        result.append(ciphertext_digraph)

        # Update alphabet state based on intermediate results
        if intermediate_block[0] != intermediate_block[1]:
            first_key = keyed_alphabets[current_index]
            first_key_list = list(first_key)
            pos1, pos2 = first_key.index(intermediate_block[0]), first_key.index(intermediate_block[1])
            first_key_list[pos1], first_key_list[pos2] = first_key_list[pos2], first_key_list[pos1]
            keyed_alphabets[current_index] = ''.join(first_key_list)

        if first_letter != second_letter:
            second_key = keyed_alphabets[next_index]
            second_key_list = list(second_key)
            pos1, pos2 = second_key.index(first_letter), second_key.index(second_letter)
            second_key_list[pos1], second_key_list[pos2] = second_key_list[pos2], second_key_list[pos1]
            keyed_alphabets[next_index] = ''.join(second_key_list)

        # Update state for next iteration
        shift_for_cycle = first_letter_distance % cycle_length
        shift_for_order = second_letter_distance

        current_index = (current_index + shift_for_cycle) % cycle_length
        keyed_alphabets = [rotate_alphabet(alphabet, shift_for_order) for alphabet in keyed_alphabets]

        current_iv = ciphertext_digraph

    return ''.join(result), keyed_alphabets



filtered_message = "Our princess is in another castle!"
iv = "JP"
f1 = open('key1.txt','r')
key1 = ''.join(filter(lambda x: x in PRINTABLE_ASCII, f1.read()))
f1.close()
f2 = open('key2.txt','r')
key2 = ''.join(filter(lambda x: x in PRINTABLE_ASCII, f2.read()))
f2.close()
keyed_alphabets = [key1,key2]
encrypted_message, final_keyed_alphabets = core_encrypt(
        filtered_message, keyed_alphabets, iv)
print(encrypted_message)
