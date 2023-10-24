#crack script for re01

cereal = ['4d', '79', '7c', '70', '7b', '80', '47', '52', '59', '5c', '4c', '4e', '4c', '59']

print(''.join([chr(int(val, 16) - 7) for val in cereal]))