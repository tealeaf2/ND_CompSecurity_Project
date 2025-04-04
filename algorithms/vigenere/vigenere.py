def encode_vigenere(key, text):
  key = key.upper()
  result = []
  key_index = 0
  for char in text:
    if char.isalpha():
      shift = ord(key[key_index]) - ord('A')
      if char.isupper():
        result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
      else:
        result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
      key_index = (key_index + 1) % len(key)
    else:
      result.append(char)
  return ''.join(result)

def decode_vigenere(key, text):
  key = key.upper()
  result = []
  key_index = 0
  for char in text:
    if char.isalpha():
      shift = ord(key[key_index]) - ord('A')
      if char.isupper():
        result.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
      else:
        result.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
      key_index = (key_index + 1) % len(key)
    else:
      result.append(char)
  return ''.join(result)


# For testing the functions
if __name__ == "__main__":
  key = input("Enter the key: ")
  text = input("Enter the text: ")
  action = input("Do you want to encode or decode? (e/d): ")
  if action.lower() == 'e':
    print("Encoded text:", encode_vigenere(key, text))
  elif action.lower() == 'd':
    print("Decoded text:", decode_vigenere(key, text))
  else:
    print("Invalid action. Please enter 'e' for encode or 'd' for decode.")