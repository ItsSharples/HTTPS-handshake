import secrets
import socket
from struct import unpack               # Import socket module

s = socket.socket()         # Create a socket object
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

host = "0.0.0.0"#socket.gethostname() # Get local machine name
port = 443                # Reserve a port for your service.
s.bind((host, port))        # Bind to the port


def printHex(byteArray: bytes):
   print(byteArray.hex())

current_iter = 0
def resetGetValuesCount():
   global current_iter
   current_iter = 0

def getValuesFrom(byteArray, count: int):
   global current_iter
   current_iter += count
   # print(f"Got Values up to {current_iter}")
   return byteArray[current_iter - count: current_iter]

def handleClientHello(client_hello):
   global current_iter
   # assert message_type == b"\x01", "I don't think it's Client Hello"
   message_length = int.from_bytes(getValuesFrom(client_hello, 3))
   assert message_length == total_size - 4, "Funky Size Check"
   tlsType = getValuesFrom(client_hello, 2)
   print(tlsType.hex())

   randomData = getValuesFrom(client_hello, 32)
   print(f"Random Data: {randomData.hex()}")

   session_ID_len = getValuesFrom(client_hello, 1)
   session_ID = getValuesFrom(client_hello, int.from_bytes(session_ID_len))
   print(f"Session ID Block Size: {session_ID_len.hex()}")

   cipher_count_bytes = getValuesFrom(client_hello, 2)
   cipher_count = int.from_bytes(cipher_count_bytes)
   print(f"Cipher Block Size: {cipher_count}")
   ciphers = getValuesFrom(client_hello, cipher_count)
   print(ciphers.hex())
   # for cipher in range(1, cipher_count):
   #    cipher_name_bytes = getValuesFrom(client_hello, 2)
   #    printHex(cipher_name_bytes)

   compression_count_bytes = getValuesFrom(client_hello, 1)
   compression_count = int.from_bytes(compression_count_bytes)
   print(f"Compression Block Size: {compression_count}")
   compressions = getValuesFrom(client_hello, compression_count)
   print(compressions.hex())
   #print(current_iter)
   # for cipher in range(compression_count):
   #    compression_name_bytes = getValuesFrom(client_hello, 1)
   #    print(int.from_bytes(compression_name_bytes))
   #print(current_iter)

   # Extensions Block Size in bytes
   extensions_block_size_bytes = getValuesFrom(client_hello, 2)
   extensions_block_size = int.from_bytes(extensions_block_size_bytes)
   print(f"There are {extensions_block_size} bytes ({extensions_block_size_bytes.hex()}) of extensions")
   
   old_iter = current_iter
   extensions_block = getValuesFrom(client_hello, extensions_block_size)
   print(extensions_block.hex())
   current_iter = old_iter

   while True:
      # For each Extension we need the first 
      # 2 + 2 bytes to get the type, and length
      extension_type_bytes = getValuesFrom(client_hello, 2)
      extension_type = int.from_bytes(extension_type_bytes)

      extension_len_bytes = getValuesFrom(client_hello, 2)
      extension_len = int.from_bytes(extension_len_bytes)

      extension_data = getValuesFrom(client_hello, extension_len)

      if extension_type == 21:
         print(f"Padding (Expecting end of chunk), Size: {extension_len} ({extension_len_bytes.hex()})")
         break

      print(f"Extension Type: {extension_type} ({extension_type_bytes.hex()}), Extension Block Size: {extension_len} ({extension_len_bytes.hex()})")
      print(extension_data.hex())

   # This isn't the best, but because the extensions include
   # Padding, it will always be the final block of data
      if current_iter == total_size:
         break
      if current_iter > total_size:
         print("Went too far")
         break
   
   print(f"{current_iter} == {total_size}")



print(f"opened connection at {host}:{port}")
s.listen(5)                 # Now wait for client connection.
while True:
   c, addr = s.accept()     # Establish connection with client.
   print(f"connected to {addr}")
   connection_open = True
   session_ID = bytes.fromhex(secrets.token_hex(32))
   random = bytes.fromhex(secrets.token_hex(32))
   while connection_open:
      recieved = c.recv(512)
      print("New Message")
      print(recieved.hex())
      if(recieved.__len__() < 5):
         print(f"Tiny Message: {recieved.hex()}")
         break
      blocks = recieved[:5]
      header = unpack("!bhh", blocks)
      print(header)
      total_size = header[2]
      client_hello = recieved[5:5+total_size]
      resetGetValuesCount();
      message_type = getValuesFrom(client_hello, 1)
      print(message_type)
      if message_type == b"\x01":
         handleClientHello(client_hello)

         exampleHello = bytes.fromhex("0200004d0303c8ca5c5f8379eb8f8a1686c207d742c7eeb9dc71b7f1719feb516624b41e4f6c20e40280101dea7faaee5d4fac53492925ec29a8b723faef24d4472e907b99362b0033000005ff01000100")
         c.send(exampleHello)
      else:
         print("Unhandled Type")


      


   c.close()                # Close the connection


