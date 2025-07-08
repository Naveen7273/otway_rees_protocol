#include <iostream>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <utility>
using namespace CryptoPP;
using namespace std;

/*
// Function to send the combined message to the specified socket
void sendCombinedMessage(Socket& socket, const SecByteBlock& encryptedTicket, const SecByteBlock& normalMessage) {
    // Combine the encrypted ticket and the normal message into one message
    size_t combinedMessageSize = encryptedTicket.size() + normalMessage.size();
    SecByteBlock combinedMessage(combinedMessageSize);
    memcpy(combinedMessage.data(), encryptedTicket.data(), encryptedTicket.size());
    memcpy(combinedMessage.data() + encryptedTicket.size(), normalMessage.data(), normalMessage.size());

    // Send the combined message to the socket
    sendMessage(socket, combinedMessage);
}
*/
SecByteBlock aliceGenerateNonce() {
    AutoSeededRandomPool rnd;
    SecByteBlock nonce(4);
    rnd.GenerateBlock(nonce, nonce.size());
    
    /*cout << "Generated Nonce: ";
    for (size_t i = 0; i < nonce.size(); ++i) {
        cout << static_cast<int>(nonce[i])<<" ";
    }
    cout << endl;*/
    
    return nonce;
}

SecByteBlock aliceEncryptWithSessionKey(const SecByteBlock& data, const SecByteBlock& key) {
    if (key.size() != AES::DEFAULT_KEYLENGTH) {
        cerr << "Error: Invalid key size." << endl;
        exit(EXIT_FAILURE);
    }

    if (data.empty()) {
        cerr << "Error: Empty data to encrypt." << endl;
        exit(EXIT_FAILURE);
    }

    SecByteBlock encryptedData(data.size());  // Output buffer

    try {
        CBC_Mode<AES>::Encryption encryption(key, key.size(), (CryptoPP::byte*)"");
        encryption.ProcessData(encryptedData, data, data.size());
    } catch (const Exception& e) {
        cerr << "Error during encryption: " << e.what() << endl;
        exit(EXIT_FAILURE);
    }

    // Print encrypted data
    /*cout << "Encrypted Data: ";
    for (size_t i = 0; i < encryptedData.size(); ++i) {
        cout << static_cast<int>(encryptedData[i]);
    }
    cout << endl;*/

    return encryptedData;
}

SecByteBlock aliceDecryptWithSessionKey(const SecByteBlock& data, const SecByteBlock& key) {
    SecByteBlock decryptedData(data.size()); // Resize decryptedData to match data
    CBC_Mode<AES>::Decryption decryption(key, key.size(), (CryptoPP::byte*)"");
    decryption.ProcessData(decryptedData, data, data.size());
    //cout<<"dept data"<<endl;
    return decryptedData;
}


void sendMessage(int socket, const SecByteBlock& message) {
    size_t totalBytes = message.SizeInBytes();
    size_t sentBytes = 0;
    
    while (sentBytes < totalBytes) {
        ssize_t currentBytes = send(socket, message.BytePtr() + sentBytes, totalBytes - sentBytes, 0);
        if (currentBytes == -1) {
            perror("send");
            cerr << "Error sending message. Sent bytes: " << sentBytes << ", Total bytes: " << totalBytes << endl;
            exit(EXIT_FAILURE);
        } else if (currentBytes == 0) {
            cerr << "Connection closed by the remote side." << endl;
            exit(EXIT_FAILURE);
        }
		
        sentBytes += static_cast<size_t>(currentBytes);
        //cout << "sentBytes " << hex << sentBytes << endl;
    }
}

SecByteBlock receiveMessage(int socket, size_t expectedSize) {
    SecByteBlock buffer(expectedSize);
    ssize_t bytesRead = recv(socket, buffer.BytePtr(), buffer.SizeInBytes(), 0);
    if (bytesRead == -1) {
        perror("recv");
        exit(EXIT_FAILURE);
    }

    // Resize the buffer to the actual number of bytes received
    buffer.resize(static_cast<size_t>(bytesRead));

    // Print the received buffer
    /*cout << "Received Buffer: ";
    for (size_t i = 0; i < buffer.size(); ++i) {
        cout << static_cast<int>(buffer[i]);
    }
    cout << endl;*/

    return buffer;
}

/*
// Function to send the combined message to the specified socket
void sendCombinedMessage(Socket& socket, const SecByteBlock& encryptedTicket, const SecByteBlock& normalMessage) {
    // Combine the encrypted ticket and the normal message into one message
    size_t combinedMessageSize = encryptedTicket.size() + normalMessage.size();
    SecByteBlock combinedMessage(combinedMessageSize);
    memcpy(combinedMessage.data(), encryptedTicket.data(), encryptedTicket.size());
    memcpy(combinedMessage.data() + encryptedTicket.size(), normalMessage.data(), normalMessage.size());

    // Send the combined message to the socket
    sendMessage(socket, combinedMessage);
}
*/
// Function to send the combined message to the specified socket
void sendCombinedMessage(int socket, const SecByteBlock& encryptedTicket, const SecByteBlock& normalMessage) {
    // Combine the encrypted ticket and the normal message into one message
    size_t combinedMessageSize = encryptedTicket.size() + normalMessage.size();
    SecByteBlock combinedMessage(combinedMessageSize);
    memcpy(combinedMessage.data(), encryptedTicket.data(), encryptedTicket.size());
    memcpy(combinedMessage.data() + encryptedTicket.size(), normalMessage.data(), normalMessage.size());

    // Send the combined message to the socket
    sendMessage(socket, combinedMessage);
}


int main() {
    int aliceSocket, kdcSocket, bobSocket;
    int port = 12345;
    string kdcIP = "172.29.1.66"; // Replace with KDC IP address
    string bobIP = "172.16.15.7"; // Replace with Bob's IP address
    int bobPort = 12345;        // Replace with the port Bob is listening on
    sockaddr_in kdcAddr, bobAddr;

    aliceSocket = socket(AF_INET, SOCK_STREAM, 0);
    kdcSocket = socket(AF_INET, SOCK_STREAM, 0);
    bobSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (aliceSocket == -1 || kdcSocket == -1 || bobSocket == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Connect to KDC
    kdcAddr.sin_family = AF_INET;
    kdcAddr.sin_addr.s_addr = inet_addr(kdcIP.c_str());
    kdcAddr.sin_port = htons(port);

    if (connect(kdcSocket, (struct sockaddr*)&kdcAddr, sizeof(kdcAddr)) == -1) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    cout << "Connected to KDC.\n";

    // Alice logic for communication with KDC goes here
    SecByteBlock sessionKey = receiveMessage(kdcSocket, 16);
    
    // Print the session key received from KDC
    cout << "Alice-KDC Session Key received from KDC(Received from IP addr=172.29.1.66 && port no = 12345 ): ";
    for (size_t i = 0; i < sessionKey.size(); ++i) {
        cout << static_cast<int>(sessionKey[i])<<" ";
    }
    cout << endl;

    // Connect to Bob
    bobAddr.sin_family = AF_INET;
    bobAddr.sin_addr.s_addr = inet_addr(bobIP.c_str());
    bobAddr.sin_port = htons(bobPort);

    if (connect(bobSocket, (struct sockaddr*)&bobAddr, sizeof(bobAddr)) == -1) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    cout << "Connected to Bob.\n";

    // Generate Alice's nonce
    SecByteBlock aliceNonce = aliceGenerateNonce();
    
    cout << "Alice Nonce: ";
    for (size_t i = 0; i < aliceNonce.size(); ++i) {
        cout << static_cast<int>(aliceNonce[i])<<" ";
    }
    cout << endl;

    string aliceIdentity = "alice"; 
    string bobIdentity ="bob";
    
    SecByteBlock commonNonceR = aliceGenerateNonce();

    cout << "Common Nonce R: ";
    for (size_t i = 0; i < commonNonceR.size(); ++i) {
        cout << static_cast<int>(commonNonceR[i])<<" ";
    }
    cout << endl;

    // Construct the message: Alice Identity + Bob Identity + Common Nonce R 
    SecByteBlock message;
    message += SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(aliceIdentity.data()), aliceIdentity.size());
    message += SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(bobIdentity.data()), bobIdentity.size());
    message += commonNonceR;
 

    /*cout << "Message to be sent to Bob: ";
    for (size_t i = 0; i < message.size(); ++i) {
        cout << static_cast<int>(message[i]);
    }
    cout << endl;*/

    // Construct the ticket: Alice Identity + Bob Identity + Common Nonce + Alice Nonce
    SecByteBlock ticket;
    ticket += SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(aliceIdentity.data()), aliceIdentity.size());
    ticket += SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(bobIdentity.data()), bobIdentity.size());
    ticket += commonNonceR;
    ticket += aliceNonce; // Append Alice's nonce
    
    /*cout << "Ticket to be sent to Bob: ";
    for (size_t i = 0; i < ticket.size(); ++i) {
        cout << static_cast<int>(ticket[i]);
    }
    cout << endl;*/

    //cout << "hello" << "\n";

    // Encrypt the ticket using Alice-KDC session key
    SecByteBlock encryptedTicket = aliceEncryptWithSessionKey(ticket, sessionKey);
    //cout << "hello encrypted" << "\n";

    // Send the encrypted ticket to Bob
    //sendMessage(bobSocket, encryptedTicket);
    //cout << "sent ticket to Bob" << "\n";
    sendCombinedMessage(bobSocket,encryptedTicket,message);
    // Send the message to Bob
    //sendMessage(bobSocket, message);
    cout << "sent  message to Bob" << "\n";
    
     // Print the ticket sent to Bob
    cout << "Ticket sent to Bob: ";
    for (size_t i = 0; i < encryptedTicket.size(); ++i) {
        cout << static_cast<int>(encryptedTicket[i])<<" ";
    }
    cout << endl;
    
     // Print the normal message sent to Bob
    cout << "Normal message sent to Bob: ";
    for (size_t i = 0; i < message.size(); ++i) {
        cout << static_cast<int>(message[i])<<" ";
    }
    cout << endl;
    
    // Receive the encrypted message from Bob
    SecByteBlock encryptedMessage = receiveMessage(bobSocket, 32); // Assuming 32 bytes for the encrypted message
    
    // Print the received encrypted message from Bob
    cout << "Encrypted Message received from Bob: ";
    for (size_t i = 0; i < encryptedMessage.size(); ++i) {
        cout << static_cast<int>(encryptedMessage[i])<<" ";
    }
    cout << endl;

    // Decrypt the message with Alice-KDC session key
    SecByteBlock decryptedMessage = aliceDecryptWithSessionKey(encryptedMessage, sessionKey);

    // Extract nonce and Alice-Bob session key from the decrypted message
    SecByteBlock aliceNonceReceived(decryptedMessage.BytePtr(), 4);
    SecByteBlock aliceBobSessionKey(decryptedMessage.BytePtr() + 4, 16);
    
    
	std::cout << "Alice-Bob Session Key(received from IP addr=172.16.15.7 && port no = 12345  ): ";
	for (size_t i = 0; i < aliceBobSessionKey.size(); ++i) {
 	   std::cout << static_cast<int>(aliceBobSessionKey[i])<<" ";
	}
	std::cout << std::endl;

	std::cout << "Alice Nonce Received(received from IP addr=172.16.15.7 && port no = 12345 ): ";
	for (size_t i = 0; i < aliceNonceReceived.size(); ++i) {
 	   std::cout << static_cast<int>(aliceNonceReceived[i])<<" ";
	}
	std::cout << std::endl;

    // Send a random message encrypted with Alice-Bob session key to Bob
    SecByteBlock randomMessage = aliceGenerateNonce(); // You can replace this with your own message
    SecByteBlock encryptedRandomMessage = aliceEncryptWithSessionKey(randomMessage, aliceBobSessionKey);
    sendMessage(bobSocket, encryptedRandomMessage);
    
    cout << "Encrypted Message sent to Bob: ";
    for (size_t i = 0; i < encryptedRandomMessage.size(); ++i) {
        cout << static_cast<int>(encryptedRandomMessage[i])<<" ";
    }
    cout << endl;
    
    close(bobSocket);
    close(aliceSocket);
    close(kdcSocket);

    return 0;
}

