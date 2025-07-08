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

SecByteBlock kdcGenerateNonce() {
    AutoSeededRandomPool rnd;
    SecByteBlock nonce(4);
    rnd.GenerateBlock(nonce, nonce.size());
    return nonce;
}

SecByteBlock kdcGenerateSessionKey() {
    AutoSeededRandomPool rnd;
    SecByteBlock sessionKey(16);
    rnd.GenerateBlock(sessionKey, sessionKey.size());
    return sessionKey;
}

SecByteBlock kdcEncryptWithSessionKey(const SecByteBlock& data, const SecByteBlock& key) {
    if (key.size() != AES::DEFAULT_KEYLENGTH) {
        cerr << "Error: Invalid key size." << endl;
        exit(EXIT_FAILURE);
    }

    if (data.empty()) {
        cerr << "Error: Empty data to encrypt." << endl;
        exit(EXIT_FAILURE);
    }
    //cout << "Data size to encrypt" << data.size()<< endl;
    SecByteBlock encryptedData(data.size());  // Output buffer
     //cout << "Data size after resize" << encryptedData.size() << endl;

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
        cout << static_cast<int>(encryptedData[i])<< " ";
    }
    cout << endl;*/
  
    return encryptedData;
}

SecByteBlock kdcDecryptWithSessionKey(const SecByteBlock& data, const SecByteBlock& key) {
  //cout << "Data size to decrypt" << data.size()<< endl;
    SecByteBlock decryptedData(data.size()); // Resize decryptedData to match data
    //cout << "Data size after resize" << decryptedData.size() << endl;
    CBC_Mode<AES>::Decryption decryption(key, key.size(), (CryptoPP::byte*)"");
    decryption.ProcessData(decryptedData, data, data.size());
    // Print encrypted data
    /*cout << "Decrypted Data: ";
    for (size_t i = 0; i < decryptedData.size(); ++i) {
        cout << static_cast<int>(decryptedData[i])<< " ";
    }
    cout << endl;
    cout<<"dept data"<<endl;*/
    return decryptedData;
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
        cout << static_cast<int>(buffer[i])<< " ";
    }
    cout << endl;*/

    return buffer;
}
void sendMessage(int socket, const SecByteBlock& message) {
    /*cout << "Sending Message: ";
    for (size_t i = 0; i < message.size(); ++i) {
        cout << static_cast<int>(message[i])<< " ";
    }
    cout << endl;*/

    size_t totalBytes = message.SizeInBytes();
    size_t sentBytes = 0;

    while (sentBytes < totalBytes) {
        ssize_t currentBytes = send(socket, message.BytePtr() + sentBytes, totalBytes - sentBytes, 0);
        //cout << "Sent " << currentBytes << " bytes." << endl;

        if (currentBytes == -1) {
            perror("send");
            cerr << "Error sending message. Sent bytes: " << sentBytes << ", Total bytes: " << totalBytes << endl;
            exit(EXIT_FAILURE);
        } else if (currentBytes == 0) {
            cerr << "Connection closed by the remote side." << endl;
            exit(EXIT_FAILURE);
        }

        sentBytes += static_cast<size_t>(currentBytes);
    }
    cout << "Message sent successfully." << endl;
}

std::pair<SecByteBlock, SecByteBlock> receiveCombinedMessage(int socket, size_t encryptedTicketSize, size_t normalMessageSize) {
    SecByteBlock combinedMessage = receiveMessage(socket, encryptedTicketSize + normalMessageSize);

    SecByteBlock encryptedTicket(encryptedTicketSize);
    SecByteBlock normalMessage(normalMessageSize);

    memcpy(encryptedTicket.data(), combinedMessage.data(), encryptedTicketSize);
    memcpy(normalMessage.data(), combinedMessage.data() + encryptedTicketSize, normalMessageSize);

    return std::make_pair(encryptedTicket, normalMessage);
}

std::tuple<SecByteBlock, SecByteBlock, SecByteBlock> receiveCombinedMessage(int socket, size_t encryptedTicketSize, size_t normalMessageSize, size_t additionalMessageSize) {
    SecByteBlock combinedMessage = receiveMessage(socket, encryptedTicketSize + normalMessageSize + additionalMessageSize);

    SecByteBlock encryptedTicket(encryptedTicketSize);
    SecByteBlock normalMessage(normalMessageSize);
    SecByteBlock additionalMessage(additionalMessageSize);

    memcpy(encryptedTicket.data(), combinedMessage.data(), encryptedTicketSize);
    memcpy(normalMessage.data(), combinedMessage.data() + encryptedTicketSize, normalMessageSize);
    memcpy(additionalMessage.data(), combinedMessage.data() + encryptedTicketSize + normalMessageSize, additionalMessageSize);

    return std::make_tuple(encryptedTicket, normalMessage, additionalMessage);
}

void sendCombinedMessage(int socket, const SecByteBlock& encryptedTicket, const SecByteBlock& normalMessage, const SecByteBlock& additionalMessage) {
    // Combine the encrypted ticket, normal message, and additional message into one message
    size_t combinedMessageSize = encryptedTicket.size() + normalMessage.size() + additionalMessage.size();
    SecByteBlock combinedMessage(combinedMessageSize);
    memcpy(combinedMessage.data(), encryptedTicket.data(), encryptedTicket.size());
    memcpy(combinedMessage.data() + encryptedTicket.size(), normalMessage.data(), normalMessage.size());
    memcpy(combinedMessage.data() + encryptedTicket.size() + normalMessage.size(), additionalMessage.data(), additionalMessage.size());

    // Send the combined message to the socket
    sendMessage(socket, combinedMessage);
}


int main() {
    int kdcSocket, bobSocket;
    int port = 12345;
    sockaddr_in kdcAddr, bobAddr;

    kdcSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (kdcSocket == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Generate Alice-KDC secret key
    SecByteBlock aliceKDCSessionKey(AES::DEFAULT_KEYLENGTH);
    AutoSeededRandomPool aliceRng;
    aliceRng.GenerateBlock(aliceKDCSessionKey, aliceKDCSessionKey.size());

    // Generate Bob-KDC secret key
    SecByteBlock bobKDCSessionKey(AES::DEFAULT_KEYLENGTH);
    AutoSeededRandomPool bobRng;
    bobRng.GenerateBlock(bobKDCSessionKey, bobKDCSessionKey.size());

    kdcAddr.sin_family = AF_INET;
    kdcAddr.sin_addr.s_addr = INADDR_ANY;
    kdcAddr.sin_port = htons(port);

    bind(kdcSocket, (struct sockaddr*)&kdcAddr, sizeof(kdcAddr));
    listen(kdcSocket, 2); // Listen for Bob and Alice

    cout << "KDC listening on port " << port << "...\n";
    
     // Wait for Bob to connect
    socklen_t lenBob = sizeof(bobAddr);
    bobSocket = accept(kdcSocket, (struct sockaddr*)&bobAddr, &lenBob);
    cout << "Bob connected.\n";

    // Send Bob-KDC secret key to Bob
    sendMessage(bobSocket, bobKDCSessionKey);
    
    // Wait for Alice to connect
    sockaddr_in aliceAddr;
    socklen_t lenAlice = sizeof(aliceAddr);
    int aliceSocket = accept(kdcSocket, (struct sockaddr*)&aliceAddr, &lenAlice);
    cout << "Alice connected.\n";

    // Send Alice-KDC secret key to Alice
    sendMessage(aliceSocket, aliceKDCSessionKey);
    
    cout << "Alice-Kdc session key: ";
    for (size_t i = 0; i < aliceKDCSessionKey.size(); ++i) {
        cout << static_cast<int>(aliceKDCSessionKey[i])<< " ";
    }
    cout << endl;
    
    cout << "Bob-Kdc session key: ";
    for (size_t i = 0; i < bobKDCSessionKey.size(); ++i) {
        cout << static_cast<int>(bobKDCSessionKey[i])<< " ";
    }
    cout << endl;

    close(aliceSocket);

    // Receive encrypted messages from Bob
    ////------------------------
    
    //SecByteBlock encryptedMessage1Alice = receiveMessage(bobSocket, 16); // Assuming 32 bytes for the encrypted message
    //SecByteBlock encryptedMessage2Bob = receiveMessage(bobSocket, 16); // Assuming 32 bytes for the encrypted message
    

    //SecByteBlock encryptedMessageAlice, normalMessageAlice;
    SecByteBlock encryptedMessage1Alice, encryptedMessage2Bob;
    std::tie(encryptedMessage1Alice, encryptedMessage2Bob) = receiveCombinedMessage(bobSocket, 16, 16);

    
    cout << "Encrypted  1 received from Bob (IP address=172.16.15.7 && port no = 12345 ): ";
for (size_t i = 0; i < encryptedMessage1Alice.size(); ++i) {
    cout << static_cast<int>(encryptedMessage1Alice[i])<< " ";
}
cout << endl;

cout << "Encrypted Message 2 received from Bob (IP address=172.16.15.7 && port no = 12345 ): ";
for (size_t i = 0; i < encryptedMessage2Bob.size(); ++i) {
    cout << static_cast<int>(encryptedMessage2Bob[i])<< " ";
}
cout << endl;

    // Decrypt the message with alice-KDC secret key
   
    SecByteBlock decryptedMessage1 = kdcDecryptWithSessionKey(encryptedMessage1Alice, aliceKDCSessionKey);
    cout<< "decryptedMessage1 received from Bob: " << endl;
    for (size_t i = 0; i < decryptedMessage1.size(); ++i) {
    cout << static_cast<int>(decryptedMessage1[i])<< " ";
    }
    cout << endl;

    // Decrypt the message with bob-KDC secret key
     SecByteBlock decryptedMessage2 = kdcDecryptWithSessionKey(encryptedMessage2Bob, bobKDCSessionKey);
cout<< "decryptedMessage2 received from Bob: " << endl;
for (size_t i = 0; i < decryptedMessage2.size(); ++i) {
    cout << static_cast<int>(decryptedMessage2[i])<< " ";
}
cout << endl;
    // Generate Alice-Bob session key
    SecByteBlock aliceBobSessionKey = kdcGenerateSessionKey(); // You should use a proper key generation function here
std::cout << "Alice-Bob Session Key(generated by IP addr=172.29.1.66 && port no = 12345 ): ";

    for (size_t i = 0; i < aliceBobSessionKey.size(); ++i) {
        std::cout << static_cast<int>(aliceBobSessionKey[i])<< " ";
    }
    std::cout << std::endl;

// Assuming the structure of the normal message sent by Alice to Bob is as follows:
// [Alice Identity (5 bytes)] [Bob Identity (3 bytes)] [Common Nonce (8 bytes)]

const size_t aliceIdentitySize = 5;
const size_t bobIdentitySize = 3;
const size_t commonNonceSize = 4;
const size_t aliceNonceSize = 4;
const size_t bobNonceSize = 4;
// Extract Alice's Identity
SecByteBlock aliceNonce(aliceNonceSize);
memcpy(aliceNonce.BytePtr(), decryptedMessage1.BytePtr()+aliceIdentitySize+bobIdentitySize+commonNonceSize, aliceNonceSize);

std::cout << "Received Alice nonce(Received from IP addr=172.16.15.7 && port no = 12345 ): ";
for (size_t i = 0; i < aliceNonce.size(); ++i) {
    std::cout << static_cast<int>(aliceNonce[i])<< " ";
}
std::cout << std::endl;

// Extract Bob's Identity
SecByteBlock bobNonce(bobNonceSize);
memcpy(bobNonce.BytePtr(), decryptedMessage2.BytePtr()+aliceIdentitySize+bobIdentitySize+commonNonceSize, bobNonceSize);

std::cout << "Received Bob nonce(Received from IP addr=172.16.15.7 && port no = 12345 ): ";
for (size_t i = 0; i < bobNonce.size(); ++i) {
    std::cout << static_cast<int>(bobNonce[i])<< " ";
}
cout << endl;
// Extract Common Nonce
SecByteBlock commonNonce(commonNonceSize);
memcpy(commonNonce.BytePtr(), decryptedMessage1.BytePtr() + aliceIdentitySize + bobIdentitySize, commonNonceSize);

// Print the extracted common nonce
cout << "Received Common Nonce (Bytes)(Received from IP addr=172.16.15.7 && port no = 12345 ): ";
for (size_t i = 0; i < commonNonce.size(); ++i) {
    cout << static_cast<int>(commonNonce[i]) << " ";
}
cout << endl;

    // Create the first ticket: Bob Nonce + Alice-Bob Session Key
    SecByteBlock ticket1;
    ticket1 += bobNonce;
    ticket1 += aliceBobSessionKey;
    ticket1 += bobNonce;
    ticket1 += bobNonce;
    ticket1 += bobNonce;
    
    // Encrypt the first ticket with Bob-KDC secret key
    SecByteBlock encryptedTicket1ToBob = kdcEncryptWithSessionKey(ticket1, bobKDCSessionKey);
    cout<<"encryptedTicket1ToBob: "<<endl;
    for (size_t i = 0; i < encryptedTicket1ToBob.size(); ++i) {
    	cout << static_cast<int>(encryptedTicket1ToBob[i])<< " ";
	}
	cout << endl;
    
    // Create the second ticket: Alice Nonce + Alice-Bob Session Key
    SecByteBlock ticket2;
    ticket2 += aliceNonce;
    ticket2 += aliceBobSessionKey;
    ticket2 += aliceNonce;
    ticket2 += aliceNonce;
    ticket2 += aliceNonce;

    // Encrypt the second ticket with Alice-KDC secret key
    SecByteBlock encryptedTicket2ToBob = kdcEncryptWithSessionKey(ticket2, aliceKDCSessionKey);
    cout<<"encryptedTicket2ToBob: "<<endl;
    for (size_t i = 0; i < encryptedTicket2ToBob.size(); ++i) {
    	cout << static_cast<int>(encryptedTicket2ToBob[i])<< " ";
	}
	cout << endl;

    // Send the common nonce, and two tickets to Bob    
    //sendMessage(bobSocket, encryptedTicket1ToBob);
    //sendMessage(bobSocket, encryptedTicket2ToBob);
    //sendMessage(bobSocket, commonNonce);
    
    sendCombinedMessage(bobSocket,encryptedTicket1ToBob,encryptedTicket2ToBob,commonNonce);

    // Close sockets
    close(bobSocket);
    close(aliceSocket);
    close(kdcSocket);
    return 0;
}
