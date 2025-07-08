#include <iostream>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <utility>
using namespace CryptoPP;
using namespace std;

SecByteBlock bobGenerateNonce() {
    AutoSeededRandomPool rnd;
    SecByteBlock nonce(4);
    rnd.GenerateBlock(nonce, nonce.size());
    return nonce;
}

SecByteBlock bobEncryptWithSessionKey(const SecByteBlock& data, const SecByteBlock& key) {
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

    return encryptedData;
}

SecByteBlock bobDecryptWithSessionKey(const SecByteBlock& data, const SecByteBlock& key) {
    SecByteBlock decryptedData(data.size()); // Resize decryptedData to match data
    CBC_Mode<AES>::Decryption decryption(key, key.size(), (CryptoPP::byte*)"");
    decryption.ProcessData(decryptedData, data, data.size());
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

    return buffer;
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

void sendCombinedMessage(int socket, const SecByteBlock& encryptedTicket, const SecByteBlock& normalMessage) {
    // Combine the encrypted ticket and the normal message into one message
    size_t combinedMessageSize = encryptedTicket.size() + normalMessage.size();
    SecByteBlock combinedMessage(combinedMessageSize);
    memcpy(combinedMessage.data(), encryptedTicket.data(), encryptedTicket.size());
    memcpy(combinedMessage.data() + encryptedTicket.size(), normalMessage.data(), normalMessage.size());

    // Send the combined message to the socket
    sendMessage(socket, combinedMessage);
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
    int bobSocket, aliceSocket, kdcSocket;
    int bobPort = 12345; // Bob's port
    int kdcPort = 12345; // KDC's port
    string kdcIP = "172.29.1.66"; // Replace with KDC IP address
    sockaddr_in bobAddr, kdcAddr;

    bobSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (bobSocket == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    bobAddr.sin_family = AF_INET;
    bobAddr.sin_addr.s_addr = INADDR_ANY;
    bobAddr.sin_port = htons(bobPort);

    if (bind(bobSocket, (struct sockaddr*)&bobAddr, sizeof(bobAddr)) == -1) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(bobSocket, 2) == -1) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    kdcSocket = socket(AF_INET, SOCK_STREAM, 0);
    kdcAddr.sin_family = AF_INET;
    kdcAddr.sin_addr.s_addr = inet_addr(kdcIP.c_str());
    kdcAddr.sin_port = htons(kdcPort);

    if (connect(kdcSocket, (struct sockaddr*)&kdcAddr, sizeof(kdcAddr)) == -1) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    cout << "Connected to KDC.\n";

    SecByteBlock sessionKey = receiveMessage(kdcSocket, 16);

    cout << "Bob-KDC Session Key received from KDC: ";
    for (size_t i = 0; i < sessionKey.size(); ++i) {
        cout << static_cast<int>(sessionKey[i]) << " ";
    }
    cout << endl;

    cout << "Waiting for Alice to connect...\n";

    sockaddr_in aliceAddr;
    socklen_t lenAlice = sizeof(aliceAddr);
    aliceSocket = accept(bobSocket, (struct sockaddr*)&aliceAddr, &lenAlice);
    cout << "Alice connected.\n";

    size_t encryptedTicketSize =16; /* assign proper value */;
    size_t normalMessageSize =12; /* assign proper value */;

    SecByteBlock encryptedMessageAlice, normalMessageAlice;
    std::tie(encryptedMessageAlice, normalMessageAlice) = receiveCombinedMessage(aliceSocket, encryptedTicketSize, normalMessageSize);

    cout << "Encrypted Message  from Alice (IP address= 172.16.15.6 && port no = 12345  ): ";
    for (size_t i = 0; i < encryptedMessageAlice.size(); ++i) {
        cout << static_cast<int>(encryptedMessageAlice[i])<< " ";
    }
	cout<<endl;
    cout << "----";
	cout<<endl;
    sleep(2);



    cout << "Normal Message  from Alice(IP address= 172.16.15.6 && port no = 12345  ): ";
    for (size_t i = 0; i < normalMessageAlice.size(); ++i) {
        cout << static_cast<int>(normalMessageAlice[i])<< " ";
    }
    cout << endl;

    SecByteBlock aliceIdentity(5);
    SecByteBlock bobIdentity(3);
    SecByteBlock commonNonce(4);

    memcpy(aliceIdentity.BytePtr(), normalMessageAlice.BytePtr(), aliceIdentity.size());
    memcpy(bobIdentity.BytePtr(), normalMessageAlice.BytePtr() + aliceIdentity.size(), bobIdentity.size());
    memcpy(commonNonce.BytePtr(), normalMessageAlice.BytePtr() + aliceIdentity.size() + bobIdentity.size(), commonNonce.size());

    cout << "Common Nonce received from Alice(Bytes): ";
    for (size_t i = 0; i < commonNonce.size(); ++i) {
        cout << static_cast<int>(commonNonce[i]) << " ";
    }
    cout << endl;

    string aliceIdentityStr(aliceIdentity.begin(), aliceIdentity.end());
    string bobIdentityStr(bobIdentity.begin(), bobIdentity.end());
    string commonNonceStr(commonNonce.begin(), commonNonce.end());

//    cout << "Alice's Identity (String): " << aliceIdentityStr << endl;
  //  cout << "Bob's Identity (String): " << bobIdentityStr << endl;
  //  cout << "Common Nonce (String): " << commonNonceStr << endl;

    SecByteBlock bobNonce = bobGenerateNonce();
    SecByteBlock ticket2Bob;
    ticket2Bob += aliceIdentity;
    ticket2Bob += bobIdentity;
    ticket2Bob += commonNonce;
    ticket2Bob += bobNonce;


    SecByteBlock encryptedTicket2Bob = bobEncryptWithSessionKey(ticket2Bob, sessionKey);
	
    cout << "Encrypted ticket 2:";
    for (size_t i = 0; i< encryptedTicket2Bob.size(); ++i) {
        cout << static_cast<int>(encryptedTicket2Bob[i]) << " ";
    }
    cout << endl;

    sendCombinedMessage(kdcSocket,encryptedMessageAlice,encryptedTicket2Bob);
    //sendMessage(kdcSocket, encryptedMessageAlice);
    //sendMessage(kdcSocket, encryptedTicket2Bob);

//    SecByteBlock kdcticket1 = receiveMessage(kdcSocket, 32);
//    SecByteBlock kdcticket2 = receiveMessage(kdcSocket, 32);
//    SecByteBlock commonNonceReceived = receiveMessage(kdcSocket, 4);

auto receivedMessages_1 = receiveCombinedMessage(kdcSocket, 32, 32, 4);
    SecByteBlock kdcticket1 = std::get<0>(receivedMessages_1);
    SecByteBlock kdcticket2 = std::get<1>(receivedMessages_1);
    SecByteBlock commonNonceReceived = std::get<2>(receivedMessages_1);

 cout<<"encryptedTicket1ToBob (Received from IP addr=172.29.1.66 && port no = 12345 ): "<<endl;
    for (size_t i = 0; i < kdcticket1.size(); ++i) {
    	cout << static_cast<int>(kdcticket1[i])<< " ";
	}
	cout << endl;
	
 cout<<"encryptedTicket2ToBob: "<<endl;
    for (size_t i = 0; i < kdcticket2.size(); ++i) {
    	cout << static_cast<int>(kdcticket2[i])<< " ";
	}
	cout << endl;
	

cout << "Received Common Nonce (Bytes): ";
for (size_t i = 0; i < commonNonceReceived.size(); ++i) {
    cout << static_cast<int>(commonNonceReceived[i]) << " ";
}
cout << endl;

    SecByteBlock decryptedTicket1 = bobDecryptWithSessionKey(kdcticket1, sessionKey);

    SecByteBlock bobNonceReceived(decryptedTicket1.BytePtr(), 4);
    cout << "Bob Nonce Received: ";
    for (size_t i = 0; i < bobNonceReceived.size(); ++i) {
        cout << static_cast<int>(bobNonceReceived[i]) << " ";
    }
    cout << endl;

    SecByteBlock aliceBobSessionKey(decryptedTicket1.BytePtr() + 4, 16);
    cout << "Alice-Bob Session Key: ";
    for (size_t i = 0; i < aliceBobSessionKey.size(); ++i) {
        cout << static_cast<int>(aliceBobSessionKey[i]) << " ";
    }
    cout << endl;

    sendMessage(aliceSocket, kdcticket2);
    SecByteBlock aliceticket = receiveMessage(aliceSocket, 4);

 cout<<"received message from alice successfully" << endl;

 for (size_t i = 0; i < aliceticket.size(); ++i) {
    cout << static_cast<int>(aliceticket[i]) << " ";
}
cout << endl;

    close(aliceSocket);
    close(bobSocket);
    close(kdcSocket);

    return 0;
}


