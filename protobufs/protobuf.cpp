#include "messages/message.pb.h"
#include "messages/message.pb.cc"
#include <iostream>

using namespace std;

int main() {
    // Serialize
    CarrotMessage message;
    message.set_ip_address("171.64.15.7");
    message.set_port(12345);
    message.set_message("Hey there!");

    string serialized_data;
    message.SerializeToString(&serialized_data);

    // Deserialize
    CarrotMessage deserialized_message;
    deserialized_message.ParseFromString(serialized_data);

    cout << "IP Address: " << deserialized_message.ip_address() << endl;
    cout << "Port Number: " << deserialized_message.port() << endl;
    cout << "Message: " << deserialized_message.message() << endl;
    return 0;
}