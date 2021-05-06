Install the OpenSSL library, for the ubuntu use the below command.
sudo apt-get install libssl-dev

Commands to run in Task3 at mitm side (trudy1):
1) To build the files:
make task3
2) To execute secure_chat_interceptor
./secure_chat_interceptor -d alice1 bob1

Commands to run in Task4 at mitm side (trudy1):
1) To build the files:
make task4
2) To execute secure_chat_interceptor_en
./secure_chat_interceptor_en -m alice1 bob1
