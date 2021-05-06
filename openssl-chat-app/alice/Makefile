CXX = g++

RM = rm -f

CFLAGS = -g -Wall

LDLIBS = -L/usr/lib -lssl -lcrypto

task2: 
	$(CXX) $(CFLAGS) secure_chat_app.cpp -o secure_chat_app $(LDLIBS)

task3: 
	$(CXX) $(CFLAGS) secure_chat_interceptor.cpp -o secure_chat_interceptor $(LDLIBS)

task4: 
	$(CXX) $(CFLAGS) secure_chat_interceptor_en.cpp -o secure_chat_interceptor_en $(LDLIBS)

clean:
	rm -f *.o
	find . -type f -executable -delete

