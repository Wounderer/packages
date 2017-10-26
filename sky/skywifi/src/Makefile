LIBS += -lssl -lboost_thread -lboost_system -lcrypto -latomic
skywifi: main.o
	$(CXX) $(LDFLAGS) -std=c++11 -Iautobahn -Wno-deprecated-declarations -Wno-unused-local-typedefs -Isrc/msgpack-c/include -pedantic -ffunction-sections -fdata-sections -pthread  $(LIBS) main.o -o skywifi
main.o: main.cpp
	$(CXX) $(CXXLAGS) -std=c++11 -c main.cpp -Iautobahn -Wno-deprecated-declarations -Wno-unused-local-typedefs -Isrc/msgpack-c/include -pedantic -ffunction-sections -fdata-sections -pthread
clean:
	rm *.o skywifi
