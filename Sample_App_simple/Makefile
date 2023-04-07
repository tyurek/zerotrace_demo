
.PHONY: all clean

all: Sample_App

Sample_App : Sample_App.cpp
	g++ -std=c++11 Sample_App.cpp utils.cpp -L=$(CURDIR) -lZT -lcrypto -Wl,--rpath=$(CURDIR) -o sampleapp