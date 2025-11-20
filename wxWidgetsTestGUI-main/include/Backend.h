#pragma once

// dummy class to test how using functions from different,
// outside of wxWidgets api classes, in the event handlers, works
class MyBackendClass {
public:
	static int TestFunction(int a, int b);
};