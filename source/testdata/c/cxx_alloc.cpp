#include <cstdint>
#include <cstring>

int main()
{
	for (int i = 0; i < 128; i++) {
		int *ints = new int[16];
		ints[0] = i;
		delete[] ints;

		char *buf = new char[0x123];
		std::memset(buf, 'C', 0x123);
		delete buf;
	}
	return 0;
}
