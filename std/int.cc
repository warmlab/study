#include <cstdio>
#include <string>
#include <sstream>
#include <cstdlib>

using namespace std;

int main() {
	string str = "z123z";
	int numb;
	std::stringstream ( str ) >> numb;

	numb = atoi(str.c_str());
	printf("%d\n", numb);
}
