#include <iostream>
#include <boost/logic/tribool.hpp>

int main() {
	using namespace boost::logic;
	using namespace std;

	tribool x;
	tribool y(true);
	tribool z(indeterminate);

	if (x)
		cout << "false\n";

	if (y)
		cout << "true\n";

	if (z)
		cout << "indeterminate\n";

	if (!!(!z || z))
		cout << "not indeterminate\n";

}
