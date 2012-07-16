#include <iostream>
#include <vector>

using namespace std;

int main() {
	vector<int> v;

	for (int i = 0; i < 100; i++)
		v.push_back(i);

	for (vector<int>::iterator it = v.begin();
			it != v.end(); it++) {
		//cout << "it: " << *it << endl;
		int a = *it;
		v.erase(it);
		//it--;
		cout << "it: " << a << endl;
	}
}
