#include <cassert>
#include <cstdio>
#include <fstream>
#include <string>
#include "../include/nescaneg.h"

int main(void)
{
	/* build a tiny dictionary */
	{
		std::ofstream f("/tmp/nesca4_neg_test.txt");
		f << "access denied\n403 forbidden\nparking\n\n  \n";
	}
	negatives_setpath("/tmp/nesca4_neg_test.txt");

	assert(is_negative("<html>Access Denied</html>") == true);   /* case-insensitive */
	assert(is_negative("HTTP 403 Forbidden page") == true);
	assert(is_negative("welcome to the camera admin panel") == false);
	assert(is_negative("") == false);

	/* empty/missing dictionary -> never negative */
	negatives_setpath("/tmp/does_not_exist_neg.txt");
	assert(is_negative("access denied") == false);

	printf("test_neg: all passed\n");
	return 0;
}
