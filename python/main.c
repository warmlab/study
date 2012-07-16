#include <Python.h>

int main() {
	int ret;
	PyThreadState* state;

	Py_Initialize();
	state = Py_NewInterpreter();

	//ret = PyRun_SimpleString("a='a'");
	//ret = PyRun_SimpleString("print a");
	FILE *fp = fopen("global_var.py", "r");
	ret = PyRun_AnyFile(fp, "global_var.py");
	fclose(fp);
	PyThreadState_Clear(state);
	PyEval_ReleaseThread(state);
	PyThreadState_Swap(NULL);
	PyThreadState_Delete(state);
	fp = fopen("main.py", "r");
	ret = PyRun_AnyFile(fp, "global_var.py");
	fclose(fp);

	Py_EndInterpreter(state);
	Py_Finalize();

	return 0;
}
