#include <glib.h>
int	main(int argc, char *argv[])
{
	GString *s;
	s = g_string_new("Hello");
	g_print("%s\n", s->str);
	s = g_string_append(s," World!");
	g_print("%s\n",s->str);
	s = g_string_erase(s,0,6);
	g_print("%s\n",s->str);
	s = g_string_prepend(s,"Also a ");
	g_print("%s\n",s->str);

	s = g_string_insert(s,6," Nice");
	g_print("%s\n",s->str);
}
