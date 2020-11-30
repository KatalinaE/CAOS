#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

enum { NAMESIZE = 1024, BUFSIZE = 1024 * 8 };

int main() {
  char name[NAMESIZE], buf[BUFSIZE];
  int fd;
  struct stat st;

  while (scanf(" %[^\n]", name) == 1) {
    if (!(lstat(name, &st) == 0 && st.st_mode & S_IXUSR) ||
        (fd = open(name, O_RDONLY)) == -1 || read(fd, buf, BUFSIZE) < 4 ||
        !strncmp(buf, "\x7f\ELF", 4) ||
        (sscanf(buf, "#! %s", buf) == 1 && access(buf, F_OK | X_OK) == -1))
      printf("%s\n", name);
  }
  return 0;
}
