#include "ankah/files.h"
int main(int argc, char **argv) {
    return argc == 2 && ankah_file_private_check(argv[1]) == 0 ? 0 : 1;
}
