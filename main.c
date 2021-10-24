#include "woody.h"

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        PrintError("main", "Invalid number of arguments");
        return (RET_KO);
    }

    return (PackerMain(argv[1]));
}
