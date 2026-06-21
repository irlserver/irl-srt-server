#include <string>
#include <sys/types.h>

size_t strlcpy(char *dst, const char *src, size_t dsize);

std::string url_encode(const std::string &value);
