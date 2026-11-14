#ifndef IUL_IOS_UNTAR_H
#define IUL_IOS_UNTAR_H

// Extracts a gzipped POSIX ustar archive at `tgz_path` into `dest_dir`
// (which must already exist). Returns 0 on success, -1 on error.
int untar_gz(const char *tgz_path, const char *dest_dir);

#endif
