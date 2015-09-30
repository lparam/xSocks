#ifndef ACL_H
#define ACL_H

int init_acl(const char *path);
void free_acl(void);
int acl_contains_ip(const char * ip);

#endif // for #ifndef ACL_H
