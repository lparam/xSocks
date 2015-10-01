#ifndef ACL_H
#define ACL_H

int acl_init(const char *path);
void acl_free(void);
int acl_contains_ip(const char * ip);

#endif // for #ifndef ACL_H
