/* Minimal shim for <sys/fileport.h>, absent from the theos iPhoneOS16.5 SDK.
 * Signatures taken from XNU bsd/sys/fileport.h; symbols exist in libSystem.tbd
 * (_fileport_makeport / _fileport_makefd) so linking works. */
#ifndef _SYS_FILEPORT_SHIM_H_
#define _SYS_FILEPORT_SHIM_H_

#include <mach/mach_types.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

int fileport_makeport(int fd, mach_port_t *portp);
int fileport_makefd(mach_port_t port);

__END_DECLS

#endif /* _SYS_FILEPORT_SHIM_H_ */
