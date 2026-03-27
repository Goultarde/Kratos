#ifndef CONFIG_H
#define CONFIG_H

// Placeholder values that will be replaced by builder.py
#ifndef AGENT_UUID
#define AGENT_UUID "%AGENT_UUID%"
#endif
#ifndef CALLBACK_HOST
#define CALLBACK_HOST "%CALLBACK_HOST%"
#endif
#ifndef CALLBACK_PORT
#ifdef BUILD
#define CALLBACK_PORT % CALLBACK_PORT %
#else
#define CALLBACK_PORT 80
#endif
#endif
#ifndef POST_URI
#define POST_URI "%POST_URI%"
#endif
#ifndef USER_AGENT
#define USER_AGENT "%USER_AGENT%"
#endif
#ifndef SLEEP_TIME
#ifdef BUILD
#define SLEEP_TIME % SLEEP_TIME %
#else
#define SLEEP_TIME 5
#endif
#endif
#ifndef DEBUG
#ifdef BUILD
#define DEBUG % DEBUG_VAL %
#else
#define DEBUG 1
#endif
#endif

#ifndef KRATOS_AESPSK
#define KRATOS_AESPSK "%AESPSK%"
#endif
#ifndef KRATOS_HEADERS
#define KRATOS_HEADERS "%HEADERS%"
#endif
#ifndef KRATOS_ENCRYPTED_EXCHANGE
#ifdef BUILD
#define KRATOS_ENCRYPTED_EXCHANGE % ENCRYPTED_EXCHANGE %
#else
#define KRATOS_ENCRYPTED_EXCHANGE false
#endif
#endif

#ifndef CALLBACK_JITTER
#ifdef BUILD
#define CALLBACK_JITTER % CALLBACK_JITTER %
#else
#define CALLBACK_JITTER 0
#endif
#endif

#endif
