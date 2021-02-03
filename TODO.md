- Require authentication
- Whether user is logged on or not depends on Whether a session id exists,
but that is not correct, since a unlogged-on session id may exist, causing a
loop
