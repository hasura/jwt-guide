Refresh Token Flow (rfc6749, Section 1.5)
From https://datatracker.ietf.org/doc/html/rfc6749#section-1.5
 
  +--------+                                           +---------------+
  |        |--(A)------- Authorization Grant --------->|               |
  |        |                                           |               |
  |        |<-(B)----------- Access Token -------------|               |
  |        |               & Refresh Token             |               |
  |        |                                           |               |
  |        |                            +----------+   |               |
  |        |--(C)---- Access Token ---->|          |   |               |
  |        |                            |          |   |               |
  |        |<-(D)- Protected Resource --| Resource |   | Authorization |
  | Client |                            |  Server  |   |     Server    |
  |        |--(E)---- Access Token ---->|          |   |               |
  |        |                            |          |   |               |
  |        |<-(F)- Invalid Token Error -|          |   |               |
  |        |                            +----------+   |               |
  |        |                                           |               |
  |        |--(G)----------- Refresh Token ----------->|               |
  |        |                                           |               |
  |        |<-(H)----------- Access Token -------------|               |
  +--------+           & Optional Refresh Token        +---------------+

               Figure 2: Refreshing an Expired Access Token



Goals:

- Mitigate use of a data store (state-less).
- Ability to force log out all users.
- Ability to force log out any individual at any time.
- Ability to require password re-entry after a certain amount of time.
- Ability to work with multiple clients.
- Ability to force a re-log in when a user clicks logout from a particular client. (To prevent someone "un-deleting" a client token after user walks away - see comments for additional information)

The Solution:

- Use short lived (<5m) access tokens paired with a longer lived (few hours) client stored refresh-token.
Every request checks either the auth or refresh token expiration date for validity.
- When the access token expires, the client uses the refresh token to refresh the access token.
- During the refresh token check, the server checks a small blacklist of user ids - if found reject the refresh request.
- When a client doesn't have a valid(not expired) refresh or auth token the user must log back in, as all other requests will be rejected.
- On login request, check user data store for ban.
- On logout - add that user to the session blacklist so they have to log back in. You would have to store additional information to not log them out of all devices in a multi device environment but it could be done by adding a device field to the user blacklist.
- To force re-entry after x amount of time - maintain last login date in the auth token, and check it per request.
- To force log out all users - reset token hash key.

This requires you to maintain a blacklist(state) on the server, assuming the user table contains banned user information. The invalid sessions blacklist - is a list of user ids. This blacklist is only checked during a refresh token request. Entries are required to live on it as long as the refresh token TTL. Once the refresh token expires the user would be required to log back in.

Cons:

- Still required to do a data store lookup on the refresh token request.
- Invalid tokens may continue to operate for access token's TTL.

Pros:

- Provides desired functionality.
- Refresh token action is hidden from the user under normal operation.
- Only required to do a data store lookup on refresh requests instead of every request. ie 1 every 15 min instead of 1 per second.
- Minimizes server side state to a very small blacklist.