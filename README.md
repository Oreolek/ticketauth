# Ticket Authentication

See [here](https://www.mediawiki.org/wiki/Extension:Ticket_Authentication).

## CHANGES

By default TicketAuth creates new users and logs you in as a new user.
To allow anyone to login under any user, so you could create ticket URLs for an existing user, add this to your
LocalSettings:

```
$wgTktAuth_AllowLoginAll = TRUE;
```
